#!/usr/bin/env python3
"""
build_dataset.py
================
Label cppcheck findings (results.xml) against the NIST Juliet C/C++ 1.3
ground truth (manifest.xml + the bad/good structure of every test case) and
emit a `code_trace` table:

    label | trace | bug_function | functions | bug_url   (+ metadata columns)

Labeling rule (the "simple comparison" requested):
    label = 1  (true positive)  iff
        (a) the finding's primary location lies in *bad* code of a Juliet test
            case (bad()/badSink()/badSource()/<...>_bad class, or code inside
            `#ifndef OMITBAD`), AND
        (b) the CWE reported by cppcheck equals one of the CWEs NIST assigns to
            that test case (manifest.xml <flaw name="CWE-xxx ..."/>).
    label = 0  (false positive)  otherwise — including findings in good()
    code, findings with a different CWE, and findings with no CWE at all.

Everything needed to re-derive labels under a different policy is kept as
extra columns (region, cwe_match, on_flaw_line, flaw_line_dist, ...).

Only the Python standard library is required.

Usage (defaults are auto-detected from the current directory):
    python3 build_dataset.py
    python3 build_dataset.py --results results.xml --juliet <dir containing C/> \
        --out dataset.sqlite --csv dataset.csv --jsonl dataset.jsonl
    python3 build_dataset.py --validate      # self-check against the manifest
    python3 build_dataset.py --limit 2000    # smoke test
"""
from __future__ import annotations

import argparse
import bisect
import csv
import glob
import json
import os
import re
import sqlite3
import sys
import time
import xml.etree.ElementTree as ET
from collections import Counter, OrderedDict, defaultdict
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple

# --------------------------------------------------------------------------- #
# Constants / regexes
# --------------------------------------------------------------------------- #

SRC_EXT = ('.c', '.cpp', '.h')

# Tokens that must be masked before brace matching: preprocessor lines (with
# line continuations), block comments, line comments, string & char literals.
# Order matters: leftmost match wins, and alternatives are tried in order at
# the same position.
_MASK_RE = re.compile(
    r'(?P<pp>^[ \t]*#(?:\\\r?\n|[^\n])*)'          # preprocessor directive
    r'|(?P<bc>/\*.*?\*/)'                          # block comment
    r'|(?P<lc>//[^\n]*)'                           # line comment
    r'|(?P<str>L?"(?:\\.|[^"\\\n])*")'             # string literal
    r'|(?P<chr>L?\'(?:\\.|[^\'\\\n])*\')',         # char literal
    re.S | re.M,
)
_COMMENT_ONLY_RE = re.compile(
    r'(?P<bc>/\*.*?\*/)|(?P<lc>//[^\n]*)'
    r'|(?P<str>L?"(?:\\.|[^"\\\n])*")|(?P<chr>L?\'(?:\\.|[^\'\\\n])*\')',
    re.S,
)
_BRACE_RE = re.compile(r'[{};]')
_TRAILING_QUAL_RE = re.compile(
    r'\s*(?:const|volatile|override|final|noexcept|throw\s*\([^)]*\)|=\s*0|=\s*default|=\s*delete)\s*$'
)
_ACCESS_RE = re.compile(r'^\s*(?:(?:public|private|protected)\s*:\s*)+')
_NAMESPACE_RE = re.compile(r'^\s*(?:inline\s+)?namespace(?:\s+([A-Za-z_]\w*))?\s*$')
_CLASS_RE = re.compile(
    r'(?:^|\s)(?:typedef\s+)?(class|struct|union|enum)(?:\s+class)?\s*([A-Za-z_]\w*)?'
    r'(?:\s*(?:final))?(?:\s*:\s*[^{]*)?\s*$'
)
_FUNC_NAME_RE = re.compile(r'(operator\s*(?:\(\)|\[\]|[^\s(\w]+)|~?[A-Za-z_][\w:~]*)\s*\(')
_CWE_DIR_RE = re.compile(r'^CWE(\d+)_')
_TESTCASE_NAME_RE = re.compile(r'^(.*?_\d{2})(?:[a-z]|_bad|_good\w*)?\.(?:c|cpp|h)$')
_INCIDENTAL_RE = re.compile(r'INCIDENTAL[^\n]*?CWE[ \-]?(\d+)', re.I)
_PP_DIRECTIVE_RE = re.compile(r'^\s*#\s*(ifndef|ifdef|if|elif|else|endif)\b\s*(\S*)')
_CONTROL_KEYWORDS = {'if', 'while', 'for', 'switch', 'return', 'sizeof', 'catch', 'do', 'else', 'try'}

# --------------------------------------------------------------------------- #
# Ground truth: manifest.xml
# --------------------------------------------------------------------------- #


@dataclass
class FileTruth:
    basename: str
    testcase_id: int
    testcase_name: str
    testcase_cwes: Set[int]          # union of manifest flaw CWEs over the whole test case
    flaw_lines: Dict[int, int]       # line -> CWE  (this file only)
    dir_cwe: Optional[int]           # CWE number from the file-name prefix


def load_manifest(path: str) -> Dict[str, FileTruth]:
    """basename -> FileTruth for every file listed in manifest.xml."""
    truth: Dict[str, FileTruth] = {}
    tc_id = 0
    for _ev, el in ET.iterparse(path, events=('end',)):
        if el.tag != 'testcase':
            continue
        tc_id += 1
        files = el.findall('file')
        cwes: Set[int] = set()
        per_file: List[Tuple[str, Dict[int, int]]] = []
        for f in files:
            fl: Dict[int, int] = {}
            for w in list(f.findall('flaw')) + list(f.findall('mixed')):
                m = re.match(r'CWE-?(\d+)', w.get('name', ''))
                if m:
                    c = int(m.group(1))
                    cwes.add(c)
                    try:
                        fl[int(w.get('line'))] = c
                    except (TypeError, ValueError):
                        pass
            per_file.append((f.get('path'), fl))
        first = per_file[0][0] if per_file else ''
        m = _TESTCASE_NAME_RE.match(first)
        tc_name = m.group(1) if m else os.path.splitext(first)[0]
        for bn, fl in per_file:
            dm = _CWE_DIR_RE.match(bn)
            dir_cwe = int(dm.group(1)) if dm else None
            if not cwes and dir_cwe is not None:
                cwes = {dir_cwe}
            truth[bn] = FileTruth(bn, tc_id, tc_name, set(cwes), fl, dir_cwe)
        el.clear()
    return truth


# --------------------------------------------------------------------------- #
# Source parsing: comments/strings masking, preprocessor guard regions,
# function / class boundaries
# --------------------------------------------------------------------------- #


def _blank_keep_newlines(s: str) -> str:
    return re.sub(r'[^\n]', ' ', s)


def mask_source(text: str) -> str:
    """Same length as `text`; comments, literals and preprocessor lines -> spaces."""
    return _MASK_RE.sub(lambda m: _blank_keep_newlines(m.group(0)), text)


def strip_comments(code: str) -> str:
    """Remove C/C++ comments (but not string contents); collapse blank lines."""
    def repl(m):
        return '' if (m.group('bc') or m.group('lc')) else m.group(0)
    out = _COMMENT_ONLY_RE.sub(repl, code)
    lines = [ln.rstrip() for ln in out.split('\n')]
    res, blank = [], 0
    for ln in lines:
        if ln.strip() == '':
            blank += 1
            if blank > 1:
                continue
        else:
            blank = 0
        res.append(ln)
    return '\n'.join(res).strip('\n')


def guard_regions(lines: List[str]) -> List[Optional[str]]:
    """
    For each line (1-based index -> list index i-1) the innermost Juliet
    preprocessor region: 'bad' (#ifndef OMITBAD), 'good' (#ifndef OMITGOOD),
    'main' (#ifdef INCLUDEMAIN) or None.
    """
    regions: List[Optional[str]] = [None] * len(lines)
    stack: List[Optional[str]] = []      # region contributed by each open #if
    pending_continuation = False
    for i, raw in enumerate(lines):
        line = raw
        if pending_continuation:
            pending_continuation = line.rstrip().endswith('\\')
            regions[i] = next((r for r in reversed(stack) if r), None)
            continue
        m = _PP_DIRECTIVE_RE.match(line)
        if m:
            kind, arg = m.group(1), m.group(2)
            if kind in ('if', 'ifdef', 'ifndef'):
                reg = None
                if kind == 'ifndef' and arg == 'OMITBAD':
                    reg = 'bad'
                elif kind == 'ifndef' and arg == 'OMITGOOD':
                    reg = 'good'
                elif kind == 'ifdef' and arg == 'INCLUDEMAIN':
                    reg = 'main'
                elif kind == 'if' and arg.startswith('!defined(OMITBAD)'):
                    reg = 'bad'
                elif kind == 'if' and arg.startswith('!defined(OMITGOOD)'):
                    reg = 'good'
                stack.append(reg)
            elif kind in ('else', 'elif'):
                if stack:
                    stack[-1] = None       # the #else branch of #ifndef OMITBAD is *not* bad code
            elif kind == 'endif':
                if stack:
                    stack.pop()
            pending_continuation = line.rstrip().endswith('\\')
        regions[i] = next((r for r in reversed(stack) if r), None)
    return regions


@dataclass
class CodeUnit:
    name: str                # qualified: ns::Class::method
    kind: str                # 'function' | 'class'
    start_line: int          # 1-based, inclusive (signature line)
    end_line: int            # 1-based, inclusive (closing brace)
    region: str = 'other'    # bad | good | main | other
    region_source: str = ''  # name | guard | none


@dataclass
class SourceFile:
    relpath: str
    lines: List[str]
    units: List[CodeUnit]
    guards: List[Optional[str]]
    parse_error: Optional[str] = None
    _starts: List[int] = field(default_factory=list)

    def unit_at(self, line: int) -> Optional[CodeUnit]:
        """Innermost (smallest) unit containing `line`."""
        best = None
        for u in self.units:
            if u.start_line <= line <= u.end_line:
                if best is None or (u.end_line - u.start_line) < (best.end_line - best.start_line):
                    best = u
        return best

    def code(self, unit: CodeUnit) -> str:
        return '\n'.join(self.lines[unit.start_line - 1:unit.end_line])

    def line_region(self, line: int) -> str:
        if 1 <= line <= len(self.guards):
            return self.guards[line - 1] or 'other'
        return 'other'

    def region_for_line(self, line: int) -> Tuple[str, str, Optional[CodeUnit]]:
        u = self.unit_at(line)
        if u is not None:
            return u.region, u.region_source, u
        g = self.line_region(line)
        return (g, 'guard', None) if g != 'other' else ('other', 'none', None)


def _name_region(qualified: str) -> Optional[str]:
    """
    Juliet naming: bad/badSink/badSource/<tc>_bad, good/goodG2B/goodB2G/good1/
    goodG2BSink/...; class variants <tc>_bad / <tc>_goodG2B.  Test case names
    themselves never contain 'good'/'bad', so a substring test on the
    non-namespace part of the qualified name is safe.
    """
    parts = qualified.split('::')
    tail = '::'.join(parts[-2:]).lower()      # Class::method (or just name)
    if 'bad' in tail:
        return 'bad'
    if 'good' in tail:
        return 'good'
    return None


def parse_source(relpath: str, text: str) -> SourceFile:
    lines = text.split('\n')
    guards = guard_regions(lines)
    masked = mask_source(text)
    nl_pos = [i for i, ch in enumerate(masked) if ch == '\n']

    def line_of(idx: int) -> int:
        return bisect.bisect_left(nl_pos, idx) + 1

    units: List[CodeUnit] = []
    # scope stack entries: dict(kind=..., name=..., start=..., hdr_start=...)
    stack: List[dict] = []
    seg_start = 0
    err = None

    def ns_prefix() -> str:
        names = [s['name'] for s in stack if s['kind'] in ('namespace', 'class') and s['name']]
        return '::'.join(names)

    for m in _BRACE_RE.finditer(masked):
        ch = m.group(0)
        i = m.start()
        if ch == ';':
            if not stack or stack[-1]['kind'] in ('namespace', 'class', 'extern'):
                seg_start = i + 1
            continue
        if ch == '{':
            inside_code = bool(stack) and stack[-1]['kind'] in ('function', 'block', 'enum', 'init')
            header = masked[seg_start:i]
            hdr_stripped = header.strip()
            entry = {'kind': 'block', 'name': None, 'start': i, 'hdr_start': None}
            if inside_code:
                entry['kind'] = 'block'
            else:
                h = _ACCESS_RE.sub('', hdr_stripped).strip()
                # signature start index (first non-space char of header, in masked text)
                off = len(header) - len(header.lstrip())
                hdr_start = seg_start + off
                nm = _NAMESPACE_RE.match(h)
                if nm:
                    entry.update(kind='namespace', name=nm.group(1))
                elif h == 'extern':                      # extern "C" {   (string masked)
                    entry.update(kind='extern')
                elif '=' in h.split('(')[0] and not h.endswith(')'):
                    entry.update(kind='init')            # aggregate initializer at file/class scope
                else:
                    hq = _TRAILING_QUAL_RE.sub('', h)
                    while hq != _TRAILING_QUAL_RE.sub('', hq):
                        hq = _TRAILING_QUAL_RE.sub('', hq)
                    cm = _CLASS_RE.search(h) if '(' not in h else None
                    if cm and cm.group(1) == 'enum':
                        entry.update(kind='enum', name=cm.group(2))
                    elif cm:
                        entry.update(kind='class', name=cm.group(2), hdr_start=hdr_start)
                    elif hq.endswith(')'):
                        fm = _FUNC_NAME_RE.search(hq)
                        fname = fm.group(1) if fm else None
                        if fname and fname.split('::')[-1] not in _CONTROL_KEYWORDS:
                            entry.update(kind='function', name=fname, hdr_start=hdr_start)
                        else:
                            entry.update(kind='block')
                    else:
                        entry.update(kind='block')
                if entry['kind'] == 'function':
                    pre = ns_prefix()
                    entry['qualified'] = (pre + '::' + entry['name']) if pre and not entry['name'].startswith(pre) else entry['name']
                elif entry['kind'] == 'class':
                    pre = ns_prefix()
                    nm_ = entry['name'] or '<anonymous>'
                    entry['qualified'] = (pre + '::' + nm_) if pre else nm_
            stack.append(entry)
            seg_start = i + 1
            continue
        # ch == '}'
        if not stack:
            err = f'unbalanced }} at line {line_of(i)}'
            break
        entry = stack.pop()
        seg_start = i + 1
        if entry['kind'] in ('function', 'class'):
            start_line = line_of(entry['hdr_start'])
            end_line = line_of(i)
            units.append(CodeUnit(entry['qualified'], entry['kind'], start_line, end_line))
    if stack and err is None:
        err = f'unclosed {{ opened at line {line_of(stack[-1]["start"])}'

    for u in units:
        r = _name_region(u.name)
        if r:
            u.region, u.region_source = r, 'name'
        else:
            g = guards[u.start_line - 1] if 0 <= u.start_line - 1 < len(guards) else None
            if g:
                u.region, u.region_source = g, 'guard'
            else:
                u.region, u.region_source = 'other', 'none'
    units.sort(key=lambda u: (u.start_line, -u.end_line))
    return SourceFile(relpath, lines, units, guards, err)


# --------------------------------------------------------------------------- #
# Suite index + cache
# --------------------------------------------------------------------------- #


class Suite:
    def __init__(self, c_dir: str, cache_size: int = 4000):
        self.c_dir = c_dir
        self.by_basename: Dict[str, str] = {}
        tc_root = os.path.join(c_dir, 'testcases')
        for root, _dirs, files in os.walk(tc_root):
            for fn in files:
                if fn.endswith(SRC_EXT):
                    rel = os.path.relpath(os.path.join(root, fn), c_dir)
                    # duplicates (main.cpp, testcases.h per CWE dir) are not test cases; keep first
                    self.by_basename.setdefault(fn, rel)
        self._cache: 'OrderedDict[str, SourceFile]' = OrderedDict()
        self.cache_size = cache_size
        self.missing: Counter = Counter()

    def resolve(self, loc_file: str) -> Optional[str]:
        """cppcheck location path -> path relative to the C dir (or None)."""
        p = loc_file.replace('\\', '/')
        if os.path.isfile(os.path.join(self.c_dir, p)):
            return os.path.normpath(p)
        if os.path.isabs(p) and os.path.isfile(p):
            try:
                return os.path.relpath(p, self.c_dir)
            except ValueError:
                return p
        # try suffix match ("…/C/testcases/x.c" with a different prefix)
        idx = p.find('testcases/')
        if idx >= 0 and os.path.isfile(os.path.join(self.c_dir, p[idx:])):
            return p[idx:]
        bn = os.path.basename(p)
        return self.by_basename.get(bn)

    def get(self, relpath: str) -> Optional[SourceFile]:
        sf = self._cache.get(relpath)
        if sf is not None:
            self._cache.move_to_end(relpath)
            return sf
        full = os.path.join(self.c_dir, relpath)
        try:
            with open(full, 'r', encoding='utf-8', errors='replace', newline='') as fh:
                text = fh.read()
        except OSError:
            self.missing[relpath] += 1
            return None
        text = text.replace('\r\n', '\n').replace('\r', '\n')
        sf = parse_source(relpath, text)
        self._cache[relpath] = sf
        if len(self._cache) > self.cache_size:
            self._cache.popitem(last=False)
        return sf


# --------------------------------------------------------------------------- #
# Dataset row construction
# --------------------------------------------------------------------------- #

COLUMNS = [
    # requested table
    'label', 'trace', 'bug_function', 'functions', 'bug_url',
    # finding metadata
    'checker_id', 'severity', 'inconclusive', 'report_cwe', 'msg', 'verbose',
    'file', 'line', 'column', 'tu_file', 'n_locations',
    # code unit metadata
    'bug_function_name', 'bug_function_kind', 'bug_function_start', 'bug_function_end',
    # ground-truth metadata
    'region', 'region_source', 'testcase_id', 'testcase_name', 'testcase_cwes',
    'cwe_match', 'on_flaw_line', 'flaw_line_dist', 'flaw_lines', 'incidental_cwes',
    'trace_json',
]


def make_url(url_base: str, relpath: str, line: int) -> str:
    rel = relpath.replace(os.sep, '/')
    return f'{url_base}{rel}#L{line}'


def build_row(el, suite: Suite, truth: Dict[str, FileTruth], url_base: str,
              cwe_map: Dict[int, Set[int]], do_strip: bool,
              include_non_testcase: bool) -> Optional[dict]:
    locs = el.findall('location')
    if not locs:
        return None
    checker = el.get('id', '')
    severity = el.get('severity', '')
    msg = el.get('msg', '')
    verbose = el.get('verbose', '')
    inconclusive = 1 if el.get('inconclusive') == 'true' else 0
    tu_file = el.get('file0', '')
    rc = el.get('cwe')
    report_cwe = int(rc) if rc and rc.isdigit() else None

    # resolve every location
    resolved: List[Tuple[str, int, int, str, Optional[str]]] = []  # (file, line, col, info, relpath)
    for l in locs:
        f = l.get('file', '')
        try:
            ln = int(l.get('line', '0'))
        except ValueError:
            ln = 0
        try:
            col = int(l.get('column', '0'))
        except ValueError:
            col = 0
        resolved.append((f, ln, col, l.get('info', '') or '', suite.resolve(f)))

    pfile, pline, pcol, _pinfo, prel = resolved[0]
    if prel is None:
        return None
    pbase = os.path.basename(prel)
    ft = truth.get(pbase)
    if ft is None and not include_non_testcase:
        return None

    # ---- code units along the trace
    trace_entries = []
    functions = []
    seen_units = set()
    bug_unit: Optional[CodeUnit] = None
    bug_sf: Optional[SourceFile] = None
    for idx, (f, ln, col, info, rel) in enumerate(resolved):
        sf = suite.get(rel) if rel else None
        unit = sf.unit_at(ln) if sf else None
        ent = {
            'file': rel or f, 'line': ln, 'column': col, 'info': info,
            'function': unit.name if unit else None,
            'region': (sf.region_for_line(ln)[0] if sf else None),
        }
        trace_entries.append(ent)
        if idx == 0:
            bug_unit, bug_sf = unit, sf
        if unit is not None and sf is not None:
            key = (rel, unit.start_line, unit.end_line)
            if key not in seen_units:
                seen_units.add(key)
                code = sf.code(unit)
                functions.append({
                    'name': unit.name, 'kind': unit.kind, 'file': rel,
                    'start_line': unit.start_line, 'end_line': unit.end_line,
                    'region': unit.region,
                    'code': strip_comments(code) if do_strip else code,
                })

    # ---- region / ground truth for the primary location
    if bug_sf is not None:
        region, region_source, _u = bug_sf.region_for_line(pline)
    else:
        region, region_source = 'other', 'none'

    if ft is not None:
        tc_cwes = ft.testcase_cwes
        accepted = {report_cwe} | cwe_map.get(report_cwe, set()) if report_cwe is not None else set()
        cwe_match = 1 if (accepted & tc_cwes) else 0
        flaw_lines = sorted(ft.flaw_lines)
        on_flaw_line = 1 if pline in ft.flaw_lines else 0
        flaw_dist = min((abs(pline - fl) for fl in flaw_lines), default=None)
        testcase_id, testcase_name = ft.testcase_id, ft.testcase_name
    else:
        tc_cwes, cwe_match, flaw_lines, on_flaw_line, flaw_dist = set(), 0, [], 0, None
        testcase_id, testcase_name = None, None

    label = 1 if (region == 'bad' and cwe_match) else 0

    # incidental CWE comments inside the bug function (NIST marks secondary flaws)
    incidental: List[int] = []
    if bug_unit is not None and bug_sf is not None:
        incidental = sorted({int(x) for x in _INCIDENTAL_RE.findall(bug_sf.code(bug_unit))})

    # ---- human-readable trace
    cwe_txt = f'CWE-{report_cwe}' if report_cwe is not None else 'CWE-?'
    head = f'{checker} [{severity}] {cwe_txt}: {msg}'
    tlines = [head]
    for k, e in enumerate(trace_entries):
        fn = f' (in {e["function"]})' if e['function'] else ''
        info = f' {e["info"]}' if e['info'] else ''
        tlines.append(f'  #{k} {e["file"]}:{e["line"]}:{e["column"]}{info}{fn}')
    trace = '\n'.join(tlines)

    bug_code = ''
    if bug_unit is not None and bug_sf is not None:
        bug_code = bug_sf.code(bug_unit)
        if do_strip:
            bug_code = strip_comments(bug_code)

    return {
        'label': label,
        'trace': trace,
        'bug_function': bug_code,
        'functions': json.dumps(functions, ensure_ascii=False),
        'bug_url': make_url(url_base, prel, pline),
        'checker_id': checker,
        'severity': severity,
        'inconclusive': inconclusive,
        'report_cwe': report_cwe,
        'msg': msg,
        'verbose': verbose,
        'file': prel,
        'line': pline,
        'column': pcol,
        'tu_file': tu_file,
        'n_locations': len(resolved),
        'bug_function_name': bug_unit.name if bug_unit else None,
        'bug_function_kind': bug_unit.kind if bug_unit else None,
        'bug_function_start': bug_unit.start_line if bug_unit else None,
        'bug_function_end': bug_unit.end_line if bug_unit else None,
        'region': region,
        'region_source': region_source,
        'testcase_id': testcase_id,
        'testcase_name': testcase_name,
        'testcase_cwes': ';'.join(str(c) for c in sorted(tc_cwes)),
        'cwe_match': cwe_match,
        'on_flaw_line': on_flaw_line,
        'flaw_line_dist': flaw_dist,
        'flaw_lines': ';'.join(str(x) for x in flaw_lines),
        'incidental_cwes': ';'.join(str(x) for x in incidental),
        'trace_json': json.dumps(trace_entries, ensure_ascii=False),
    }


# --------------------------------------------------------------------------- #
# Writers
# --------------------------------------------------------------------------- #


class SqliteWriter:
    def __init__(self, path: str, table: str = 'code_trace'):
        if os.path.exists(path):
            os.remove(path)
        self.conn = sqlite3.connect(path)
        self.conn.execute('PRAGMA journal_mode=OFF')
        self.conn.execute('PRAGMA synchronous=OFF')
        self.table = table
        types = {
            'label': 'INTEGER', 'inconclusive': 'INTEGER', 'report_cwe': 'INTEGER',
            'line': 'INTEGER', 'column': 'INTEGER', 'n_locations': 'INTEGER',
            'bug_function_start': 'INTEGER', 'bug_function_end': 'INTEGER',
            'testcase_id': 'INTEGER', 'cwe_match': 'INTEGER', 'on_flaw_line': 'INTEGER',
            'flaw_line_dist': 'INTEGER',
        }
        cols = ', '.join(f'"{c}" {types.get(c, "TEXT")}' for c in COLUMNS)
        self.conn.execute(f'CREATE TABLE {table} (id INTEGER PRIMARY KEY, {cols})')
        self.sql = f'INSERT INTO {table} ({", ".join(chr(34)+c+chr(34) for c in COLUMNS)}) VALUES ({", ".join("?"*len(COLUMNS))})'
        self.buf: List[tuple] = []

    def write(self, row: dict):
        self.buf.append(tuple(row[c] for c in COLUMNS))
        if len(self.buf) >= 2000:
            self.flush()

    def flush(self):
        if self.buf:
            self.conn.executemany(self.sql, self.buf)
            self.buf.clear()

    def close(self):
        self.flush()
        self.conn.execute(f'CREATE INDEX IF NOT EXISTS idx_{self.table}_label ON {self.table}(label)')
        self.conn.execute(f'CREATE INDEX IF NOT EXISTS idx_{self.table}_checker ON {self.table}(checker_id)')
        self.conn.execute(f'CREATE INDEX IF NOT EXISTS idx_{self.table}_testcase ON {self.table}(testcase_id)')
        self.conn.commit()
        self.conn.close()


class CsvWriter:
    def __init__(self, path: str):
        csv.field_size_limit(min(sys.maxsize, 2**31 - 1))
        self.fh = open(path, 'w', newline='', encoding='utf-8')
        self.w = csv.DictWriter(self.fh, fieldnames=['id'] + COLUMNS)
        self.w.writeheader()

    def write(self, row: dict, rid: int):
        self.w.writerow({'id': rid, **row})

    def close(self):
        self.fh.close()


class JsonlWriter:
    def __init__(self, path: str):
        self.fh = open(path, 'w', encoding='utf-8')

    def write(self, row: dict, rid: int):
        r = {'id': rid, **row}
        r['functions'] = json.loads(r['functions'])
        r['trace_json'] = json.loads(r['trace_json'])
        self.fh.write(json.dumps(r, ensure_ascii=False) + '\n')

    def close(self):
        self.fh.close()


# --------------------------------------------------------------------------- #
# Validation mode: every manifest flaw line must land in a 'bad' region
# --------------------------------------------------------------------------- #


def validate(suite: Suite, truth: Dict[str, FileTruth], show: int = 25) -> int:
    t0 = time.time()
    region_counts: Counter = Counter()
    src_counts: Counter = Counter()
    bad_examples = []
    parse_errors = []
    n_files = 0
    n_flaws = 0
    no_unit = 0
    for bn, ft in truth.items():
        if not ft.flaw_lines:
            continue
        rel = suite.by_basename.get(bn)
        if rel is None:
            bad_examples.append((bn, None, 'file not found in testcases/'))
            continue
        sf = suite.get(rel)
        n_files += 1
        if sf is None:
            bad_examples.append((bn, None, 'unreadable'))
            continue
        if sf.parse_error:
            parse_errors.append((rel, sf.parse_error))
        for ln, cwe in ft.flaw_lines.items():
            n_flaws += 1
            region, src, unit = sf.region_for_line(ln)
            region_counts[region] += 1
            src_counts[src] += 1
            if unit is None:
                no_unit += 1
            if region != 'bad':
                bad_examples.append((rel, ln, f'region={region} src={src} unit={unit.name if unit else None}'))
    print(f'[validate] files with flaws: {n_files}, flaw lines: {n_flaws}, '
          f'time {time.time()-t0:.1f}s')
    print(f'[validate] region of manifest flaw lines: {dict(region_counts)}')
    print(f'[validate] region source: {dict(src_counts)}')
    print(f'[validate] flaw lines outside any function/class unit: {no_unit}')
    print(f'[validate] files with parse errors: {len(parse_errors)}')
    for rel, e in parse_errors[:show]:
        print(f'    parse error: {rel}: {e}')
    print(f'[validate] flaw lines NOT in a bad region: {len(bad_examples)}')
    for rel, ln, why in bad_examples[:show]:
        print(f'    {rel}:{ln}  {why}')
    return 0 if not bad_examples and not parse_errors else 1


# --------------------------------------------------------------------------- #
# Main
# --------------------------------------------------------------------------- #


def find_c_dir(juliet: Optional[str]) -> str:
    cands = []
    if juliet:
        cands += [juliet, os.path.join(juliet, 'C')]
    cands += ['C', '.'] + sorted(glob.glob('*juliet*/C')) + sorted(glob.glob('*juliet*'))
    for c in cands:
        if os.path.isfile(os.path.join(c, 'manifest.xml')) and os.path.isdir(os.path.join(c, 'testcases')):
            return os.path.abspath(c)
    sys.exit('Could not locate the Juliet "C" directory (needs manifest.xml + testcases/). Use --juliet.')


def load_cwe_map(path: Optional[str]) -> Dict[int, Set[int]]:
    if not path:
        return {}
    with open(path, encoding='utf-8') as fh:
        raw = json.load(fh)
    out: Dict[int, Set[int]] = {}
    for k, v in raw.items():
        if str(k).startswith('_'):          # allow "_comment" keys in the JSON
            continue
        ks = int(re.sub(r'\D', '', str(k)))
        vs = v if isinstance(v, list) else [v]
        out[ks] = {int(re.sub(r'\D', '', str(x))) for x in vs}
    return out


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('--results', default='results.xml', help='cppcheck XML (version 2) output')
    ap.add_argument('--juliet', default=None, help='Juliet root (dir containing C/) or the C dir itself')
    ap.add_argument('--out', default='dataset.sqlite', help='SQLite output (table code_trace)')
    ap.add_argument('--table', default='code_trace')
    ap.add_argument('--csv', default=None, help='also write a CSV file')
    ap.add_argument('--jsonl', default=None, help='also write a JSON-lines file')
    ap.add_argument('--url-base', default=None,
                    help='prefix for bug_url (default file://<abs C dir>/). '
                         'E.g. https://github.com/<user>/<repo>/blob/main/C/')
    ap.add_argument('--cwe-map', default=None,
                    help='JSON {"788": ["121","122","126"], ...}: extra Juliet CWEs accepted as a '
                         'match for a cppcheck CWE (default: exact match only)')
    ap.add_argument('--severities', default='error,warning,style,performance,portability',
                    help='comma list of cppcheck severities to keep (information is dropped by default)')
    ap.add_argument('--ids', default=None, help='comma list: keep only these cppcheck checker ids')
    ap.add_argument('--exclude-ids', default=None, help='comma list: drop these checker ids')
    ap.add_argument('--require-cwe', action='store_true', help='drop findings that carry no CWE')
    ap.add_argument('--include-non-testcase', action='store_true',
                    help='keep findings in files not listed in manifest.xml (main.cpp, testcases.h, ...)')
    ap.add_argument('--keep-duplicates', action='store_true',
                    help='keep findings cppcheck reported identically more than once (different configurations)')
    ap.add_argument('--strip-comments', action='store_true',
                    help='remove comments from bug_function/functions code (avoids FLAW/FIX label leakage)')
    ap.add_argument('--limit', type=int, default=None, help='stop after N rows (smoke test)')
    ap.add_argument('--validate', action='store_true',
                    help='only check that every manifest flaw line maps to a bad region; no dataset')
    args = ap.parse_args(argv)

    c_dir = find_c_dir(args.juliet)
    print(f'[info] Juliet C dir: {c_dir}')
    t0 = time.time()
    truth = load_manifest(os.path.join(c_dir, 'manifest.xml'))
    print(f'[info] manifest: {len(truth)} files, {len({t.testcase_id for t in truth.values()})} test cases '
          f'({time.time()-t0:.1f}s)')
    suite = Suite(c_dir)
    print(f'[info] indexed {len(suite.by_basename)} source files under testcases/')

    if args.validate:
        return validate(suite, truth)

    if not os.path.isfile(args.results):
        sys.exit(f'results file not found: {args.results}')
    url_base = args.url_base or ('file://' + c_dir.rstrip('/') + '/')
    cwe_map = load_cwe_map(args.cwe_map)
    keep_sev = {s.strip() for s in args.severities.split(',') if s.strip()}
    only_ids = {s.strip() for s in args.ids.split(',')} if args.ids else None
    excl_ids = {s.strip() for s in args.exclude_ids.split(',')} if args.exclude_ids else set()

    sq = SqliteWriter(args.out, args.table)
    cw = CsvWriter(args.csv) if args.csv else None
    jw = JsonlWriter(args.jsonl) if args.jsonl else None

    stats = Counter()
    label_by_checker: Dict[str, Counter] = defaultdict(Counter)
    mismatch_pairs: Counter = Counter()
    seen_keys: Set[tuple] = set()
    rid = 0
    t0 = time.time()
    for _ev, el in ET.iterparse(args.results, events=('end',)):
        if el.tag != 'error':
            continue
        stats['errors_total'] += 1
        try:
            sev = el.get('severity', '')
            cid = el.get('id', '')
            if sev not in keep_sev:
                stats['skipped_severity'] += 1
                continue
            if only_ids is not None and cid not in only_ids:
                stats['skipped_id_filter'] += 1
                continue
            if cid in excl_ids:
                stats['skipped_id_filter'] += 1
                continue
            if args.require_cwe and not el.get('cwe'):
                stats['skipped_no_cwe'] += 1
                continue
            if not args.keep_duplicates:
                key = (cid, el.get('msg', ''),
                       tuple((l.get('file'), l.get('line'), l.get('column')) for l in el.findall('location')))
                if key in seen_keys:
                    stats['skipped_duplicate'] += 1
                    continue
                seen_keys.add(key)
            row = build_row(el, suite, truth, url_base, cwe_map, args.strip_comments,
                            args.include_non_testcase)
            if row is None:
                stats['skipped_unresolved_or_non_testcase'] += 1
                continue
            rid += 1
            sq.write(row)
            if cw:
                cw.write(row, rid)
            if jw:
                jw.write(row, rid)
            stats['rows'] += 1
            stats[f'label_{row["label"]}'] += 1
            stats[f'region_{row["region"]}'] += 1
            label_by_checker[row['checker_id']][row['label']] += 1
            if row['region'] == 'bad' and not row['cwe_match'] and row['report_cwe'] is not None:
                mismatch_pairs[(row['report_cwe'], row['testcase_cwes'])] += 1
            if rid % 20000 == 0:
                print(f'[info] {rid} rows ({time.time()-t0:.0f}s)')
            if args.limit and rid >= args.limit:
                break
        finally:
            el.clear()

    sq.close()
    if cw:
        cw.close()
    if jw:
        jw.close()

    print(f'[done] {stats["rows"]} rows written to {args.out} (table {args.table}) in {time.time()-t0:.0f}s')
    print('[stats]', json.dumps(stats, indent=2, sort_keys=True))
    if suite.missing:
        print(f'[warn] {sum(suite.missing.values())} locations referenced unreadable files, e.g. {list(suite.missing)[:5]}')
    print('[stats] label distribution per checker (top 30 by volume):')
    for cid, c in sorted(label_by_checker.items(), key=lambda kv: -sum(kv[1].values()))[:30]:
        print(f'    {cid:32s} TP={c[1]:7d}  FP={c[0]:7d}')
    if mismatch_pairs:
        print('[stats] findings in BAD code whose CWE differs from the test-case CWE '
              '(candidates for --cwe-map if you consider them equivalent), top 25:')
        for (rc, tc), n in mismatch_pairs.most_common(25):
            print(f'    cppcheck CWE-{rc:<4} vs Juliet CWE(s) {tc:12s} : {n}')
    return 0


if __name__ == '__main__':
    sys.exit(main())
