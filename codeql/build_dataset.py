#!/usr/bin/env python3
"""
build_dataset.py (CodeQL edition)
=================================
Label CodeQL findings (codeql.sarif) against the NIST Juliet C/C++ 1.3 ground
truth and emit the same `code_trace` table as ../cppcheck/build_dataset.py:

    label | trace | bug_function | functions | bug_url   (+ metadata columns)

Labeling rule (identical to the cppcheck version):
    label = 1  (true positive)  iff
        (a) the finding's primary location lies in *bad* code of a Juliet test
            case, AND
        (b) one of the CWEs tagged on the CodeQL rule (properties.tags:
            "external/cwe/cwe-NNN") equals one of the CWEs NIST assigns to
            that test case.
    label = 0  (false positive)  otherwise.

Differences from the cppcheck version, forced by the input format:
  * input is SARIF 2.1.0 (--sarif), not cppcheck XML;
  * a CodeQL rule can carry several CWEs: `report_cwe` holds the first one
    and the extra column `report_cwes` holds the full ';'-joined list —
    cwe_match uses all of them;
  * `severity` is the SARIF level (error/warning/note), `inconclusive` is
    always 0, `tu_file` is always ''.

All the shared machinery (manifest parsing, bad/good region detection,
function extraction, writers) is imported from ../cppcheck/build_dataset.py.

Usage (run from codeql/; the Juliet suite is auto-detected in ./ or ../):
    python3 build_dataset.py
    python3 build_dataset.py --sarif codeql.sarif --csv dataset.csv
    python3 build_dataset.py --limit 2000          # smoke test
"""
from __future__ import annotations

import argparse
import importlib.util
import json
import os
import re
import sys
import time
from collections import Counter, defaultdict
from typing import Dict, List, Optional, Set, Tuple

# --------------------------------------------------------------------------- #
# Import the shared machinery from the cppcheck script
# --------------------------------------------------------------------------- #

_HERE = os.path.dirname(os.path.abspath(__file__))
_CPP_SCRIPT = os.path.join(_HERE, '..', 'cppcheck', 'build_dataset.py')


def _load_shared():
    if not os.path.isfile(_CPP_SCRIPT):
        sys.exit(f'shared module not found: {_CPP_SCRIPT} '
                 '(this script reuses ../cppcheck/build_dataset.py)')
    spec = importlib.util.spec_from_file_location('cppcheck_build_dataset', _CPP_SCRIPT)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = mod   # dataclasses need the module in sys.modules
    spec.loader.exec_module(mod)
    return mod


shared = _load_shared()

# one extra column: full CWE list of the CodeQL rule
if 'report_cwes' not in shared.COLUMNS:
    shared.COLUMNS.insert(shared.COLUMNS.index('report_cwe') + 1, 'report_cwes')
COLUMNS = shared.COLUMNS

_CWE_TAG_RE = re.compile(r'^external/cwe/cwe-0*(\d+)$', re.I)

# --------------------------------------------------------------------------- #
# SARIF parsing
# --------------------------------------------------------------------------- #


def rule_index(run: dict) -> Dict[str, dict]:
    """ruleId -> {'cwes': [...], 'level': str, 'desc': str, 'sec_sev': str}."""
    out: Dict[str, dict] = {}
    comps = [run.get('tool', {}).get('driver', {})] + run.get('tool', {}).get('extensions', [])
    for comp in comps:
        for ru in comp.get('rules', []) or []:
            props = ru.get('properties', {}) or {}
            cwes = []
            for tag in props.get('tags', []) or []:
                m = _CWE_TAG_RE.match(tag)
                if m:
                    cwes.append(int(m.group(1)))
            desc = (ru.get('fullDescription') or ru.get('shortDescription') or {}).get('text', '')
            out[ru.get('id', '')] = {
                'cwes': sorted(set(cwes)),
                'level': (ru.get('defaultConfiguration') or {}).get('level', 'warning'),
                'desc': desc,
                'sec_sev': props.get('security-severity'),
            }
    return out


def loc_tuple(loc: dict) -> Optional[Tuple[str, int, int, str]]:
    """SARIF location -> (uri, line, column, info message) or None."""
    phys = loc.get('physicalLocation') or {}
    art = phys.get('artifactLocation') or {}
    uri = art.get('uri', '')
    if not uri or uri.startswith('file:///'):
        return None
    region = phys.get('region') or {}
    line = int(region.get('startLine', 0) or 0)
    col = int(region.get('startColumn', 0) or 0)
    info = (loc.get('message') or {}).get('text', '')
    return (uri, line, col, info)


def result_locations(res: dict) -> List[Tuple[str, int, int, str]]:
    """Trace steps, source -> sink; the *last* entry is the primary location."""
    steps: List[Tuple[str, int, int, str]] = []
    for cf in res.get('codeFlows', [])[:1]:                 # first flow is enough
        for tf in cf.get('threadFlows', [])[:1]:
            for st in tf.get('locations', []):
                t = loc_tuple(st.get('location', {}))
                if t:
                    steps.append(t)
    prim = None
    for loc in res.get('locations', []):
        prim = loc_tuple(loc)
        if prim:
            break
    if prim and (not steps or steps[-1][:2] != prim[:2]):
        steps.append(prim)
    return steps


# --------------------------------------------------------------------------- #
# Row construction (mirrors shared.build_row, adapted for SARIF)
# --------------------------------------------------------------------------- #


def build_row(res: dict, rules: Dict[str, dict], suite, truth, url_base: str,
              cwe_map: Dict[int, Set[int]], do_strip: bool,
              include_non_testcase: bool) -> Optional[dict]:
    rule_id = res.get('ruleId', '')
    meta = rules.get(rule_id, {'cwes': [], 'level': 'warning', 'desc': '', 'sec_sev': None})
    severity = res.get('level') or meta['level']
    msg = (res.get('message') or {}).get('text', '')
    report_cwes: List[int] = meta['cwes']
    report_cwe = report_cwes[0] if report_cwes else None

    steps = result_locations(res)
    if not steps:
        return None
    # primary = SARIF result location = last step (the sink)
    pfile, pline, pcol, _pinfo = steps[-1]
    prel = suite.resolve(pfile)
    if prel is None:
        return None
    ft = truth.get(os.path.basename(prel))
    if ft is None and not include_non_testcase:
        return None

    # ---- code units along the trace (primary first, like the cppcheck rows)
    ordered = [steps[-1]] + steps[:-1]
    trace_entries, functions, seen_units = [], [], set()
    bug_unit = bug_sf = None
    for idx, (f, ln, col, info) in enumerate(ordered):
        rel = suite.resolve(f)
        sf = suite.get(rel) if rel else None
        unit = sf.unit_at(ln) if sf else None
        trace_entries.append({
            'file': rel or f, 'line': ln, 'column': col, 'info': info,
            'function': unit.name if unit else None,
            'region': (sf.region_for_line(ln)[0] if sf else None),
        })
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
                    'code': shared.strip_comments(code) if do_strip else code,
                })

    # ---- region / ground truth for the primary location
    if bug_sf is not None:
        region, region_source, _u = bug_sf.region_for_line(pline)
    else:
        region, region_source = 'other', 'none'

    if ft is not None:
        tc_cwes = ft.testcase_cwes
        accepted: Set[int] = set()
        for c in report_cwes:
            accepted |= {c} | cwe_map.get(c, set())
        cwe_match = 1 if (accepted & tc_cwes) else 0
        flaw_lines = sorted(ft.flaw_lines)
        on_flaw_line = 1 if pline in ft.flaw_lines else 0
        flaw_dist = min((abs(pline - fl) for fl in flaw_lines), default=None)
        testcase_id, testcase_name = ft.testcase_id, ft.testcase_name
    else:
        tc_cwes, cwe_match, flaw_lines, on_flaw_line, flaw_dist = set(), 0, [], 0, None
        testcase_id, testcase_name = None, None

    label = 1 if (region == 'bad' and cwe_match) else 0

    incidental: List[int] = []
    if bug_unit is not None and bug_sf is not None:
        incidental = sorted({int(x) for x in shared._INCIDENTAL_RE.findall(bug_sf.code(bug_unit))})

    cwe_txt = ','.join(f'CWE-{c}' for c in report_cwes) or 'CWE-?'
    tlines = [f'{rule_id} [{severity}] {cwe_txt}: {msg}']
    for k, e in enumerate(trace_entries):
        fn = f' (in {e["function"]})' if e['function'] else ''
        info = f' {e["info"]}' if e['info'] else ''
        tlines.append(f'  #{k} {e["file"]}:{e["line"]}:{e["column"]}{info}{fn}')
    trace = '\n'.join(tlines)

    bug_code = ''
    if bug_unit is not None and bug_sf is not None:
        bug_code = bug_sf.code(bug_unit)
        if do_strip:
            bug_code = shared.strip_comments(bug_code)

    verbose = meta['desc']
    if meta['sec_sev'] is not None:
        verbose = f'{verbose} [security-severity {meta["sec_sev"]}]'.strip()

    return {
        'label': label,
        'trace': trace,
        'bug_function': bug_code,
        'functions': json.dumps(functions, ensure_ascii=False),
        'bug_url': shared.make_url(url_base, prel, pline),
        'checker_id': rule_id,
        'severity': severity,
        'inconclusive': 0,
        'report_cwe': report_cwe,
        'report_cwes': ';'.join(str(c) for c in report_cwes),
        'msg': msg,
        'verbose': verbose,
        'file': prel,
        'line': pline,
        'column': pcol,
        'tu_file': '',
        'n_locations': len(trace_entries),
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
# Main
# --------------------------------------------------------------------------- #


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('--sarif', default='codeql.sarif', help='CodeQL SARIF 2.1.0 output')
    ap.add_argument('--juliet', default=None, help='Juliet root (dir containing C/) or the C dir itself')
    ap.add_argument('--out', default='dataset.sqlite', help='SQLite output (table code_trace)')
    ap.add_argument('--table', default='code_trace')
    ap.add_argument('--csv', default=None, help='also write a CSV file')
    ap.add_argument('--jsonl', default=None, help='also write a JSON-lines file')
    ap.add_argument('--url-base', default=None,
                    help='prefix for bug_url (default file://<abs C dir>/)')
    ap.add_argument('--cwe-map', default=None,
                    help='JSON {"788": ["121","122","126"], ...}: extra Juliet CWEs accepted as a '
                         'match for a CodeQL CWE (default: exact match only)')
    ap.add_argument('--severities', default='error,warning,note',
                    help='comma list of SARIF levels to keep')
    ap.add_argument('--ids', default=None, help='comma list: keep only these CodeQL rule ids')
    ap.add_argument('--exclude-ids', default=None, help='comma list: drop these rule ids')
    ap.add_argument('--require-cwe', action='store_true', help='drop findings whose rule has no CWE tag')
    ap.add_argument('--include-non-testcase', action='store_true',
                    help='keep findings in files absent from the manifest (label 0)')
    ap.add_argument('--keep-duplicates', action='store_true',
                    help='do not collapse identical (rule, msg, locations) findings')
    ap.add_argument('--strip-comments', action='store_true',
                    help='remove comments from bug_function/functions code (avoids FLAW/FIX label leakage)')
    ap.add_argument('--limit', type=int, default=None, help='stop after N rows (smoke test)')
    args = ap.parse_args(argv)

    c_dir = shared.find_c_dir(args.juliet)
    print(f'[info] Juliet C dir: {c_dir}')
    t0 = time.time()
    truth = shared.load_manifest(os.path.join(c_dir, 'manifest.xml'))
    print(f'[info] manifest: {len(truth)} files, {len({t.testcase_id for t in truth.values()})} test cases '
          f'({time.time()-t0:.1f}s)')
    suite = shared.Suite(c_dir)
    print(f'[info] indexed {len(suite.by_basename)} source files under testcases/')

    if not os.path.isfile(args.sarif):
        sys.exit(f'SARIF file not found: {args.sarif}')
    with open(args.sarif, 'r', encoding='utf-8') as fh:
        sarif = json.load(fh)
    url_base = args.url_base or ('file://' + c_dir.rstrip('/') + '/')
    cwe_map = shared.load_cwe_map(args.cwe_map)
    keep_sev = {s.strip() for s in args.severities.split(',') if s.strip()}
    only_ids = {s.strip() for s in args.ids.split(',')} if args.ids else None
    excl_ids = {s.strip() for s in args.exclude_ids.split(',')} if args.exclude_ids else set()

    sq = shared.SqliteWriter(args.out, args.table)
    cw = shared.CsvWriter(args.csv) if args.csv else None
    jw = shared.JsonlWriter(args.jsonl) if args.jsonl else None

    stats = Counter()
    label_by_checker: Dict[str, Counter] = defaultdict(Counter)
    mismatch_pairs: Counter = Counter()
    seen_keys: Set[tuple] = set()
    rid = 0
    t0 = time.time()
    for run in sarif.get('runs', []):
        rules = rule_index(run)
        print(f'[info] {run["tool"]["driver"].get("name")} '
              f'{run["tool"]["driver"].get("semanticVersion", "")}: '
              f'{len(run.get("results", []))} results, {len(rules)} rules')
        for res in run.get('results', []):
            stats['errors_total'] += 1
            rule_id = res.get('ruleId', '')
            meta = rules.get(rule_id, {})
            sev = res.get('level') or meta.get('level', 'warning')
            if sev not in keep_sev:
                stats['skipped_severity'] += 1
                continue
            if only_ids is not None and rule_id not in only_ids:
                stats['skipped_id_filter'] += 1
                continue
            if rule_id in excl_ids:
                stats['skipped_id_filter'] += 1
                continue
            if args.require_cwe and not meta.get('cwes'):
                stats['skipped_no_cwe'] += 1
                continue
            if not args.keep_duplicates:
                key = (rule_id, (res.get('message') or {}).get('text', ''),
                       tuple(loc_tuple(l) for l in res.get('locations', [])))
                if key in seen_keys:
                    stats['skipped_duplicate'] += 1
                    continue
                seen_keys.add(key)
            row = build_row(res, rules, suite, truth, url_base, cwe_map,
                            args.strip_comments, args.include_non_testcase)
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
            if row['region'] == 'bad' and not row['cwe_match'] and row['report_cwes']:
                mismatch_pairs[(row['report_cwes'], row['testcase_cwes'])] += 1
            if rid % 5000 == 0:
                print(f'[info] {rid} rows ({time.time()-t0:.0f}s)')
            if args.limit and rid >= args.limit:
                break
        if args.limit and rid >= args.limit:
            break

    sq.close()
    if cw:
        cw.close()
    if jw:
        jw.close()

    print(f'[done] {stats["rows"]} rows written to {args.out} (table {args.table}) in {time.time()-t0:.0f}s')
    print('[stats]', json.dumps(stats, indent=2, sort_keys=True))
    if suite.missing:
        print(f'[warn] {sum(suite.missing.values())} locations referenced unreadable files, '
              f'e.g. {list(suite.missing)[:5]}')
    print('[stats] label distribution per rule (top 30 by volume):')
    for cid, c in sorted(label_by_checker.items(), key=lambda kv: -sum(kv[1].values()))[:30]:
        print(f'    {cid:40s} TP={c[1]:6d}  FP={c[0]:6d}')
    if mismatch_pairs:
        print('[stats] findings in BAD code whose CWE differs from the test-case CWE '
              '(candidates for --cwe-map if you consider them equivalent), top 25:')
        for (rc, tc), n in mismatch_pairs.most_common(25):
            print(f'    CodeQL CWE(s) {rc:15s} vs Juliet CWE(s) {tc:12s} : {n}')
    return 0


if __name__ == '__main__':
    sys.exit(main())
