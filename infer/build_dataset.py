#!/usr/bin/env python3
"""
build_dataset.py (Infer edition)
================================
Label Facebook Infer findings (report.json) against the NIST Juliet C/C++ 1.3
ground truth and emit the same `code_trace` table as ../cppcheck/build_dataset.py
and ../codeql/build_dataset.py:

    label | trace | bug_function | functions | bug_url   (+ metadata columns)

Labeling rule (identical to the other two):
    label = 1  (true positive)  iff
        (a) the finding's primary location lies in *bad* code of a Juliet test
            case, AND
        (b) one of the CWEs this script maps to the Infer bug type equals one
            of the CWEs NIST assigns to that test case.
    label = 0  (false positive)  otherwise.

Infer reports its own bug types (NULLPTR_DEREFERENCE, MEMORY_LEAK_C, ...),
not CWEs, so this script carries a bug_type -> CWE map (TYPE_CWES below,
overridable with --type-cwe-map). Quality findings with no sensible CWE
(DEAD_STORE aside, e.g. PULSE_UNNECESSARY_COPY*) map to nothing and can
therefore never be true positives — same treatment as cppcheck findings that
carry no CWE.

Differences from the cppcheck version, forced by the input format:
  * input is Infer's report.json (--report);
  * `report_cwes` holds the mapped CWE list (like the codeql column);
  * `severity` is Infer's severity, lowercased (error/warning/...);
  * `inconclusive` is always 0, `tu_file` is always ''.

Usage (run from infer/; the Juliet suite is auto-detected in ./ or ../):
    python3 build_dataset.py
    python3 build_dataset.py --report report.json --csv dataset.csv
    python3 build_dataset.py --limit 2000          # smoke test
"""
from __future__ import annotations

import argparse
import importlib.util
import json
import os
import sys
import time
from collections import Counter, defaultdict
from typing import Dict, List, Optional, Set

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

if 'report_cwes' not in shared.COLUMNS:
    shared.COLUMNS.insert(shared.COLUMNS.index('report_cwe') + 1, 'report_cwes')
COLUMNS = shared.COLUMNS

# --------------------------------------------------------------------------- #
# Infer bug type -> CWE(s)
# --------------------------------------------------------------------------- #

TYPE_CWES: Dict[str, List[int]] = {
    'NULLPTR_DEREFERENCE':              [476],
    'NULL_DEREFERENCE':                 [476],
    'MEMORY_LEAK_C':                    [401],
    'MEMORY_LEAK_CPP':                  [401],
    'PULSE_RESOURCE_LEAK':              [772],
    'USE_AFTER_FREE':                   [416],
    'USE_AFTER_DELETE':                 [416],
    'USE_AFTER_LIFETIME':               [416],
    'PULSE_UNINITIALIZED_VALUE':        [457],
    'UNINITIALIZED_VALUE':              [457],
    'DEAD_STORE':                       [563],
    'STACK_VARIABLE_ADDRESS_ESCAPE':    [562],
    'BUFFER_OVERRUN_L1':                [119, 121, 122, 125, 787],
    'BUFFER_OVERRUN_L2':                [119, 121, 122, 125, 787],
    'BUFFER_OVERRUN_L3':                [119, 121, 122, 125, 787],
    'INTEGER_OVERFLOW_L1':              [190],
    'INTEGER_OVERFLOW_L2':              [190],
    # quality/performance findings with no meaningful CWE:
    'PULSE_UNNECESSARY_COPY':           [],
    'PULSE_UNNECESSARY_COPY_INTERMEDIATE': [],
    'PULSE_UNNECESSARY_COPY_ASSIGNMENT': [],
    'PULSE_CONST_REFABLE':              [],
}


def load_type_map(path: Optional[str]) -> Dict[str, List[int]]:
    if not path:
        return TYPE_CWES
    with open(path) as fh:
        raw = json.load(fh)
    return {k: [int(x) for x in v] for k, v in raw.items() if not k.startswith('_')}


# --------------------------------------------------------------------------- #
# Row construction (mirrors the codeql adapter)
# --------------------------------------------------------------------------- #


def build_row(res: dict, type_map: Dict[str, List[int]], suite, truth, url_base: str,
              cwe_map: Dict[int, Set[int]], do_strip: bool,
              include_non_testcase: bool) -> Optional[dict]:
    bug_type = res.get('bug_type', '')
    severity = (res.get('severity') or '').lower()
    msg = res.get('qualifier', '')
    report_cwes = type_map.get(bug_type, [])
    report_cwe = report_cwes[0] if report_cwes else None

    pfile, pline, pcol = res.get('file', ''), int(res.get('line', 0) or 0), int(res.get('column', 0) or 0)
    prel = suite.resolve(pfile)
    if prel is None:
        return None
    ft = truth.get(os.path.basename(prel))
    if ft is None and not include_non_testcase:
        return None

    # trace: primary location first (like the cppcheck/codeql rows), then the
    # bug_trace steps in Infer's own order
    steps = [(pfile, pline, pcol, '')]
    for st in res.get('bug_trace', []):
        steps.append((st.get('filename', ''), int(st.get('line_number', 0) or 0),
                      int(st.get('column_number', 0) or 0), st.get('description', '') or ''))

    trace_entries, functions, seen_units = [], [], set()
    bug_unit = bug_sf = None
    for idx, (f, ln, col, info) in enumerate(steps):
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
    tlines = [f'{bug_type} [{severity}] {cwe_txt}: {msg}']
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

    return {
        'label': label,
        'trace': trace,
        'bug_function': bug_code,
        'functions': json.dumps(functions, ensure_ascii=False),
        'bug_url': shared.make_url(url_base, prel, pline),
        'checker_id': bug_type,
        'severity': severity,
        'inconclusive': 0,
        'report_cwe': report_cwe,
        'report_cwes': ';'.join(str(c) for c in report_cwes),
        'msg': msg,
        'verbose': res.get('category', ''),
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
    ap.add_argument('--report', default='report.json', help="Infer's report.json")
    ap.add_argument('--juliet', default=None, help='Juliet root (dir containing C/) or the C dir itself')
    ap.add_argument('--out', default='dataset.sqlite', help='SQLite output (table code_trace)')
    ap.add_argument('--table', default='code_trace')
    ap.add_argument('--csv', default=None, help='also write a CSV file')
    ap.add_argument('--jsonl', default=None, help='also write a JSON-lines file')
    ap.add_argument('--url-base', default=None,
                    help='prefix for bug_url (default file://<abs C dir>/)')
    ap.add_argument('--type-cwe-map', default=None,
                    help='JSON {"NULLPTR_DEREFERENCE": [476], ...} overriding the built-in '
                         'Infer bug_type -> CWE map')
    ap.add_argument('--cwe-map', default=None,
                    help='JSON {"476": ["690"], ...}: extra Juliet CWEs accepted as a match '
                         'for a mapped CWE (default: exact match only)')
    ap.add_argument('--severities', default='error,warning,advice,like,info',
                    help='comma list of Infer severities to keep (lowercased)')
    ap.add_argument('--ids', default=None, help='comma list: keep only these Infer bug types')
    ap.add_argument('--exclude-ids', default=None, help='comma list: drop these bug types')
    ap.add_argument('--require-cwe', action='store_true',
                    help='drop findings whose bug type maps to no CWE')
    ap.add_argument('--include-non-testcase', action='store_true',
                    help='keep findings in files absent from the manifest (label 0)')
    ap.add_argument('--keep-duplicates', action='store_true',
                    help='do not collapse identical (type, msg, file, line) findings')
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

    if not os.path.isfile(args.report):
        sys.exit(f'report file not found: {args.report}')
    with open(args.report, 'r', encoding='utf-8') as fh:
        results = json.load(fh)
    print(f'[info] Infer report: {len(results)} issues')
    type_map = load_type_map(args.type_cwe_map)
    unmapped = Counter(r['bug_type'] for r in results if r.get('bug_type') not in type_map)
    if unmapped:
        print(f'[warn] bug types with no CWE mapping (treated as no-CWE): {dict(unmapped)}')

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
    for res in results:
        stats['errors_total'] += 1
        bug_type = res.get('bug_type', '')
        sev = (res.get('severity') or '').lower()
        if sev not in keep_sev:
            stats['skipped_severity'] += 1
            continue
        if only_ids is not None and bug_type not in only_ids:
            stats['skipped_id_filter'] += 1
            continue
        if bug_type in excl_ids:
            stats['skipped_id_filter'] += 1
            continue
        if args.require_cwe and not type_map.get(bug_type):
            stats['skipped_no_cwe'] += 1
            continue
        if not args.keep_duplicates:
            key = (bug_type, res.get('qualifier', ''), res.get('file'), res.get('line'))
            if key in seen_keys:
                stats['skipped_duplicate'] += 1
                continue
            seen_keys.add(key)
        row = build_row(res, type_map, suite, truth, url_base, cwe_map,
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
        if rid % 10000 == 0:
            print(f'[info] {rid} rows ({time.time()-t0:.0f}s)')
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
    print('[stats] label distribution per bug type (top 30 by volume):')
    for cid, c in sorted(label_by_checker.items(), key=lambda kv: -sum(kv[1].values()))[:30]:
        print(f'    {cid:40s} TP={c[1]:6d}  FP={c[0]:6d}')
    if mismatch_pairs:
        print('[stats] findings in BAD code whose CWE differs from the test-case CWE '
              '(candidates for --cwe-map if you consider them equivalent), top 25:')
        for (rc, tc), n in mismatch_pairs.most_common(25):
            print(f'    Infer CWE(s) {rc:15s} vs Juliet CWE(s) {tc:12s} : {n}')
    return 0


if __name__ == '__main__':
    sys.exit(main())
