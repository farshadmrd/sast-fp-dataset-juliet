#!/usr/bin/env python3
"""
make_splits.py
==============
Turn a dataset built by cppcheck/build_dataset.py or codeql/build_dataset.py
into fine-tuning-ready train/val/test JSONL files.

Why the raw dataset must NOT be used directly for training:
  1. Juliet code is full of label giveaways: /* FLAW */ and /* FIX */ comments,
     function/class names containing bad/good (badSink, goodG2B, ..._bad), and
     file paths that embed the test case's CWE (testcases/CWE190_.../x.c).
     A model shortcuts on those instead of learning anything about the warning.
  2. Juliet ships ~18 near-identical control-flow variants of every flaw, so a
     random row split leaks train rows into the test set.

What this script does:
  * strips comments from all code (reusing strip_comments from the cppcheck
    script);
  * masks bad/good/OMITBAD-style identifiers to a neutral token, identically
    for bad and good so they become indistinguishable;
  * replaces every Juliet CWE-bearing name/path segment with a stable
    anonymous hash token (tc_ab12cd34);
  * splits 80/10/10 *by test case* (stable hash of testcase_id), never by row.

Each output line:
    {"id", "label", "tool",
     "input": {checker_id, severity, report_cwe[, report_cwes], msg,
               trace, bug_function, functions:[{name, kind, code}]},
     "meta":  {...ground truth, UNMASKED — never feed this to the model...}}

Usage:
    python3 make_splits.py --dataset cppcheck/dataset.sqlite --tool cppcheck \
        --outdir cppcheck/splits
    python3 make_splits.py --dataset codeql/dataset.sqlite --tool codeql \
        --outdir codeql/splits
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
import re
import sqlite3
import sys
from collections import Counter

_HERE = os.path.dirname(os.path.abspath(__file__))


def _load_shared():
    p = os.path.join(_HERE, 'cppcheck', 'build_dataset.py')
    spec = importlib.util.spec_from_file_location('cppcheck_build_dataset', p)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = mod
    spec.loader.exec_module(mod)
    return mod


strip_comments = _load_shared().strip_comments

# --------------------------------------------------------------------------- #
# Masking
# --------------------------------------------------------------------------- #

# bad / good / goodG2B1 / goodB2G ... as an identifier fragment.  The
# lookarounds keep English words ("badly", "goodness") in analyzer messages
# intact: the fragment must not be followed by a lowercase letter and not be
# preceded by a letter.
_BADGOOD_RE = re.compile(r'(?<![A-Za-z])(?:good(?:G2B|B2G)?\d*|bad)(?![a-z])')
_OMIT_RE = re.compile(r'\bOMIT(?:BAD|GOOD)\b')
# any Juliet test-case-derived identifier or path segment: CWE190_Integer_...
_TC_RE = re.compile(r'CWE\d+_[A-Za-z0-9_]+')
# leftover bare CWE numbers in *paths* (directory names like s01 keep no CWE)
_PATH_CWE_RE = re.compile(r'\bCWE\d+\b(?=[^:\s]*[/\\.])')


_HEX_TR = str.maketrans('abcdef', 'ghjkmn')   # keep hash tokens free of a-f so
                                              # they can never spell 'bad' etc.

def _tc_token(m: re.Match) -> str:
    return 'tc_' + hashlib.md5(m.group(0).encode()).hexdigest()[:8].translate(_HEX_TR)


def mask(text) -> str:
    """Remove everything that gives away Juliet's bad/good ground truth."""
    if not text:
        return text or ''
    text = _OMIT_RE.sub('OMITTED', text)
    text = _BADGOOD_RE.sub('x', text)          # bad and good -> the SAME token
    text = _TC_RE.sub(_tc_token, text)         # after bad/good removal, so the
    text = _PATH_CWE_RE.sub('CWEx', text)      # bad/good twins hash identically
    return text


# --------------------------------------------------------------------------- #
# Split assignment: stable hash of the test case id
# --------------------------------------------------------------------------- #


def split_of(testcase_id, seed: str, ratios) -> str:
    h = hashlib.md5(f'{seed}:{testcase_id}'.encode()).hexdigest()
    x = int(h[:8], 16) / 0xFFFFFFFF
    if x < ratios[0]:
        return 'train'
    if x < ratios[0] + ratios[1]:
        return 'val'
    return 'test'


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('--dataset', required=True, help='dataset.sqlite from a build_dataset.py')
    ap.add_argument('--tool', required=True, help='tool name stored in each record (cppcheck/codeql)')
    ap.add_argument('--table', default='code_trace')
    ap.add_argument('--outdir', default='splits')
    ap.add_argument('--seed', default='juliet-v1', help='salt for the stable test-case split')
    ap.add_argument('--ratios', default='0.8,0.1,0.1', help='train,val,test')
    ap.add_argument('--no-mask', action='store_true', help='skip masking (for ablation only)')
    args = ap.parse_args(argv)

    ratios = tuple(float(x) for x in args.ratios.split(','))
    assert abs(sum(ratios) - 1.0) < 1e-6, '--ratios must sum to 1'
    os.makedirs(args.outdir, exist_ok=True)

    conn = sqlite3.connect(args.dataset)
    conn.row_factory = sqlite3.Row
    cols = {r[1] for r in conn.execute(f'PRAGMA table_info({args.table})')}
    has_cwes = 'report_cwes' in cols          # codeql datasets have the multi-CWE column

    fhs = {s: open(os.path.join(args.outdir, f'{s}.jsonl'), 'w', encoding='utf-8')
           for s in ('train', 'val', 'test')}
    n = Counter()
    m = (lambda t: t) if args.no_mask else mask

    for row in conn.execute(f'SELECT * FROM {args.table}'):
        split = split_of(row['testcase_id'], args.seed, ratios)
        funcs = []
        for f in json.loads(row['functions'] or '[]'):
            funcs.append({'name': m(f['name'] or ''), 'kind': f['kind'],
                          'code': m(strip_comments(f['code']))})
        inp = {
            'checker_id': row['checker_id'],
            'severity': row['severity'],
            'report_cwe': row['report_cwe'],
            'msg': m(row['msg']),
            'trace': m(row['trace']),
            'bug_function': m(strip_comments(row['bug_function'] or '')),
            'functions': funcs,
        }
        if has_cwes:
            inp['report_cwes'] = row['report_cwes']
        rec = {
            'id': row['id'],
            'label': row['label'],
            'tool': args.tool,
            'input': inp,
            'meta': {                                  # ground truth, NOT model input
                'testcase_id': row['testcase_id'],
                'testcase_name': row['testcase_name'],
                'testcase_cwes': row['testcase_cwes'],
                'region': row['region'],
                'cwe_match': row['cwe_match'],
                'on_flaw_line': row['on_flaw_line'],
                'file': row['file'],
                'line': row['line'],
            },
        }
        fhs[split].write(json.dumps(rec, ensure_ascii=False) + '\n')
        n[split] += 1
        n[f'{split}_label_{row["label"]}'] += 1

    for fh in fhs.values():
        fh.close()
    conn.close()
    for s in ('train', 'val', 'test'):
        tot = n[s] or 1
        print(f'[{args.tool}] {s:5s}: {n[s]:7d} rows  '
              f'(TP {n[f"{s}_label_1"]:6d} = {100*n[f"{s}_label_1"]/tot:5.1f}%)')
    return 0


if __name__ == '__main__':
    sys.exit(main())
