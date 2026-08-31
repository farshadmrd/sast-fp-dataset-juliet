# CodeQL vs Juliet

Same experiment as [../cppcheck/](../cppcheck/), but for **CodeQL** (2.26.4,
`cpp-security-and-quality` style queries). See the cppcheck README for the full
story of how labelling works — the rule is identical:

> a finding is a **true positive** only if it points into the *bad* code of a
> Juliet test case **and** one of the CWEs tagged on the CodeQL rule matches
> the CWE NIST assigns to that case.

## Files

| File | Unpacked size | What it is |
|------|---------------|------------|
| `build_dataset.py` | — | SARIF → labelled dataset. Reuses the parsing/labelling machinery from `../cppcheck/build_dataset.py`. |
| `codeql.sarif.gz` | 74 MB | Raw CodeQL output (SARIF 2.1.0) |
| `dataset.csv.gz` | 56 MB | The labelled dataset |
| `dataset.sqlite.gz` | 68 MB | Same data as SQLite (table `code_trace`) |

Unpack with `gunzip -k <file>.gz`.

## Reproduce

```bash
cd codeql
gunzip -k codeql.sarif.gz
python3 build_dataset.py --csv dataset.csv
```

The Juliet suite is auto-detected in the repository root (or pass
`--juliet ../<folder>`). Same CLI flags as the cppcheck script
(`--limit`, `--cwe-map`, `--ids`, `--require-cwe`, ...), with `--sarif`
instead of `--results`. One extra column: `report_cwes` — a CodeQL rule can
carry several CWEs (e.g. `120;787;805`); `cwe_match` checks all of them.

## Fine-tuning splits

`splits/{train,val,test}.jsonl.gz` — same masking + per-test-case split as the
cppcheck ones (see [../cppcheck/README.md](../cppcheck/README.md) and
`../make_splits.py`). Rebuild with:

```bash
python3 ../make_splits.py --dataset dataset.sqlite --tool codeql --outdir splits
```

## Numbers from the last full run

- 13,454 findings → 13,454 rows (every finding resolved to a test case)
- **8,240 true positives** and **5,214 false positives**

CodeQL is far more precise on Juliet than cppcheck (61% TP vs 1.6%), largely
because it only ships security queries with CWE tags, while cppcheck also
reports thousands of style findings.
