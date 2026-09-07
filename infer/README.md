# Infer vs Juliet

Same experiment as [../cppcheck/](../cppcheck/) and [../codeql/](../codeql/),
but for **Facebook Infer** (v1.3.0). See the cppcheck README for the full story
of how labelling works — the rule is identical:

> a finding is a **true positive** only if it points into the *bad* code of a
> Juliet test case **and** its CWE matches the CWE NIST assigns to that case.

Infer reports its own bug types (`NULLPTR_DEREFERENCE`, `MEMORY_LEAK_C`, ...)
instead of CWEs, so `build_dataset.py` carries a built-in bug_type → CWE map
(`TYPE_CWES`, overridable with `--type-cwe-map`), e.g. `NULLPTR_DEREFERENCE`
→ CWE-476, `DEAD_STORE` → CWE-563. Quality findings with no meaningful CWE
(`PULSE_UNNECESSARY_COPY*`, `PULSE_CONST_REFABLE`) map to nothing and are
always false positives, like cppcheck findings without a CWE.

## How the report was produced

```bash
cd ../2017-10-01-juliet-test-suite-for-c-cplusplus-v1-3/C
find testcases testcasesupport -name '*.o' -delete
infer run --keep-going -j 16 -- make -k -j16 CC=gcc CPP=g++
cp infer-out/report.json ../../infer/report.json
```

(The `CC`/`CPP` overrides matter: Juliet's Makefiles hardcode `/usr/bin/gcc`,
which would bypass Infer's compiler interception.)

## Files

| File | Unpacked size | What it is |
|------|---------------|------------|
| `build_dataset.py` | — | report.json → labelled dataset. Reuses the machinery from `../cppcheck/build_dataset.py`. |
| `cwe_map.json` | — | Optional related-CWE equivalences (e.g. Infer's 416 vs Juliet's double-free 415). Off by default. |
| `report.json.gz` | 53 MB | Raw Infer output (46,471 issues) |
| `dataset.csv.gz` | 199 MB | The labelled dataset |
| `dataset.sqlite.gz` | 237 MB | Same data as SQLite (table `code_trace`) |
| `splits/*.jsonl.gz` | — | Fine-tuning splits (masked + per-test-case, built by `../make_splits.py`) |

Unpack with `gunzip -k <file>.gz`.

## Reproduce

```bash
cd infer
gunzip -k report.json.gz
python3 build_dataset.py --csv dataset.csv
python3 ../make_splits.py --dataset dataset.sqlite --tool infer --outdir splits
```

Same CLI flags as the cppcheck script (`--limit`, `--cwe-map`, `--ids`,
`--require-cwe`, ...), with `--report` instead of `--results`, plus
`--type-cwe-map` for the bug_type → CWE mapping. Like the codeql dataset,
there is an extra `report_cwes` column.

## Numbers from the last full run

- 46,471 issues → 46,470 rows (one issue fell outside `testcases/`)
- **1,622 true positives** and **44,848 false positives** (3.5% TP)
- splits: train 37,295 / val 4,575 / test 4,600 rows, TP rate 3.3–3.5% in each,
  zero test-case overlap, zero label-leak patterns in the masked inputs

Precision sits between cppcheck (1.6%) and CodeQL (61%): half of Infer's
volume is the `DEAD_STORE` quality checker (0.9% TP), while the memory
checkers do well (`MEMORY_LEAK_C` 13%, `USE_AFTER_DELETE` 21%).
`USE_AFTER_FREE` shows 0 TP only because Infer flags Juliet's *double-free*
(CWE-415) cases and the default policy demands an exact CWE match — run with
`--cwe-map cwe_map.json` to accept 416≈415 and similar siblings.
