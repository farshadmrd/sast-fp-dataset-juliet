# SAST False-Positive Dataset (Juliet + cppcheck)

A small, self-contained project that turns the output of a static analysis tool
(**cppcheck**) into a labelled dataset: for every warning cppcheck raised, we say
whether it was a **real bug** (true positive, `label = 1`) or **noise** (false
positive, `label = 0`).

The ground truth comes from the [NIST Juliet Test Suite for C/C++ v1.3](https://samate.nist.gov/SARD/test-suites/112),
which contains ~64,000 tiny programs that each have a known, documented flaw.

## Why?

Static analysers report a lot of warnings, and many of them are wrong. Having a
large dataset of "this warning was right / this one was wrong" makes it possible
to study, and train models to reduce, false positives. This repo is part of a
DevSecOps master's thesis on exactly that.

## How labelling works (in plain words)

Every Juliet test case has two versions of the same code:

- a **bad** part that contains the flaw, and
- a **good** part where the flaw has been fixed.

The manifest that ships with Juliet also tells us *which CWE* (bug category)
each test case is about.

A cppcheck warning is labelled a **true positive** only if **both** are true:

1. it points into the *bad* part of a test case, **and**
2. the CWE cppcheck reports is the same CWE that Juliet assigns to that case.

Everything else (warning in the good code, a different CWE, no CWE at all) is a
**false positive**.

All the intermediate facts (which region the warning is in, whether the CWE
matched, how far it is from the documented flaw line, ...) are stored as extra
columns, so you can re-label under a different policy without re-running cppcheck.

## Layout

```
.
├── 2017-10-01-juliet-test-suite-for-c-cplusplus-v1-3/   # Juliet suite (not committed)
├── .gitignore
└── cppcheck/            # everything for the cppcheck experiment
    ├── README.md        # this file
    ├── build_dataset.py
    ├── cwe_map.json
    ├── results.xml.gz
    ├── dataset.csv.gz
    └── dataset.sqlite.gz
```

## What's in `cppcheck/`

| File | Purpose |
|------|---------|
| `build_dataset.py` | The whole pipeline. Python 3 standard library only, no dependencies. |
| `cwe_map.json` | Optional: treat some closely related CWEs as a match (e.g. cppcheck's CWE-788 vs Juliet's CWE-121/122/126). |
| `.gitignore` | Keeps the big inputs/outputs out of git (see below). |

The dataset and the raw cppcheck output **are** included, gzipped so they fit
GitHub's file-size limit:

| File | Unpacked size | What it is |
|------|---------------|------------|
| `dataset.csv.gz` (28 MB) | 723 MB | The dataset, one row per cppcheck finding |
| `dataset.sqlite.gz` (39 MB) | 939 MB | Same data as a SQLite DB (table `code_trace`) |
| `results.xml.gz` (6 MB) | 245 MB | Raw cppcheck output the dataset was built from |

Unpack whichever you need:

```bash
gunzip -k dataset.csv.gz            # -k keeps the .gz
gunzip -k dataset.sqlite.gz
gunzip -k results.xml.gz
```

Only the Juliet suite itself (~150 MB zip, ~1 GB extracted) is not committed;
download it from NIST if you want to rebuild from scratch.

## Reproducing the dataset

1. **Get Juliet** and unzip it in the repository root:

   ```bash
   # download from https://samate.nist.gov/SARD/test-suites/112
   unzip 2017-10-01-juliet-test-suite-for-c-cplusplus-v1-3.zip
   cd cppcheck
   ```

2. **Run cppcheck** over the suite and keep the XML output:

   ```bash
   cppcheck --enable=all --xml --xml-version=2 \
       ../2017-10-01-juliet-test-suite-for-c-cplusplus-v1-3/C/testcases \
       2> results.xml
   ```

3. **Build the dataset** (from inside `cppcheck/`; the Juliet folder in the
   parent directory is found automatically, or pass `--juliet ../<folder>`):

   ```bash
   python3 build_dataset.py --csv dataset.csv
   ```

   That produces `dataset.sqlite` (table `code_trace`) and `dataset.csv`
   (the committed `.gz` files are just these, gzipped).
   On a normal laptop it takes under a minute.

Useful options:

```bash
python3 build_dataset.py --validate           # sanity-check the parser against the manifest
python3 build_dataset.py --limit 2000         # quick smoke test
python3 build_dataset.py --cwe-map cwe_map.json   # accept related CWEs as matches
python3 build_dataset.py --require-cwe        # drop warnings with no CWE
python3 build_dataset.py --ids nullPointer,memleak   # keep only some checkers
python3 build_dataset.py --url-base https://github.com/<user>/<repo>/blob/main/C/
```

Run `python3 build_dataset.py --help` for the full list.

## Dataset columns (the important ones)

| Column | Meaning |
|--------|---------|
| `label` | `1` = true positive, `0` = false positive |
| `trace` | The code path cppcheck reported, as text |
| `bug_function` | Source of the function containing the warning |
| `functions` | JSON list of all functions touched by the trace |
| `bug_url` | Link to the exact file and line |
| `checker_id`, `severity`, `report_cwe`, `msg` | What cppcheck said |
| `file`, `line`, `column` | Where it said it |
| `testcase_id`, `testcase_name`, `testcase_cwes` | Which Juliet case this belongs to and its CWE(s) |
| `region` | `bad`, `good`, or `other` |
| `cwe_match`, `on_flaw_line`, `flaw_line_dist` | Building blocks of the label, kept for re-labelling |

## Numbers from the last full run

- 415,861 cppcheck findings read → 215,994 rows kept
  (findings outside the chosen severities are dropped)
- **3,454 true positives** and **212,540 false positives**

Yes, that is heavily imbalanced — that is the point of the dataset.
Some checkers are almost always right (`mismatchAllocDealloc`,
`autovarInvalidDeallocation`), some are almost always noise
(`cstyleCast`, `variableScope`, `shadowVariable`).

## License / credits

The Juliet Test Suite is public domain, published by NIST.
cppcheck is GPL-3.0. The code in this repo is written for the thesis; use it freely.
