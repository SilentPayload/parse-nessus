# Extending the parser

The script as written does one job on one file. Each exercise below removes one
of its limitations. They are ordered so that each builds on the last.

Work on a copy. Keep the original so you can compare.

---

## 1. Take the filename as an argument

Right now the filename is fixed in the code:

```python
filename = "nessus_scan_results.csv"
```

Change it so the file can be given on the command line:

```bash
python3 parse_nessus.py my_scan.csv
```

Start with `sys.argv`. Once that works, switch to `argparse` and add a `--help`
message. Keep the current filename as the default so running it with no
arguments still works.

**Check:** does it still run with no arguments? Does it give a useful message
when the file does not exist, rather than a traceback?

---

## 2. Survive a missing column

`get_vulnerabilities_only` reads `row['Risk']` directly. If an export has no
`Risk` column, the script stops with a `KeyError`.

Change the lookups so a missing column produces a blank or a sensible default
instead of a crash. `dict.get()` is the tool.

**Check:** delete the `Solution` column from a copy of the CSV and run it. The
Criticals should still print, with the solution shown as unknown.

---

## 3. Sort the Criticals by CVSS score

The Criticals print in the order they appear in the file. Print them worst
first instead.

The score arrives as text, so `"10.0"` and `"9.3"` will not compare correctly
until you convert them. Watch for rows with a blank score.

**Check:** Shellshock at 10.0 should come before the two 9.3 findings.

---

## 4. Count findings per host, ranked

The per host summary lists findings in file order. Add a ranking: which host
carries the most findings, and how many.

You already wrote the pieces in the log analysis worksheet. This is
`sort | uniq -c | sort -rn` in Python.

**Check:** the host totals should add up to the overall count.

---

## 5. Write the summary to a file

Add an option to write the report to a file instead of the screen:

```bash
python3 parse_nessus.py scan.csv --output report.txt
```

**Check:** the file should contain exactly what the screen showed.

---

## 6. Export the findings as CSV

Produce a cleaned CSV containing only the real findings, with just the columns
that matter for a report: host, risk, CVE, score and name.

This is the version you would hand to someone who has to do something about the
findings. The `csv` module writes as well as it reads, with `csv.DictWriter`.

**Check:** open the output in a spreadsheet. One row per finding, no
informational rows, no description blobs.

---

## 7. Compare two scans

Given last month's export and this month's, report what changed: findings that
are new, findings that are gone, and findings still present in both.

This is the hardest one and the most useful in real work. Nobody cares much
about a single scan. They care whether the numbers are moving in the right
direction.

Think about what makes a finding "the same" across two scans. Plugin ID plus
host is a reasonable start. Is it enough?

**Check:** run it against two copies of the same file. It should report
everything as unchanged and nothing as new.
