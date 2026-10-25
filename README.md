# parse-nessus

An annotated Python script that reads a Nessus CSV export and summarises it:
which hosts were scanned, how many findings at each risk level, and the full
detail of every Critical.

Written for students learning Python through something they will actually do in
the job, rather than through a toy example. The code is deliberately plain and
heavily commented. Standard library only, no dependencies.

## Run it

```bash
git clone https://github.com/SilentPayload/parse-nessus.git
cd parse-nessus
python3 parse_nessus.py
```

A sample export is included, so that works immediately. To use your own scan,
export from Nessus as CSV and save it over `nessus_scan_results.csv`.

## What it prints

```
============================================================
       NESSUS SCAN REPORT ANALYZER
============================================================

[*] Loading file: nessus_scan_results.csv
[*] Total rows loaded: 20

[*] Hosts scanned (3 total):
    - 192.168.1.10
    - 192.168.1.20
    - 192.168.1.30

[*] Total vulnerabilities found: 9

[*] Vulnerability breakdown by risk level:
    Critical  : 3
    High      : 3
    Medium    : 3
    Low       : 0

[!] CRITICAL VULNERABILITIES (3 found) - FIX IMMEDIATELY:
------------------------------------------------------------
  Host      : 192.168.1.20
  Plugin    : Apache Bash Remote Code Execution (Shellshock)
  CVE       : CVE-2014-6271
  CVSS Score: 10.0
  Solution  : Update Bash to the latest version available from the OS vendor.
------------------------------------------------------------
  ...
```

Then a per host breakdown listing every finding against each address.

## How it is built

Six small functions, each doing one thing, in the order the data flows:

| Function | Job |
|---|---|
| `load_nessus_csv` | Read the CSV into a list of dictionaries, one per row |
| `get_vulnerabilities_only` | Drop informational rows where `Risk` is `None` or blank |
| `count_by_risk` | Tally findings per risk level |
| `get_all_hosts` | Unique list of scanned addresses |
| `get_vulns_for_host` | Every finding against one address |
| `get_critical_vulns` | Only the Criticals |

The reason informational rows are filtered separately is worth noticing. The
sample export has 20 rows but only 9 real findings. Over half of a Nessus
export is usually noise, and an analyst who reports the raw row count as the
number of vulnerabilities has made their first mistake.

## The sample data

`nessus_scan_results.csv` is synthetic, modelled on a real Nessus CSV export
with the standard columns: `Plugin ID`, `CVE`, `CVSS v2.0 Base Score`, `Risk`,
`Host`, `Protocol`, `Port`, `Name`, `Synopsis`, `Description`, `Solution`,
`See Also` and `Plugin Output`.

Three hosts on a private range, carrying well known vulnerabilities that
students will recognise later: Shellshock, EternalBlue and MS12-020. It did not
come from a real scan of a real network.

## Known limitations, and what to do about them

The script assumes the CSV sits in the same folder under a fixed name, and that
every column it reads is present. Real exports vary between Nessus versions,
and a missing column will stop it.

These are not oversights to apologise for, they are the next lesson. See
[exercises.md](exercises.md) for the set of extensions that fix each one,
ordered by difficulty.

## Licence

MIT. See [LICENSE](LICENSE).

## Author

Praise Abu Ugbede, [SilentPayload](https://github.com/SilentPayload).
Penetration tester and security educator, Abuja, Nigeria.

Related: [soc-analyst-exercises](https://github.com/SilentPayload/soc-analyst-exercises)
and [linux-networking-foundations](https://github.com/SilentPayload/linux-networking-foundations).
