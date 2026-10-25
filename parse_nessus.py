"""
Nessus Scan Log Parser
======================
This script reads a Nessus CSV export and helps us answer questions like:
  - Which hosts were scanned?
  - How many Critical, High, Medium vulnerabilities were found?
  - Which vulnerabilities are the most dangerous?

We use Python's built-in 'csv' module - no need to install anything.
"""

import csv  # csv module helps us read .csv files easily


# ---------------------------------------------------------------
# STEP 1: Load the CSV file into a list of dictionaries
# ---------------------------------------------------------------

def load_nessus_csv(filename):
    """
    Opens the CSV file and returns a list of rows.
    Each row becomes a dictionary where the key = column name.

    Example row:
    {
        'Risk': 'Critical',
        'Host': '192.168.1.30',
        'Name': 'MS17-010: EternalBlue ...',
        ...
    }
    """
    results = []

    with open(filename, newline='', encoding='utf-8') as csvfile:
        reader = csv.DictReader(csvfile)  # DictReader turns each row into a dict

        for row in reader:
            results.append(row)  # add each row to our list

    return results


# ---------------------------------------------------------------
# STEP 2: Filter out informational rows (Risk = 'None')
# We only want actual vulnerabilities
# ---------------------------------------------------------------

def get_vulnerabilities_only(scan_data):
    """Returns only rows that have an actual risk level (not 'None')."""
    vulns = []

    for row in scan_data:
        if row['Risk'] != 'None' and row['Risk'] != '':
            vulns.append(row)

    return vulns


# ---------------------------------------------------------------
# STEP 3: Count vulnerabilities by risk level
# ---------------------------------------------------------------

def count_by_risk(vulnerabilities):
    """
    Counts how many Critical, High, Medium, Low vulnerabilities exist.
    Returns a dictionary like: {'Critical': 3, 'High': 2, 'Medium': 4}
    """
    counts = {}  # empty dictionary to store our counts

    for vuln in vulnerabilities:
        risk = vuln['Risk']

        # If we've seen this risk level before, add 1
        # If not, start counting at 1
        if risk in counts:
            counts[risk] += 1
        else:
            counts[risk] = 1

    return counts


# ---------------------------------------------------------------
# STEP 4: Get unique list of hosts that were scanned
# ---------------------------------------------------------------

def get_all_hosts(scan_data):
    """Returns a list of unique IP addresses found in the scan."""
    hosts = []

    for row in scan_data:
        host = row['Host']
        if host not in hosts:   # only add if we haven't seen it
            hosts.append(host)

    return hosts


# ---------------------------------------------------------------
# STEP 5: Find all vulnerabilities for a specific host
# ---------------------------------------------------------------

def get_vulns_for_host(vulnerabilities, ip_address):
    """Returns all vulnerabilities found on a specific host/IP."""
    host_vulns = []

    for vuln in vulnerabilities:
        if vuln['Host'] == ip_address:
            host_vulns.append(vuln)

    return host_vulns


# ---------------------------------------------------------------
# STEP 6: Show all Critical vulnerabilities
# ---------------------------------------------------------------

def get_critical_vulns(vulnerabilities):
    """Returns only Critical vulnerabilities."""
    criticals = []

    for vuln in vulnerabilities:
        if vuln['Risk'] == 'Critical':
            criticals.append(vuln)

    return criticals


# ---------------------------------------------------------------
# MAIN PROGRAM - This runs when you execute the script
# ---------------------------------------------------------------

if __name__ == "__main__":

    filename = "nessus_scan_results.csv"   # make sure this file is in the same folder

    print("=" * 60)
    print("       NESSUS SCAN REPORT ANALYZER")
    print("=" * 60)

    # --- Load the data ---
    print(f"\n[*] Loading file: {filename}")
    scan_data = load_nessus_csv(filename)
    print(f"[*] Total rows loaded: {len(scan_data)}")

    # --- Show scanned hosts ---
    hosts = get_all_hosts(scan_data)
    print(f"\n[*] Hosts scanned ({len(hosts)} total):")
    for host in hosts:
        print(f"    - {host}")

    # --- Filter to vulnerabilities only ---
    vulnerabilities = get_vulnerabilities_only(scan_data)
    print(f"\n[*] Total vulnerabilities found: {len(vulnerabilities)}")

    # --- Count by risk level ---
    risk_counts = count_by_risk(vulnerabilities)
    print("\n[*] Vulnerability breakdown by risk level:")

    # Define display order (most dangerous first)
    risk_order = ['Critical', 'High', 'Medium', 'Low']
    for level in risk_order:
        count = risk_counts.get(level, 0)   # .get() returns 0 if level not found
        print(f"    {level:<10}: {count}")

    # --- Show Critical vulnerabilities ---
    criticals = get_critical_vulns(vulnerabilities)
    print(f"\n[!] CRITICAL VULNERABILITIES ({len(criticals)} found) - FIX IMMEDIATELY:")
    print("-" * 60)
    for vuln in criticals:
        print(f"  Host      : {vuln['Host']}")
        print(f"  Plugin    : {vuln['Name']}")
        print(f"  CVE       : {vuln['CVE']}")
        print(f"  CVSS Score: {vuln['CVSS v2.0 Base Score']}")
        print(f"  Solution  : {vuln['Solution']}")
        print("-" * 60)

    # --- Per-host breakdown ---
    print("\n[*] Per-host vulnerability summary:")
    for host in hosts:
        host_vulns = get_vulns_for_host(vulnerabilities, host)
        if host_vulns:
            print(f"\n  Host: {host} ({len(host_vulns)} vulnerabilities)")
            for v in host_vulns:
                print(f"    [{v['Risk']:<8}] {v['Name']}")
        else:
            print(f"\n  Host: {host} - No vulnerabilities found")

    print("\n[*] Analysis complete.")
