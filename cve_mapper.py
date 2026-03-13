CVE_DATABASE = {

    "SQL Injection": {
        "cve": "CVE-2019-1234",
        "remedy": "Use parameterized queries"
    },

    "Reflected XSS": {
        "cve": "CVE-2018-7600",
        "remedy": "Sanitize user input"
    },

    "Directory Traversal": {
        "cve": "CVE-2021-41773",
        "remedy": "Restrict file access paths"
    },

    "Open Redirect": {
        "cve": "CVE-2020-11022",
        "remedy": "Validate redirect URLs"
    }

}

def map_vulnerabilities(findings):
    for f in findings:
        vuln = CVE_DATABASE.get(f["type"])

        if vuln:
            f["cve"] = vuln["cve"]
            f["remedy"] = vuln["remedy"]

    return findings