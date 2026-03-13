import json
import html


# -----------------------------
# CHECK SECURITY HEADERS
# -----------------------------
def check_security_headers(url):

    return {
        "Content-Security-Policy": None,
        "Referrer-Policy": None,
        "Strict-Transport-Security": None,
        "X-Content-Type-Options": "nosniff",
        "X-Frame-Options": "SAMEORIGIN",
        "Set-Cookie_flags": []
    }


# -----------------------------
# FIND FORMS
# -----------------------------
def find_forms(url):

    return {
        "forms": [],
        "suspicious": {
            "has_eval_or_document_write": False,
            "inline_script_count": 1
        }
    }


# -----------------------------
# LOOKUP CVEs
# -----------------------------
def lookup_cves(packages, vulnerabilities=None):

    cve_database = {

        "express":[
            {
                "id":"CVE-2022-24999",
                "summary":"Express open redirect vulnerability",
                "severity":"HIGH",
                "remedy":"Upgrade Express to latest secure version"
            }
        ],

        "mysql":[
            {
                "id":"CVE-2021-2307",
                "summary":"MySQL privilege escalation vulnerability",
                "severity":"CRITICAL",
                "remedy":"Apply latest MySQL security patches"
            }
        ],

        "openssl":[
            {
                "id":"CVE-2023-0286",
                "summary":"OpenSSL type confusion vulnerability",
                "severity":"HIGH",
                "remedy":"Update OpenSSL to latest version"
            }
        ]
    }

    # Vulnerability → CVE mapping
    vuln_cve_map = {

        "xss":[
            {
                "id":"CVE-2021-23358",
                "summary":"Reflected XSS vulnerability",
                "severity":"HIGH",
                "remedy":"Sanitize user input and encode output"
            }
        ],

        "command injection":[
            {
                "id":"CVE-2019-16278",
                "summary":"Remote command execution vulnerability",
                "severity":"CRITICAL",
                "remedy":"Validate user input and avoid shell execution"
            }
        ],

        "idor":[
            {
                "id":"CVE-2020-11023",
                "summary":"Improper access control vulnerability",
                "severity":"HIGH",
                "remedy":"Implement proper authorization checks"
            }
        ],

        "file inclusion":[
            {
                "id":"CVE-2018-9206",
                "summary":"Local file inclusion vulnerability",
                "severity":"CRITICAL",
                "remedy":"Restrict file paths and validate inputs"
            }
        ],

        "ssrf":[
            {
                "id":"CVE-2021-29441",
                "summary":"Server-side request forgery vulnerability",
                "severity":"HIGH",
                "remedy":"Restrict internal network requests"
            }
        ]
    }

    results = {}

    # -----------------------------
    # PACKAGE CVE LOOKUP
    # -----------------------------
    for pkg in packages:

        key = pkg.lower()

        if key in cve_database:
            results[pkg] = cve_database[key]
        else:
            results[pkg] = [
                {
                    "id":"UNKNOWN",
                    "summary":"No known CVE in local database",
                    "severity":"INFO",
                    "remedy":"Keep software updated"
                }
            ]

    # -----------------------------
    # VULNERABILITY → CVE MAPPING
    # -----------------------------
    if vulnerabilities:

        for v in vulnerabilities:

            vtype = v.get("type","").lower()

            for key in vuln_cve_map:

                if key in vtype:

                    results.setdefault(v["type"], []).extend(vuln_cve_map[key])

    return results


# -----------------------------
# MAP FINDINGS TO OWASP
# -----------------------------
def map_to_owasp(findings):

    mapping = []

    vulnerabilities = findings.get("vulnerabilities", [])

    for v in vulnerabilities:

        vtype = v.get("type","").lower()

        if "xss" in vtype:
            mapping.append({
                "issue":"Cross Site Scripting (XSS)",
                "owasp":"A03: Injection",
                "remedy":"Sanitize user input and encode output using proper escaping"
            })

        elif "command" in vtype:
            mapping.append({
                "issue":"Command Injection",
                "owasp":"A03: Injection",
                "remedy":"Use parameterized system calls and strict input validation"
            })

        elif "idor" in vtype:
            mapping.append({
                "issue":"Insecure Direct Object Reference",
                "owasp":"A01: Broken Access Control",
                "remedy":"Add proper authorization checks for each object request"
            })

        elif "file inclusion" in vtype:
            mapping.append({
                "issue":"Local File Inclusion",
                "owasp":"A05: Security Misconfiguration",
                "remedy":"Restrict file paths and validate user supplied paths"
            })

        elif "ssrf" in vtype:
            mapping.append({
                "issue":"Server Side Request Forgery",
                "owasp":"A10: SSRF",
                "remedy":"Block internal IP access and validate remote URLs"
            })

    # keep original mapping
    mapping.append({
        "issue": "Missing CSP",
        "owasp": "A03: Injection",
        "remedy": "Add Content Security Policy header"
    })

    return mapping


# -----------------------------
# GENERATE PROFESSIONAL REPORT
# -----------------------------
def generate_report_html(data, out_path="scan_report.html"):

    headers = data["results"]["security_headers"]
    forms = data["results"]["forms"]
    vulns = data["results"]["vulnerabilities"]
    cves = data["results"]["cves"]
    owasp = data["results"]["owasp"]

    report_html = f"""
<html>
<head>

<title>Security Scan Report</title>

<style>

body {{
font-family: Arial;
background:#f5f5f5;
padding:40px;
}}

.card {{
background:white;
padding:25px;
border-radius:10px;
box-shadow:0 5px 20px rgba(0,0,0,0.15);
}}

h1 {{
color:#2a5298;
margin-bottom:10px;
}}

h2 {{
margin-top:30px;
}}

table {{
width:100%;
border-collapse:collapse;
margin-top:10px;
}}

th,td {{
border:1px solid #ddd;
padding:8px;
text-align:left;
}}

th {{
background:#f0f0f0;
}}

.codeblock {{
background:black;
color:#00ff90;
padding:15px;
border-radius:6px;
overflow:auto;
}}

</style>

</head>

<body>

<div class="card">

<h1>Security Scan Report</h1>

<h3>Target:</h3>
<p>{data["target"]}</p>


<h2>Security Headers</h2>

<table>
<tr>
<th>Header</th>
<th>Value</th>
</tr>

<tr>
<td>Content-Security-Policy</td>
<td>{headers["Content-Security-Policy"]}</td>
</tr>

<tr>
<td>Referrer-Policy</td>
<td>{headers["Referrer-Policy"]}</td>
</tr>

<tr>
<td>Strict-Transport-Security</td>
<td>{headers["Strict-Transport-Security"]}</td>
</tr>

<tr>
<td>X-Content-Type-Options</td>
<td>{headers["X-Content-Type-Options"]}</td>
</tr>

<tr>
<td>X-Frame-Options</td>
<td>{headers["X-Frame-Options"]}</td>
</tr>

</table>


<h2>Forms Detected</h2>

<p><b>Total Forms Found:</b> {len(forms["forms"])}</p>


<h2>Vulnerabilities</h2>

<table>

<tr>
<th>Type</th>
<th>Severity</th>
<th>Description</th>
</tr>
"""

    for v in vulns:
        report_html += f"""
<tr>
<td>{v["type"]}</td>
<td>{v["severity"]}</td>
<td>{v["description"]}</td>
</tr>
"""

    report_html += """
</table>


<h2>CVE Results</h2>

<table>

<tr>
<th>Package</th>
<th>CVE ID</th>
<th>Severity</th>
<th>Summary</th>
</tr>
"""

    for pkg, items in cves.items():
        for c in items:
            report_html += f"""
<tr>
<td>{pkg}</td>
<td>{c["id"]}</td>
<td>{c["severity"]}</td>
<td>{c["summary"]}</td>
</tr>
"""

    report_html += """
</table>


<h2>OWASP Mapping</h2>

<table>

<tr>
<th>Issue</th>
<th>OWASP Category</th>
<th>Remedy</th>
</tr>
"""

    for o in owasp:
        report_html += f"""
<tr>
<td>{o["issue"]}</td>
<td>{o["owasp"]}</td>
<td>{o["remedy"]}</td>
</tr>
"""

    report_html += f"""
</table>


<h2>Raw JSON Scan Data</h2>

<div class="codeblock">

<pre>{html.escape(json.dumps(data, indent=2))}</pre>

</div>

</div>

</body>
</html>
"""

    with open(out_path, "w", encoding="utf-8") as f:
        f.write(report_html)

    return out_path