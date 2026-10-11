#!/usr/bin/env python3
"""
Nmap Parse Report
Convert Nmap XML output into a standalone HTML security report.

Usage:
    ./nmap_parse.py nmap_out.xml
    ./nmap_parse.py nmap_out.xml -o report.html
    ./nmap_parse.py nmap_out.xml report.html
"""

import argparse
import html
import re
import sys
import xml.etree.ElementTree as ET
from datetime import datetime
from pathlib import Path

VERSION = "1.2.0"

CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.I)
VULN_RE = re.compile(r"\b(?:VULNERABLE|IS VULNERABLE|vulnerable:)\b", re.I)
CVSS_RE = re.compile(r"\bCVSS(?:\s*(?:v\d(?:\.\d)?))?\s*[:=]?\s*(\d+(?:\.\d)?)\b", re.I)

SEVERITY_ORDER = {
    "critical": 4,
    "high": 3,
    "medium": 2,
    "low": 1,
    "info": 0,
}

SEVERITY_CLASS = {
    "critical": "critical",
    "high": "high",
    "medium": "medium",
    "low": "low",
    "info": "info",
}


def esc(value):
    return html.escape(str(value or "-"), quote=True)


def unique(items):
    seen = set()
    result = []
    for item in items:
        if item and item not in seen:
            seen.add(item)
            result.append(item)
    return result


def extract_cves(text):
    return unique([m.upper() for m in CVE_RE.findall(text or "")])


def extract_cvss(text):
    match = CVSS_RE.search(text or "")
    return match.group(1) if match else None


def severity_from_text(text, cvss=None):
    text = (text or "").lower()

    for level in ("critical", "high", "medium", "low"):
        if re.search(rf"\b{level}\b", text):
            return level

    if cvss is not None:
        try:
            score = float(cvss)
            if score >= 9.0:
                return "critical"
            if score >= 7.0:
                return "high"
            if score >= 4.0:
                return "medium"
            if score > 0:
                return "low"
        except ValueError:
            pass

    return "info"


def flatten_xml(node):
    parts = []
    if node.text and node.text.strip():
        parts.append(node.text.strip())

    for child in list(node):
        if child.text and child.text.strip():
            parts.append(child.text.strip())
        parts.extend(flatten_xml(child))
        if child.tail and child.tail.strip():
            parts.append(child.tail.strip())

    return "\n".join(unique(parts))


def parse_script(script, port, protocol):
    sid = script.get("id", "unknown")
    output = script.get("output", "").strip()

    if not output:
        output = flatten_xml(script).strip()

    cves = extract_cves(output)
    cvss = extract_cvss(output)
    vulnerable = bool(VULN_RE.search(output))
    severity = severity_from_text(output, cvss)

    return {
        "id": sid,
        "port": port,
        "protocol": protocol,
        "output": output,
        "cves": cves,
        "cvss": cvss,
        "vulnerable": vulnerable,
        "severity": severity,
    }


def parse_host(host):
    addresses = host.findall("address")
    ipv4 = next((a.get("addr") for a in addresses if a.get("addrtype") == "ipv4"), "")
    ipv6 = next((a.get("addr") for a in addresses if a.get("addrtype") == "ipv6"), "")
    mac = next((a.get("addr") for a in addresses if a.get("addrtype") == "mac"), "")

    address = ipv4 or ipv6 or mac or "unknown"

    hostname = ""
    hostnames = host.find("hostnames")
    if hostnames is not None:
        hn = hostnames.find("hostname")
        if hn is not None:
            hostname = hn.get("name", "")

    status = host.find("status")
    state = status.get("state", "unknown") if status is not None else "unknown"

    os_name = ""
    osmatch = host.find("./os/osmatch")
    if osmatch is not None:
        os_name = osmatch.get("name", "")

    ports = []
    scripts = []
    findings = []
    references = []

    ports_node = host.find("ports")
    if ports_node is not None:
        for port in ports_node.findall("port"):
            portid = port.get("portid", "")
            protocol = port.get("protocol", "")

            state_node = port.find("state")
            port_state = state_node.get("state", "") if state_node is not None else ""

            service_node = port.find("service")
            service = product = version = extrainfo = ""
            cpes = []

            if service_node is not None:
                service = service_node.get("name", "")
                product = service_node.get("product", "")
                version = service_node.get("version", "")
                extrainfo = service_node.get("extrainfo", "")
                cpes = [c.text.strip() for c in service_node.findall("cpe") if c.text]

            port_data = {
                "port": portid,
                "protocol": protocol,
                "state": port_state,
                "service": service,
                "product": product,
                "version": version,
                "extrainfo": extrainfo,
                "cpe": ", ".join(unique(cpes)),
            }
            ports.append(port_data)

            for script in port.findall("script"):
                parsed = parse_script(script, portid, protocol)
                scripts.append(parsed)

                if parsed["vulnerable"]:
                    findings.append(parsed)
                elif parsed["cves"]:
                    references.append(parsed)

    return {
        "address": address,
        "hostname": hostname,
        "state": state,
        "os": os_name,
        "mac": mac,
        "ports": ports,
        "scripts": scripts,
        "findings": findings,
        "references": references,
    }


def parse_nmap_xml(path):
    try:
        tree = ET.parse(path)
    except ET.ParseError as exc:
        raise SystemExit(f"[!] Invalid Nmap XML: {exc}")
    except OSError as exc:
        raise SystemExit(f"[!] Cannot read XML: {exc}")

    root = tree.getroot()
    hosts = [parse_host(host) for host in root.findall("host")]

    scanner = root.get("scanner", "nmap")
    version = root.get("version", "")
    args = root.get("args", "")

    start = root.get("start", "")
    start_time = ""
    if start:
        try:
            start_time = datetime.fromtimestamp(int(start)).strftime("%Y-%m-%d %H:%M:%S")
        except (ValueError, OSError, OverflowError):
            pass

    return {
        "hosts": hosts,
        "scanner": scanner,
        "version": version,
        "args": args,
        "start_time": start_time,
        "source": str(path),
    }


def severity_badge(severity):
    severity = severity.lower()
    label = severity.upper()
    icon = {
        "critical": "🔴",
        "high": "🟠",
        "medium": "🟡",
        "low": "🔵",
        "info": "ℹ️",
    }.get(severity, "ℹ️")
    return f"{icon} {esc(label)}"


def port_rows(host):
    rows = []
    for p in host["ports"]:
        rows.append(
            "<tr>"
            f"<td class='port'>{esc(p['port'])}</td>"
            f"<td>{esc(p['protocol'])}</td>"
            f"<td>{esc(p['state'])}</td>"
            f"<td>{esc(p['service'])}</td>"
            f"<td>{esc(p['product'])}</td>"
            f"<td>{esc(p['version'])}</td>"
            f"<td>{esc(p['extrainfo'])}</td>"
            f"<td>{esc(p['cpe'])}</td>"
            "</tr>"
        )

    if not rows:
        rows.append("<tr><td colspan='8' class='muted'>No ports found.</td></tr>")

    return "".join(rows)


def findings_html(host):
    if not host["findings"]:
        return "<div class='muted'>No vulnerability findings detected by NSE.</div>"

    blocks = []
    for finding in sorted(
        host["findings"],
        key=lambda x: SEVERITY_ORDER.get(x["severity"], 0),
        reverse=True,
    ):
        cves = "".join(
            f"<span class='cve'>{esc(cve)}</span>" for cve in finding["cves"]
        )
        cvss = (
            f"<span class='cve'>CVSS {esc(finding['cvss'])}</span>"
            if finding["cvss"]
            else ""
        )

        evidence = esc(finding["output"] or "No NSE evidence output.")

        blocks.append(
            "<div class='finding "
            + esc(SEVERITY_CLASS.get(finding["severity"], "info"))
            + "'>"
            f"<h3>{severity_badge(finding['severity'])} · VULNERABLE · {esc(finding['id'])}</h3>"
            f"<div class='muted'>Port: {esc(finding['port'])}/{esc(finding['protocol'])} · "
            "Source: Nmap NSE · Status: Confirmed by NSE check</div>"
            f"{cves}{cvss}"
            f"<div class='evidence'>{evidence}</div>"
            "</div>"
        )

    return "".join(blocks)


def references_html(host):
    if not host["references"]:
        return "<div class='muted'>No additional CVE references/correlation found.</div>"

    blocks = []
    for ref in host["references"]:
        cves = "".join(
            f"<span class='cve'>{esc(cve)}</span>" for cve in ref["cves"]
        )
        blocks.append(
            "<div class='ref'>"
            "<b class='potential'>⚠ POTENTIAL / REFERENCED</b>"
            f" · {esc(ref['id'])} · {esc(ref['port'])}/{esc(ref['protocol'])}<br>"
            f"{cves}"
            "<div class='muted'>Software/version correlation; "
            "not automatically labeled as confirmed vulnerable.</div>"
            "</div>"
        )

    return "".join(blocks)


def scripts_html(host):
    if not host["scripts"]:
        return "<div class='muted'>No NSE script results.</div>"

    blocks = []
    for script in host["scripts"]:
        output = esc(script["output"] or "-")
        blocks.append(
            "<details class='script'>"
            f"<summary><b>{esc(script['id'])}</b> · "
            f"{esc(script['port'])}/{esc(script['protocol'])}</summary>"
            f"<div class='evidence'>{output}</div>"
            "</details>"
        )

    return "".join(blocks)


def host_html(host):
    finding_count = len(host["findings"])
    host_class = "finding" if finding_count else "clean"

    finding_badge = (
        f"<span class='badge red'>{finding_count} FINDINGS</span>"
        if finding_count
        else "<span class='badge up'>0 FINDINGS</span>"
    )

    subtitle = " · ".join(
        x for x in (host["hostname"], host["os"]) if x
    ) or "Host"

    return f"""
<section class='host' data-f='{host_class}'>
  <div class='head'>
    <div>
      <div class='ip'>{esc(host['address'])}</div>
      <div class='muted'>{esc(subtitle)}</div>
    </div>
    <div>
      <span class='badge up'>{esc(host['state']).upper()}</span>
      {finding_badge}
    </div>
  </div>

  <div class='section'>
    <div class='title'>OPEN PORTS</div>
    <div class='table'>
      <table>
        <tr>
          <th>Port</th><th>Protocol</th><th>State</th><th>Service</th>
          <th>Product</th><th>Version</th><th>Extra Info</th><th>CPE</th>
        </tr>
        {port_rows(host)}
      </table>
    </div>

    <div class='title section-gap'>VULNERABILITY FINDINGS</div>
    {findings_html(host)}

    <div class='title section-gap'>CVE REFERENCES / CORRELATION</div>
    {references_html(host)}

    <div class='title section-gap'>NSE / SCRIPT RESULTS</div>
    {scripts_html(host)}
  </div>
</section>
"""


def build_report(data):
    hosts = data["hosts"]
    hosts_up = sum(1 for h in hosts if h["state"] == "up")
    open_ports = sum(
        1 for h in hosts for p in h["ports"] if p["state"] == "open"
    )
    findings = sum(len(h["findings"]) for h in hosts)
    affected_hosts = sum(1 for h in hosts if h["findings"])

    all_cves = []
    for host in hosts:
        for item in host["findings"] + host["references"]:
            all_cves.extend(item["cves"])
    unique_cves = unique(all_cves)

    critical = sum(
        1 for h in hosts
        for f in h["findings"]
        if f["severity"] == "critical"
    )

    generated = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    host_sections = "\n".join(host_html(host) for host in hosts)

    return f"""<!doctype html>
<html>
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Nmap Security Report</title>
<style>
*{{box-sizing:border-box}}
body{{margin:0;background:#0b1120;color:#e5e7eb;font-family:system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif}}
.c{{max-width:1400px;margin:auto;padding:30px}}
h1{{margin:0 0 4px;font-size:30px}}
.muted{{color:#94a3b8;font-size:13px}}
.stats{{display:grid;grid-template-columns:repeat(6,1fr);gap:12px;margin:22px 0}}
.stat,.host{{background:#111827;border:1px solid #263449;border-radius:12px}}
.stat{{padding:16px}}
.num{{font-size:27px;font-weight:800}}
.label{{color:#94a3b8;font-size:12px}}
.toolbar{{display:flex;gap:10px;margin-bottom:20px}}
input,select{{background:#0f172a;color:#e5e7eb;border:1px solid #263449;border-radius:9px;padding:12px}}
input{{flex:1}}
.host{{margin-bottom:22px;overflow:hidden}}
.head{{padding:18px 20px;border-bottom:1px solid #263449;display:flex;justify-content:space-between;align-items:center}}
.ip{{font-size:20px;font-weight:800}}
.section{{padding:20px}}
.title{{font-size:12px;font-weight:800;color:#cbd5e1;margin:0 0 12px;letter-spacing:.04em}}
.section-gap{{margin-top:25px}}
.table{{overflow:auto}}
table{{width:100%;border-collapse:collapse;min-width:850px}}
th,td{{text-align:left;padding:11px 10px;border-bottom:1px solid #263449;font-size:13px}}
th{{color:#94a3b8;font-size:10px;text-transform:uppercase}}
.port{{color:#60a5fa;font-weight:800}}
.badge{{display:inline-block;padding:5px 9px;border-radius:99px;font-size:10px;font-weight:800}}
.up{{background:#063b2d;color:#34d399}}
.red{{background:#4a1717;color:#f87171}}
.potential{{color:#fbbf24}}
.finding{{border:1px solid #633034;background:#1b1115;border-radius:10px;padding:15px;margin:10px 0}}
.finding.high{{border-color:#7c4a20}}
.finding.medium{{border-color:#725d1e}}
.finding.low{{border-color:#244d70}}
.finding h3{{margin:0 0 6px;font-size:14px;color:#f87171}}
.finding.high h3{{color:#fb923c}}
.finding.medium h3{{color:#fbbf24}}
.finding.low h3{{color:#60a5fa}}
.cve{{display:inline-block;background:#32191d;color:#fca5a5;padding:4px 7px;border-radius:5px;font:12px monospace;margin:7px 5px 0 0}}
.evidence{{background:#0a0f1a;padding:12px;border-radius:7px;margin-top:10px;color:#cbd5e1;font:12px monospace;white-space:pre-wrap;overflow:auto}}
.ref,.script{{background:#0f172a;border:1px solid #263449;border-radius:9px;padding:13px;margin:9px 0}}
.script summary{{cursor:pointer}}
.footer{{text-align:center;color:#94a3b8;font-size:12px;padding:20px}}
.generated{{font-size:14px;color:#cbd5e1;margin-top:10px;font-weight:600}}
@media(max-width:1100px){{.stats{{grid-template-columns:repeat(3,1fr)}}}}
@media(max-width:700px){{
  .stats{{grid-template-columns:repeat(2,1fr)}}
  .head{{display:block}}
  .head>div:last-child{{margin-top:10px}}
  .toolbar{{display:block}}
  input,select{{width:100%;margin-bottom:8px}}
}}
</style>
</head>
<body>
<div class="c">

<h1>NMAP SECURITY REPORT</h1>
<div class="muted">Network Security Assessment · Generated from Nmap XML</div>
<div class="generated">Nmap Parse Report Generated from XML</div>
<div class="muted">
Input: {esc(data['source'])}
 · {esc(data['scanner'])} {esc(data['version'])}
 · Generated: {esc(generated)}
</div>

<div class="stats">
  <div class="stat"><div class="num">{len(hosts)}</div><div class="label">Hosts Scanned</div></div>
  <div class="stat"><div class="num">{hosts_up}</div><div class="label">Hosts Up</div></div>
  <div class="stat"><div class="num">{open_ports}</div><div class="label">Open Ports</div></div>
  <div class="stat"><div class="num">{findings}</div><div class="label">Findings</div></div>
  <div class="stat"><div class="num">{critical}</div><div class="label">Critical</div></div>
  <div class="stat"><div class="num">{len(unique_cves)}</div><div class="label">Unique CVEs</div></div>
</div>

<div class="toolbar">
  <input id="q" placeholder="Search IP, hostname, port, service, product, CVE...">
  <select id="f">
    <option value="all">All hosts</option>
    <option value="finding">With findings</option>
    <option value="clean">No findings</option>
  </select>
</div>

{host_sections}

<div class="footer">
  Nmap Parse Report v{VERSION} · Standalone HTML · Generated from Nmap XML
</div>

</div>

<script>
const q = document.getElementById("q");
const f = document.getElementById("f");

function applyFilters() {{
  const query = q.value.toLowerCase().trim();
  const filter = f.value;

  document.querySelectorAll(".host").forEach(host => {{
    const matchesText = host.innerText.toLowerCase().includes(query);
    const matchesFilter =
      filter === "all" || filter === host.dataset.f;

    host.style.display = matchesText && matchesFilter ? "" : "none";
  }});
}}

q.addEventListener("input", applyFilters);
f.addEventListener("change", applyFilters);
</script>

</body>
</html>
"""


def main():
    parser = argparse.ArgumentParser(
        description="Convert Nmap XML into a standalone HTML security report."
    )
    parser.add_argument("xml", help="Input Nmap XML file")
    parser.add_argument(
        "output_positional",
        nargs="?",
        help="Output HTML file (optional positional form)",
    )
    parser.add_argument(
        "-o", "--output",
        dest="output_option",
        help="Output HTML file",
    )

    args = parser.parse_args()

    output = args.output_option or args.output_positional or "nmap_report.html"

    if args.output_option and args.output_positional:
        parser.error("Use either positional output or -o/--output, not both.")

    input_path = Path(args.xml)
    output_path = Path(output)

    data = parse_nmap_xml(input_path)
    report = build_report(data)

    try:
        output_path.write_text(report, encoding="utf-8")
    except OSError as exc:
        raise SystemExit(f"[!] Cannot write report: {exc}")

    print(f"[+] Nmap XML : {input_path}")
    print(f"[+] HTML Report: {output_path}")
    print(f"[+] Hosts     : {len(data['hosts'])}")
    print(f"[+] Findings  : {sum(len(h['findings']) for h in data['hosts'])}")
    print(f"[+] Done.")


if __name__ == "__main__":
    main()
