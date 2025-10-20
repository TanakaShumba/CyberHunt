#!/usr/bin/env python3
import requests, argparse, pandas as pd, datetime, os
from rich.console import Console
from rich.table import Table
from jinja2 import Template

console = Console()
VT_API = "https://www.virustotal.com/api/v3/ip_addresses/"
HEADERS = {"x-apikey": "YOUR_API_KEY_HERE"}  # Replace with your VirusTotal key

def vt_check(ip):
    try:
        r = requests.get(VT_API + ip, headers=HEADERS)
        if r.status_code != 200:
            return {"ip": ip, "malicious": "Error", "last_analysis": "N/A"}
        data = r.json()
        score = data["data"]["attributes"]["last_analysis_stats"]["malicious"]
        return {"ip": ip, "malicious": score, "last_analysis": data["data"]["attributes"]["last_analysis_date"]}
    except Exception as e:
        return {"ip": ip, "malicious": "Error", "last_analysis": str(e)}

def html_report(results):
    os.makedirs("reports", exist_ok=True)
    template = Template("""
    <html><head><title>CyberHunt Report</title></head>
    <body style="background:black;color:#39ff14;font-family:monospace;">
    <h1>🕵️‍♂️ CyberHunt Threat Intelligence Report</h1>
    <table border="1" cellspacing="0" cellpadding="5">
    <tr><th>IP</th><th>Malicious</th><th>Last Analysis</th></tr>
    {% for r in results %}
      <tr><td>{{r.ip}}</td><td>{{r.malicious}}</td><td>{{r.last_analysis}}</td></tr>
    {% endfor %}
    </table>
    <p>Generated: {{date}}</p>
    </body></html>
    """)
    with open("reports/cyberhunt_report.html","w") as f:
        f.write(template.render(results=results, date=datetime.datetime.now()))
    console.print("[green]✅ Report saved: reports/cyberhunt_report.html[/green]")

def main():
    parser = argparse.ArgumentParser(description="CyberHunt Threat Intelligence CLI")
    parser.add_argument("-i", "--indicator", help="Single IP address or domain to check")
    parser.add_argument("-f", "--file", help="File containing list of IPs/domains")
    args = parser.parse_args()

    indicators = []
    if args.indicator:
        indicators.append(args.indicator)
    elif args.file:
        with open(args.file) as f:
            indicators = [line.strip() for line in f.readlines() if line.strip()]
    else:
        console.print("[red]Provide an indicator or file (-i or -f).[/red]")
        return

    results = [vt_check(i) for i in indicators]

    # Display in console
    table = Table(title="CyberHunt Threat Report", style="green")
    table.add_column("IP/Domain"), table.add_column("Malicious"), table.add_column("Last Analysis")
    for r in results:
        table.add_row(r["ip"], str(r["malicious"]), str(r["last_analysis"]))
    console.print(table)

    # Save HTML report
    html_report(results)

if __name__ == "__main__":
    main()
