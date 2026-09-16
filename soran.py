#!/usr/bin/env python3
import whois, socket, dns.resolver, builtwith, requests, json, argparse, os
from datetime import datetime
from colorama import Fore, Style, init
from rich.console import Console
from rich.table import Table
from rich.panel import Panel

init(autoreset=True)
console = Console()

BANNER = f"""{Fore.CYAN}
   ____ ___ ____ _ _ _
  / ___| / _ \\| _ \\/ \\ | \\ | |
  \\___ \\| | | | |_) / _ \\ | \\| |
   ___) | |_| | _ < / ___ \\| |\\ |
  |____/ \\___/|_| \\_/_/ \\_\\_| \\_|

  SORAN v2.0 - Advanced Website Intelligence
{Style.RESET_ALL}"""

def whois_lookup(domain):
    console.print("[yellow][*] WHOIS lookup...[/yellow]")
    try:
        w = whois.whois(domain)
        return {
            "date_registered": str(w.creation_date[0] if isinstance(w.creation_date, list) else w.creation_date),
            "expiry_date": str(w.expiration_date[0] if isinstance(w.expiration_date, list) else w.expiration_date),
            "registrar": w.registrar,
            "owner_name": w.name,
            "owner_email": str(w.email),
            "owner_country": w.country,
        }
    except Exception as e:
        return {"whois_error": str(e)}

def dns_lookup(domain):
    console.print("[yellow][*] DNS / IP lookup...[/yellow]")
    try:
        ip = socket.gethostbyname(domain)
        data = {"ip_address": ip}
        try:
            mx = dns.resolver.resolve(domain, 'MX')
            data["mail_servers"] = [str(r.exchange) for r in mx]
        except: data["mail_servers"] = []
        try:
            ns = dns.resolver.resolve(domain, 'NS')
            data["name_servers"] = [str(r) for r in ns]
        except: data["name_servers"] = []
        return data
    except Exception as e:
        return {"dns_error": str(e)}

def geo_lookup(ip):
    console.print("[yellow][*] Geolocation...[/yellow]")
    try:
        r = requests.get(f"https://ipwho.is/{ip}", timeout=10).json()
        return {
            "server_country": r.get("country"),
            "city": r.get("city"),
            "region": r.get("region"),
            "isp": r.get("connection", {}).get("isp"),
            "org": r.get("connection", {}).get("org")
        }
    except Exception as e:
        return {"geo_error": str(e)}

def tech_lookup(domain):
    console.print("[yellow][*] Technology detection...[/yellow]")
    try:
        return builtwith.parse(f"https://{domain}")
    except:
        return {}

def subdomain_lookup(domain):
    console.print("[yellow][*] Hunting subdomains (crt.sh)...[/yellow]")
    try:
        url = f"https://crt.sh/?q=%.{domain}&output=json"
        r = requests.get(url, timeout=15).json()
        subs = set()
        for entry in r:
            name = entry['name_value']
            # clean wildcard
            for sub in name.split('\n'):
                if domain in sub:
                    subs.add(sub.replace('*.','').strip())
        return sorted(list(subs))[:30]
    except Exception as e:
        return [f"Error: {e}"]

def reverse_ip_lookup(ip):
    console.print("[yellow][*] Reverse IP lookup...[/yellow]")
    try:
        r = requests.get(f"https://api.hackertarget.com/reverseiplookup/?q={ip}", timeout=10).text
        if "No DNS" in r or "error" in r.lower():
            return []
        return r.split("\n")[:20]
    except Exception as e:
        return [f"Error: {e}"]

def shodan_lookup(ip, api_key):
    if not api_key:
        return {"info": "Add --shodan-key to enable Shodan scan"}
    console.print("[yellow][*] Shodan scan...[/yellow]")
    try:
        r = requests.get(f"https://api.shodan.io/shodan/host/{ip}?key={api_key}", timeout=10).json()
        return {
            "open_ports": r.get("ports", []),
            "vulns": list(r.get("vulns", {}).keys())[:10],
            "hostnames": r.get("hostnames", []),
            "os": r.get("os")
        }
    except Exception as e:
        return {"shodan_error": str(e)}

def generate_html_report(data, domain):
    html = f"""
    <html><head><title>SORAN Report - {domain}</title>
    <style>body{{font-family:monospace;background:#0a0a0a;color:#00ff00;padding:30px}}
   .card{{background:#111;border:1px solid #00ff00;padding:20px;margin:15px 0;border-radius:10px}}
    h1{{color:#00ffff}} h2{{color:#ffff00}} </style></head><body>
    <h1>SORAN v2.0 Report - {domain}</h1>
    <p>Scanned: {data.get('scanned_at')}</p>
    <div class="card"><h2>WHOIS</h2><pre>{json.dumps({k:data[k] for k in ['date_registered','expiry_date','registrar','owner_country'] if k in data}, indent=2)}</pre></div>
    <div class="card"><h2>Network</h2><pre>IP: {data.get('ip_address')}\nCountry: {data.get('server_country')} - {data.get('city')}\nISP: {data.get('isp')}\nMail: {data.get('mail_servers')}\nNS: {data.get('name_servers')}</pre></div>
    <div class="card"><h2>Technologies</h2><pre>{json.dumps(data.get('technologies',{{}}), indent=2)}</pre></div>
    <div class="card"><h2>Subdomains Found ({len(data.get('subdomains',[]))})</h2><pre>{chr(10).join(data.get('subdomains',[]))}</pre></div>
    <div class="card"><h2>Reverse IP ({len(data.get('reverse_ip',[]))})</h2><pre>{chr(10).join(data.get('reverse_ip',[]))}</pre></div>
    <div class="card"><h2>Shodan</h2><pre>{json.dumps(data.get('shodan',{{}}), indent=2)}</pre></div>
    </body></html>
    """
    fname = f"{domain}_soran_report.html"
    with open(fname, "w") as f:
        f.write(html)
    return fname

def main():
    parser = argparse.ArgumentParser(description="SORAN v2.0")
    parser.add_argument("-d", "--domain", required=True, help="Target domain")
    parser.add_argument("-o", "--output", help="Save JSON")
    parser.add_argument("--html", action="store_true", help="Generate HTML report")
    parser.add_argument("--shodan-key", help="Shodan API key (free at account.shodan.io)")
    args = parser.parse_args()

    print(BANNER)
    domain = args.domain.replace("https://","").replace("http://","").split("/")[0]

    result = {"target": domain, "scanned_at": str(datetime.now())}
    result.update(whois_lookup(domain))

    dns_data = dns_lookup(domain)
    result.update(dns_data)

    if "ip_address" in dns_data:
        result.update(geo_lookup(dns_data["ip_address"]))
        result["reverse_ip"] = reverse_ip_lookup(dns_data["ip_address"])
        result["shodan"] = shodan_lookup(dns_data["ip_address"], args.shodan_key)

    result["technologies"] = tech_lookup(domain)
    result["subdomains"] = subdomain_lookup(domain)

    # Rich Table
    table = Table(title=f"SORAN v2.0 - {domain}", show_header=True)
    table.add_column("Field", style="cyan")
    table.add_column("Value", style="green")
    table.add_row("IP", result.get("ip_address","N/A"))
    table.add_row("Country", f"{result.get('server_country','')} {result.get('city','')}")
    table.add_row("ISP", str(result.get('isp','N/A')))
    table.add_row("Registrar", str(result.get('registrar','N/A')))
    table.add_row("Registered", str(result.get('date_registered','N/A')))
    table.add_row("Open Ports", str(result.get('shodan',{}).get('open_ports','Add --shodan-key')))
    table.add_row("Subdomains", str(len(result.get('subdomains',[]))) + " found")
    console.print(table)

    console.print(Panel(f"[bold green]Subdomains:[/]\n" + "\n".join(result['subdomains'][:15]), title="Subdomains"))
    console.print(Panel(f"[bold green]Reverse IP:[/]\n" + "\n".join(result['reverse_ip'][:10]), title="Other sites on same server"))

    if args.output:
        with open(args.output, "w") as f:
            json.dump(result, f, indent=2)
        console.print(f"[green][+] JSON saved to {args.output}")

    if args.html:
        html_file = generate_html_report(result, domain)
        console.print(f"[green][+] HTML report saved to {html_file}")

if __name__ == "__main__":
    main()
