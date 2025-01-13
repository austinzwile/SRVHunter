import argparse
import dns.resolver
from colorama import Fore, Style
import sys
import socket

def print_banner():
    banner = """
+----------------------------------------------------+
|  ____  ______     ___   _             _            |
| / ___||  _ \\ \\   / / | | |_   _ _ __ | |_ ___ _ __ |
| \\___ \\| |_) \\ \\ / /| |_| | | | | '_ \\| __/ _ \\ '__||
|  ___) |  _ < \\ V / |  _  | |_| | | | | ||  __/ |   |
| |____/|_| \\_\\ \\_/  |_| |_|\\__,_|_| |_|\\__\\___|_|   |
|                                                    |
+----------------------------------------------------+
"""
    print(banner)

def print_good(message, output_file=None):
    formatted_message = f"{Fore.GREEN}[+] {Style.RESET_ALL}{message}"
    print(formatted_message)
    if output_file:
        with open(output_file, "a") as f:
            f.write(f"[+] {message}\n")

def print_bad(message, output_file=None):
    formatted_message = f"{Fore.RED}[-] {Style.RESET_ALL}{message}"
    print(formatted_message)
    if output_file:
        with open(output_file, "a") as f:
            f.write(f"[-] {message}\n")

def print_divider(text, output_file=None):
    divider = "-" * len(text)
    print(divider)
    if output_file:
        with open(output_file, "a") as f:
            f.write(f"{divider}\n")

def resolve_ip(hostname):
    try:
        return socket.gethostbyname(hostname.rstrip('.'))
    except socket.gaierror:
        return "Unable to resolve IP"

def get_srv_records(record_groups):
    srv_records = {
        "ds": [
            "_ldap._tcp",
            "_ldap._tcp.dc._msdcs",
            "_ldap._tcp.gc._msdcs",
            "_ldap._tcp.pdc._msdcs",
            "_ldap._tcp.dfsr._msdcs",
            "_kerberos._tcp",
            "_kerberos._tcp.dc._msdcs",
            "_kerberos._udp",
            "_kpasswd._tcp",
            "_kpasswd._udp"
        ],
        "pki": [
            "_certauth._tcp",
            "_certsrv._tcp",
            "_certenroll._tcp"
        ],
        "ex": [
            "_autodiscover._tcp"
        ],
        "fs": [
            "_afpovertcp._tcp",
            "_smb._tcp",
            "_webdav._tcp",
            "_ipp._tcp",
            "_printer._tcp"
        ],
        "im": [
            "_xmpp-client._tcp",
            "_xmpp-server._tcp"
        ],
        "voip": [
            "_sip._tcp",
            "_sip._udp",
            "_sips._tcp",
            "_h323cs._tcp",
            "_h323ls._tcp"
        ],
        "ntp": [
            "_ntp._tcp"
        ]
    }

    selected_records = set()
    for group in record_groups:
        if group == "all":
            return [record for group_records in srv_records.values() for record in group_records]
        selected_records.update(srv_records.get(group, []))
    return list(selected_records)

def perform_dns_lookup(nameservers, domain, sitename, srv_records, output_file=None):
    found_records = []
    not_found_records = []

    resolver = dns.resolver.Resolver()
    if nameservers:
        resolver.nameservers = nameservers
        print_good(f"Using custom nameservers: {', '.join(nameservers)}", output_file)
    else:
        print_good("Using system resolvers", output_file)

    try:
        for record in srv_records:
            record_fqdn = record.replace("<SiteName>", sitename) + f".{domain}"
            try:
                answers = resolver.resolve(record_fqdn, "SRV")
                found_records.append(record_fqdn)
                print_good(f"SRV Record: {record_fqdn}", output_file)
                print_divider(f"SRV Record: {record_fqdn}", output_file)
                for answer in answers:
                    ip = resolve_ip(str(answer.target))
                    result = f"Target: {answer.target}, IP: {ip}, Port: {answer.port}, Priority: {answer.priority}, Weight: {answer.weight}"
                    print(result)
                    if output_file:
                        with open(output_file, "a") as f:
                            f.write(result + "\n")
                print()
                if output_file:
                    with open(output_file, "a") as f:
                        f.write("\n")
            except dns.resolver.NoAnswer:
                not_found_records.append(record_fqdn)
            except dns.resolver.NXDOMAIN:
                not_found_records.append(record_fqdn)
            except dns.resolver.Servfail:
                print_bad("The DNS server returned a SERVFAIL error. Possible reasons include:", output_file)
                print_divider("The DNS server returned a SERVFAIL error. Possible reasons include:", output_file)
                print("  - Misconfigured DNS server.")
                print("  - Network connectivity issues.")
                print("  - DNSSEC validation failure.")
                print("\nSuggested resolutions:")
                print("  - Try adding a nameserver using the `-n` flag.")
                print("  - Ensure the DNS server is reachable.")
                print("  - Check DNSSEC settings if enabled.")
                sys.exit(1)
            except Exception as e:
                print_bad(f"Error while querying {record_fqdn}: {e}", output_file)

    except KeyboardInterrupt:
        print_bad("Operation aborted by user.", output_file)
        sys.exit(1)

    print("\nSummary of Findings:")
    summary_header = "-----------------------------------"
    print(summary_header)
    if output_file:
        with open(output_file, "a") as f:
            f.write("\nSummary of Findings:\n")
            f.write(summary_header + "\n")

    print_good(f"Total Records Queried: {len(srv_records)}", output_file)
    print_good(f"Records Found: {len(found_records)}", output_file)
    print_bad(f"Records Not Found: {len(not_found_records)}", output_file)

    if found_records:
        print("\n[+] Found Records:")
        if output_file:
            with open(output_file, "a") as f:
                f.write("\n[+] Found Records:\n")
        for record in found_records:
            print(f"  - {record}")
            if output_file:
                with open(output_file, "a") as f:
                    f.write(f"  - {record}\n")

    if not_found_records:
        print("\n[-] Records Not Found:")
        if output_file:
            with open(output_file, "a") as f:
                f.write("\n[-] Records Not Found:\n")
        for record in not_found_records:
            print(f"  - {record}")
            if output_file:
                with open(output_file, "a") as f:
                    f.write(f"  - {record}\n")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Perform DNS SRV record lookups.")
    parser.add_argument("-d", "--domain", required=True, help="Domain to query for SRV records.")
    parser.add_argument("-n", "--nameservers", help="Comma-separated list of nameservers to query.")
    parser.add_argument("-o", "--output", help="Optional output file to save results.")
    parser.add_argument("-s", "--sitename", default="Default-First-Site-Name", help="Optional site name for site-specific queries (default: Default-First-Site-Name).")
    parser.add_argument(
        "-r", "--records",
        default="all",
        help=(
            "Comma-separated service groups to query (default: all):\n"
            "- ds: Directory Services (LDAP and Kerberos)\n"
            "- pki: Public-Key Infrastructure (e.g., certificate services)\n"
            "- ex: Microsoft Exchange (e.g., Autodiscover)\n"
            "- fs: File Sharing (e.g., SMB, WebDAV, NFS)\n"
            "- im: Instant Messaging and Video Chat (e.g., XMPP)\n"
            "- voip: IP Phones (e.g., SIP, H.323)\n"
            "- ntp: Network Time Protocol\n"
            "- all: Query all available records"
        )
    )
    args = parser.parse_args()

    print_banner()
    nameservers = args.nameservers.split(",") if args.nameservers else None
    domain = args.domain
    sitename = args.sitename
    record_groups = args.records.split(",")
    output_file = args.output

    srv_records = get_srv_records(record_groups)
    if not srv_records:
        print_bad(f"No SRV records found for specified groups: {', '.join(record_groups)}", output_file)
        sys.exit(1)

    perform_dns_lookup(nameservers, domain, sitename, srv_records, output_file)
