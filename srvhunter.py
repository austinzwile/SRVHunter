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

def print_good(message):
    print(f"{Fore.GREEN}[+] {Style.RESET_ALL}{message}")

def print_bad(message):
    print(f"{Fore.RED}[-] {Style.RESET_ALL}{message}")

def print_divider(text):
    print("-" * len(text))

def resolve_ip(hostname):
    """Resolve the IP address of a hostname."""
    try:
        return socket.gethostbyname(hostname.rstrip('.'))
    except socket.gaierror:
        return "Unable to resolve IP"

def perform_dns_lookup(nameservers, domain, sitename):
    # SRV records that do NOT require a site name
    non_site_srv_records = [
        "_ldap._tcp",
        "_ldap._tcp.dc._msdcs",
        "_ldap._tcp.gc._msdcs",
        "_kerberos._tcp",
        "_kerberos._tcp.dc._msdcs",
        "_kerberos._udp",
        "_kpasswd._tcp",
        "_kpasswd._udp",
        "_ldap._tcp.pdc._msdcs",
        "_ldap._tcp.dfsr._msdcs",
        "_ntp._udp",
        "_certauth._tcp",
        "_certsrv._tcp",
        "_certenroll._tcp"
    ]

    # SRV records that DO require a site name
    site_specific_srv_records = [
        "_ldap._tcp.<SiteName>._sites",
        "_ldap._tcp.<SiteName>._sites.gc._msdcs"
    ]

    # To keep track of non-found records
    not_found_records = []

    resolver = dns.resolver.Resolver()
    if nameservers:
        resolver.nameservers = nameservers
        print_good(f"Using custom nameservers: {', '.join(nameservers)}")
    else:
        print_good("Using system resolvers")

    try:
        for record in non_site_srv_records:
            record_fqdn = f"{record}.{domain}"
            try:
                answers = resolver.resolve(record_fqdn, "SRV")
                print_good(f"SRV Record: {record_fqdn}")
                print_divider(f"SRV Record: {record_fqdn}")
                for answer in answers:
                    ip = resolve_ip(str(answer.target))
                    print(f"Target: {answer.target}, IP: {ip}, Port: {answer.port}, Priority: {answer.priority}, Weight: {answer.weight}")
                print()
            except dns.resolver.NoAnswer:
                not_found_records.append(record_fqdn)
            except dns.resolver.NXDOMAIN:
                not_found_records.append(record_fqdn)
            except dns.resolver.Servfail:
                print_bad("The DNS server returned a SERVFAIL error. Possible reasons include:")
                print_divider("The DNS server returned a SERVFAIL error. Possible reasons include:")
                print("  - Misconfigured DNS server.")
                print("  - Network connectivity issues.")
                print("  - DNSSEC validation failure.")
                print("\nSuggested resolutions:")
                print("  - Try adding a nameserver using the `-n` flag.")
                print("  - Ensure the DNS server is reachable.")
                print("  - Check DNSSEC settings if enabled.")
                sys.exit(1)
            except Exception as e:
                print_bad(f"Error while querying {record_fqdn}: {e}")

        for record in site_specific_srv_records:
            record_fqdn = record.replace("<SiteName>", sitename) + f".{domain}"
            try:
                answers = resolver.resolve(record_fqdn, "SRV")
                print_good(f"SRV Record: {record_fqdn}")
                print_divider(f"SRV Record: {record_fqdn}")
                for answer in answers:
                    ip = resolve_ip(str(answer.target))
                    print(f"Target: {answer.target}, IP: {ip}, Port: {answer.port}, Priority: {answer.priority}, Weight: {answer.weight}")
                print()
            except dns.resolver.NoAnswer:
                not_found_records.append(record_fqdn)
            except dns.resolver.NXDOMAIN:
                not_found_records.append(record_fqdn)
            except dns.resolver.Servfail:
                print_bad("The DNS server returned a SERVFAIL error. Possible reasons include:")
                print_divider("The DNS server returned a SERVFAIL error. Possible reasons include:")
                print("  - Misconfigured DNS server.")
                print("  - Network connectivity issues.")
                print("  - DNSSEC validation failure.")
                print("\nSuggested resolutions:")
                print("  - Try adding a nameserver using the `-n` flag.")
                print("  - Ensure the DNS server is reachable.")
                print("  - Check DNSSEC settings if enabled.")
                sys.exit(1)
            except Exception as e:
                print_bad(f"Error while querying {record_fqdn}: {e}")

    except KeyboardInterrupt:
        print_bad("Operation aborted by user.")
        sys.exit(1)

    if not_found_records:
        print_bad("No SRV records found for:")
        print("-----------------------------")
        for record in not_found_records:
            print(record)
        print()

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Perform DNS SRV record lookups.")
    parser.add_argument("-n", "--nameservers", help="Comma-separated list of nameservers to query.")
    parser.add_argument("-d", "--domain", required=True, help="Domain to query for SRV records.")
    parser.add_argument("-s", "--sitename", default="Default-First-Site-Name", help="Optional site name for site-specific SRV records (default: Default-First-Site-Name).")
    args = parser.parse_args()

    print_banner()
    nameservers = args.nameservers.split(",") if args.nameservers else None
    domain = args.domain
    sitename = args.sitename

    perform_dns_lookup(nameservers, domain, sitename)
