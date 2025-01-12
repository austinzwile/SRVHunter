# SRVHunter
A DNS reconnaissance tool for uncovering SRV records with precision. From LDAP servers to Kerberos guardians and certificate authorities, SRVHunter resolves hostnames, digs up IPs, and ensures no SRV is left in the shadows. Perfect for pentesters, sysadmins, and curious minds on a DNS quest. 🌐 💼 🔍

---

## Features 🚀

- Queries a comprehensive list of SRV records for various services, including:
  - LDAP, Kerberos, NTP, and PKI/CA services.
- Resolves hostnames and retrieves corresponding IP addresses.
- Handles DNS errors gracefully, providing actionable feedback.
- Customizable with options for specific nameservers and site names.
- Outputs results in a clean and structured format.

---

## Installation 📦

1. Clone the repository:
   ```bash
   git clone https://github.com/yourusername/srvhunter.git
   cd srvhunter
   ```

2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

3. Run the script:
   ```bash
   python srvhunter.py -d example.com
   ```

---

## Usage 🔧

Run the tool with the following options:

```bash
python srvhunter.py [options]
```

### Options:
| Option                  | Description                                     |
|-------------------------|-------------------------------------------------|
| `-n, --nameservers`   | Comma-separated list of nameservers to query.   |
| `-d, --domain`        | The target domain for SRV record lookups.       |
| `-s, --sitename`      | Optional site name for site-specific queries.   |

### Example:
Query SRV records for `acme.local` using local DNS servers:
```bash
python srvhunter.py -n "10.0.0.1,10.0.0.2" -d acme.local
```

---

## Demo 🖼️

*Here's an example of SRVHunter in action:*  
![Demo of SRVHunter](path/to/demo-image.png)

*(Replace `path/to/demo-image.png` with the actual image path once added.)*

---

## SRV Records Queried 📋

SRVHunter queries the following SRV records:

### SRV Records That Do NOT Require Site Names:
1. `_ldap._tcp`
2. `_ldap._tcp.dc._msdcs`
3. `_ldap._tcp.gc._msdcs`
4. `_kerberos._tcp`
5. `_kerberos._tcp.dc._msdcs`
6. `_kerberos._udp`
7. `_kpasswd._tcp`
8. `_kpasswd._udp`
9. `_ldap._tcp.pdc._msdcs`
10. `_ldap._tcp.dfsr._msdcs`
11. `_ntp._udp`
12. `_certauth._tcp`
13. `_certsrv._tcp`
14. `_certenroll._tcp`

### SRV Records That DO Require Site Names:
1. `_ldap._tcp.<SiteName>._sites`
2. `_ldap._tcp.<SiteName>._sites.gc._msdcs`

---

## Contributing 🤝

Contributions are welcome! If you'd like to improve SRVHunter, feel free to open an issue or submit a pull request.

---

## License 📜

This project is licensed under the MIT License. See the [LICENSE](./LICENSE) file for details.

---

## Acknowledgments 🙌

- Built with 💻 and 🧠  by [azw / austinzwile](https://github.com/austinzwile).
- Inspired by the need for effective DNS reconnaissance in pentesting.
