import whois


def print_banner():
    print("""
        ___          _        _____ _                 _     
       /   \___  ___| |_ ___ |  ___(_)_ __ ___  _ __ | |___ 
      / /\ / _ \/ __| __/ _ \| |_  | | '__/ _ \| '_ \| / __|
     / /_//  __/ (__| || (_) |  _| | | | | (_) | |_) | \__ \\
    /___,' \___|\___|\__\___/|_|   |_|_|  \___/| .__/|_|___/
                                               |_|         
                                        Author: Black Devil
    """)


def scan_domain(domain):
    # Whois lookup
    print(f"\nWHOIS lookup for {domain}:\n")
    print(whois.whois_lookup(domain))

    # Subdomain scanning
    print(f"\nScanning subdomains for {domain}...\n")
    subdomains = subdomain.subdomain_scan(domain)

    include_http = input(
        "Apakah Anda ingin mencari subdomain dengan protokol http? (y/n): ").lower() == "y"
    include_https = input(
        "Apakah Anda ingin mencari subdomain dengan protokol https? (y/n): ").lower() == "y"
    exclude_subdomains_str = input(
        "Jika ada subdomain yang ingin diexlude, masukkan dengan dipisahkan koma (tanpa spasi). Jika tidak ada, biarkan kosong: ")
    exclude_subdomains = exclude_subdomains_str.split(",")
    exclude_subdomains = [subdomain.strip()
                          for subdomain in exclude_subdomains]

    filtered_subdomains = subdomain.filter_subdomains(
        subdomains, include_http=include_http, include_https=include_https, exclude_subdomains=exclude_subdomains)

    print("\nSubdomains found:")
    for subdomain in filtered_subdomains:
        print(subdomain)


if __name__ == '__main__':
    print_banner()
    domain = input("Masukkan domain: ")
    scan_domain(domain)
