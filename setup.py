import requests
import socket
import whois
import os
import subprocess
import re
from urllib.parse import urlparse, parse_qs, urlencode
from colorama import init, Fore, Style

init()


def print_scanning_info():
    print(Fore.YELLOW + "Scanning in progress...")

def get_ip_address(domain):
    try:
        ip_address = socket.gethostbyname(domain)
        return ip_address
    except socket.error:
        print(Fore.RED + f"Cannot resolve {domain}")
        return None


def get_ip_address(domain):
    try:
        ip_address = socket.gethostbyname(domain)
        return ip_address
    except socket.error:
        print(Fore.RED + f"Cannot resolve {domain}")
        return None


def run_nikto(domain):
    print_scanning_info()
    try:
        output = subprocess.check_output(
            ['nikto', '-h', domain], stderr=subprocess.STDOUT)
        print(Fore.BLUE + "Nikto Output:")
        print(output.decode('utf-8'))
        print("")
    except subprocess.CalledProcessError as e:
        print(Fore.RED + f"Error running Nikto: {e.output.decode('utf-8')}")


def scan_domain(domain):
    try:
        ip_address = socket.gethostbyname(domain)
        w = whois.whois(domain)
        print(Fore.RED + "Domain Info:")
        print(f"\tDomain Name: {domain}")
        print(f"\tIP Address: {ip_address}")
        print(f"\tRegistrar: {w.registrar}")
        print(f"\tCreation Date: {w.creation_date}")
        print(f"\tExpiration Date: {w.expiration_date}")
        print(f"\tStatus: {w.status}")
        print("")

    except socket.error:
        print(Fore.RED + f"Cannot resolve {domain}")
    except AttributeError:
        w = whois.query(domain)
        print(Fore.GREEN + "Domain Info:")
        print(f"\tDomain Name: {domain}")
        print(f"\tRegistrar: {w.registrar}")
        print(f"\tCreation Date: {w.creation_date}")
        print(f"\tExpiration Date: {w.expiration_date}")
        print(f"\tStatus: {w.status}")
        print("")

def scan_xss_protection_header(url):
    try:
        response = requests.get(url)
        x_xss_protection_header = response.headers.get('X-XSS-Protection')
        if x_xss_protection_header:
            print(Fore.GREEN +
                  f"X-XSS-Protection header found: {x_xss_protection_header}")
        else:
            print(Fore.RED + "X-XSS-Protection header not found")
    except requests.exceptions.RequestException:
        print(Fore.RED + f"Cannot connect to {url}")

def scan_subdomains(domain, include_http=True, include_https=True, exclude_subdomains=None, proxy=None):
    if not exclude_subdomains:
        exclude_subdomains = []
    with open("core/subdomain.txt") as f:
        subdomains = [line.strip() for line in f]
    found_subdomains = []
    for subdomain in subdomains:
        full_domain = subdomain + "." + domain
        try:
            if proxy:
                # Use proxy server
                proxies = {"http": proxy, "https": proxy}
                response = requests.get(
                    f"http://{full_domain}", proxies=proxies)
                ip_address = socket.gethostbyname(response.url.split("//")[-1])
            else:
                ip_address = socket.gethostbyname(full_domain)
            if not include_http and (f"http://{full_domain}" in exclude_subdomains or f"http://{full_domain}/" in exclude_subdomains):
                continue
            if not include_https and (f"https://{full_domain}" in exclude_subdomains or f"https://{full_domain}/" in exclude_subdomains):
                continue
            if full_domain in exclude_subdomains or full_domain + "/" in exclude_subdomains:
                continue
            found_subdomains.append((full_domain, ip_address))
        except (socket.error, requests.exceptions.RequestException):
            pass
    return found_subdomains   

def print_banner():
    print(Fore.YELLOW + """
        ___          _        _____ _                 _     
       /   \___  ___| |_ ___ |  ___(_)_ __ ___  _ __ | |___ 
      / /\ / _ \/ __| __/ _ \| |_  | | '__/ _ \| '_ \| / __|
     / /_//  __/ (__| || (_) |  _| | | | | (_) | |_) | \__ \\
    /___,' \___|\___|\__\___/|_|   |_|_|  \___/| .__/|_|___/
                                               |_|  
                                                            
    By Black Devil - https://github.com/BlackDevil-ant
""")


def scan_sql_injection(url, wordlist):
    # Parse URL
    parsed_url = urlparse(url)
    query_params = parse_qs(parsed_url.query)

    # Check if URL has query parameters
    if not query_params:
        print("No query parameters found in URL")
        return

    # Iterate over query parameters
    for param in query_params:
        # Construct new URL with modified parameter value
        for payload in wordlist:
            modified_params = query_params.copy()
            modified_params[param] = [f"{payload}'"]
            modified_query = urlencode(modified_params, doseq=True)
            modified_url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}?{modified_query}"

            # Send request with modified parameter value
            try:
                response = requests.get(modified_url)
            except requests.exceptions.RequestException as e:
                print(f"Error: {e}")
                return

            # Check if response contains SQL error message or other SQL injection characteristic
            if "error" in response.text.lower() or re.search(r"sql.*error", response.text.lower()):
                print(f"Vulnerable parameter: {param} (URL: {modified_url})")
            elif "you have an error in your sql syntax" in response.text.lower():
                print(f"Vulnerable parameter: {param} (URL: {modified_url})")
            elif "supplied argument is not a valid mysql" in response.text.lower():
                print(f"Vulnerable parameter: {param} (URL: {modified_url})")


if __name__ == '__main__':
    print_banner()
    domain = input("Masukkan domain: ")
    subdomains = ["www"]
    wordlist = ("core/sql.txt")
    for subdomain in subdomains:
        url = f"https://{subdomain}.{domain}"
        try:
            response = requests.get(url)
            if response.status_code == 200:
                print(f"Scanning URL: {url}")
                scan_sql_injection(url, "1' or '1'='1")
            else:
                print(f"URL {url} returned status code {response.status_code}")
        except requests.exceptions.RequestException as e:
            print(f"Error: {e}")
            continue

    scan_domain(domain)
    run_nikto(domain)
    # Scan subdomains
    for subdomain in subdomains:
        url = f"http://{subdomain}.{domain}"
        print(f"Scanning {url}...")
        scan_sql_injection(url, wordlist)

    # Scan main domain
    url = f"http://{domain}"
    print(f"Scanning {url}...")
    scan_sql_injection(url, wordlist)

    # Scanning subdomains
subdomains = scan_subdomains(domain, exclude_subdomains=[domain])
if subdomains:
    print(Fore.GREEN + "Found subdomains:")
    for subdomain, ip_address in subdomains:
        print(f"\t{subdomain} ({ip_address})")
    print("")

scan_sql_injection(domain,wordlist)

# Scanning for X-XSS-Protection headers
headers = {"X-XSS-Protection": "1; mode=block"}
try:
    response = requests.get(f"http://{domain}", headers=headers)
    x_xss_protection = response.headers.get("X-XSS-Protection")
    if x_xss_protection:
        print(Fore.GREEN +
              f"X-XSS-Protection header set to: {x_xss_protection}")
    else:
        print(Fore.YELLOW + "No X-XSS-Protection header found.")
except requests.exceptions.RequestException:
    print(Fore.RED + f"Error scanning for X-XSS-Protection header on {domain}")
