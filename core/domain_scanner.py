import whois
import requests
from bs4 import BeautifulSoup
from urllib.parse import urlparse


def whois_lookup(domain):
    """
    Conducts a WHOIS lookup for the specified domain.
    """
    w = whois.whois(domain)
    return str(w)


def subdomain_scan(domain):
    """
    Scans for subdomains of the specified domain using the Google search engine.
    """
    subdomains = set()

    url = f"https://www.google.com/search?q=site:{domain}&start="
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.36"}
    page = 1
    while True:
        sub_url = url + str(page)
        try:
            html = requests.get(sub_url, headers=headers).text
        except:
            break
        soup = BeautifulSoup(html, 'html.parser')
        try:
            search_results = soup.find_all('div', {'class': 'r'})
            for result in search_results:
                link = result.find('a')['href']
                parsed_url = urlparse(link)
                subdomain = parsed_url.netloc.split('.')[0]
                subdomains.add(subdomain)
        except:
            pass
        if "No results found for" in str(soup):
            break
        page += 10

    return subdomains
