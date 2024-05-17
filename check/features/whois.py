import re
import requests
from bs4 import BeautifulSoup  
from datetime import datetime
#from dateutil import parser


def get_domain(url):
    # Extracting domain from URL
    domain = url.split('//')[-1].split('/')[0]
    return domain

def whois_lookup(domain):
    # URL for WHOIS lookup
    whois_url = f"https://www.whois.com/whois/{domain}"

    # Sending GET request to WHOIS website
    response = requests.get(whois_url)

    if response.status_code == 200:
    # Parsing HTML content
        soup = BeautifulSoup(response.content, 'html.parser')

    # Finding WHOIS data
        whois_data = soup.find("pre", class_="df-raw").text

    # Extracting creation date, expiry date
        creation_date = re.search(r"Creation Date: (.+)", whois_data)
        expiry_date = re.search(r"Registry Expiry Date: (.+)", whois_data)
        result = {}
        if creation_date:
            result["creation_date"] = creation_date.group(1)
        if expiry_date:
            result["expiration_date"] = expiry_date.group(1)

        return result
    else:
        print(f"Failed to retrieve WHOIS data for {domain}")
        return None


    
def whois(url):
    domain=get_domain(url)
    whois=whois_lookup(domain)
    return whois    
    
url='https://www.google.com'
whois=whois(url)
print(whois)