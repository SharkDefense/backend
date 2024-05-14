import requests
import json
import socket
from urllib.parse import urlparse

def extract_domain_from_url(url):
    domain = None
    try:
        parsed_url = urlparse(url)
        domain = parsed_url.netloc
    except Exception as e:
        print(f"Error occurred while parsing the URL: {e}")
    return domain

def get_ip_address(domain):  
    try:
        ip_address = socket.gethostbyname(domain)
        return ip_address
    except socket.gaierror as e:
        print(f"Error occurred while resolving IP address: {e}")
        return None
    
def check_ip_reputation(ip_address):
    
            try:
                url = 'https://api.abuseipdb.com/api/v2/check'

                querystring = {
                    'ipAddress': f'{ip_address}',
                    'maxAgeInDays': '90'
                }

                headers = {
                    'Accept': 'application/json',
                    'Key': 'a5481805b7182022b010b471c60bb48cd291e931c3e26964404177a4c6092818f502983f3a14d1a0'
                }

                response = requests.request(method='GET', url=url, headers=headers, params=querystring)

                if response.status_code == 200:
                      result = response.json()
                      return result
                  
                else:
                    print(f"Error occurred while retrieving reputation information. Status code: {response.status_code}")

            except requests.exceptions.RequestException as e:
                print(f"Error occurred while retrieving reputation information: {e}")

def ip_reputation(url):
     domain=extract_domain_from_url(url)
     ip=get_ip_address(domain)
     reputation=check_ip_reputation(ip)
     formatted_reputation = json.dumps(reputation, indent=4)
     return formatted_reputation
    
     

# url='https://google.com'
# x=ip_reputation(url)
# print(x)


