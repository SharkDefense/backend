from rest_framework.views import APIView
from rest_framework.response import Response
from .serializers import URLSerializer
from .machine_model.ml import predict
from rest_framework.permissions import IsAuthenticated,AllowAny
from .utils import extract_domain
import requests
import networkx as nx
import pyvis.network as net
import socket
from bs4 import BeautifulSoup  
from datetime import datetime
import re




class CheckURLView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        serializer = URLSerializer(data=request.data)
        if serializer.is_valid():
            url = serializer.validated_data['url']
            return Response({'Classification_result': predict(url) })
        return Response(serializer.errors, status=400)


class ScreenshotView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        serializer = URLSerializer(data=request.data)
        if serializer.is_valid():
            url = serializer.validated_data['url']
            return Response({'screenshot ': self.get_screenshot(url)})  
        return Response(serializer.errors, status=400)

    
    def get_screenshot(self,url):

        API_KEY = 'AIzaSyBEvMEs5sPH4ZJDIcv3fxtC1BGfHh1imnI'
        PSI_API_URL = f'https://www.googleapis.com/pagespeedonline/v5/runPagespeed?key={API_KEY}'

        params = {
            'url': url,
            'strategy': 'desktop',  # 'mobile' or 'desktop' based on your requirement
            'screenshot': True,
        }

        response = requests.get(PSI_API_URL, params=params)

        if response.status_code == 200:
            result = response.json()
            screenshot_data = result.get('lighthouseResult', {}).get('audits', {}).get('final-screenshot', {}).get(
                'details', {}).get('data', None)
            if screenshot_data:
                
                return screenshot_data
            else:
                return 'Unable to fetch screenshot data'
        else:
            return ' API request failed' 

class VisualizeSubdomainsView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        serializer = URLSerializer(data=request.data)
        if serializer.is_valid():
            url = serializer.validated_data['url']
            domain = extract_domain(url)
            subdomains = self.get_subdomains(domain) 
            return Response({'Graph visualization ': self.generate_graph(domain,subdomains)})
        return Response(serializer.errors, status=400)


    def get_subdomains(self, domain):
        api_key = 'j92HQnvQF5mSqDgfkRQ8L2kCTGM9DsG_'
        api_url = f'https://api.securitytrails.com/v1/domain/{domain}/subdomains'
        headers = {'APIKEY': api_key}

        response = requests.get(api_url, headers=headers)

        if response.status_code == 200:
            subdomains = response.json().get('subdomains', [])
            return subdomains
        else:
            print(f"Failed to fetch subdomains. Status code: {response.status_code}")
            return []


    def generate_graph(self,domain,subdomains):
        # Initialize a directed graph
        graph = nx.DiGraph()

        # Add URL as the central node
        graph.add_node(domain)

        # Add subdomains as nodes and edges
        for subdomain in subdomains[:40]:
            graph.add_node(subdomain)
            graph.add_edge(domain, subdomain)

        # Create the graph visualization
        pyvis_graph = net.Network(height="500px", width="100%", directed=True, notebook=False)
        pyvis_graph.from_nx(graph)
        pyvis_graph.show_buttons(filter_=['nodes'])
        html = pyvis_graph.generate_html()
        return html    
    
class IPReputationView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        serializer = URLSerializer(data=request.data)
        if serializer.is_valid():
            url = serializer.validated_data['url']
            domain = extract_domain(url)
            ip_address=self.get_ip_address(domain)
            
            return Response({'IP Reputation': self.check_ip_reputation(ip_address)})
        return Response(serializer.errors, status=400)



    def get_ip_address(self,domain):  
        try:
            ip_address = socket.gethostbyname(domain)
            return ip_address
        except socket.gaierror as e:
            print(f"Error occurred while resolving IP address: {e}")
            return None
        
    def check_ip_reputation(self,ip_address):

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
                    return response
                
            else:
                print(f"Error occurred while retrieving reputation information. Status code: {response.status_code}")

        except requests.exceptions.RequestException as e:
            print(f"Error occurred while retrieving reputation information: {e}")   


class WhoisView(APIView):
    permission_classes = [AllowAny]
    def post(self, request):
        serializer = URLSerializer(data=request.data)
        if serializer.is_valid():
            url = serializer.validated_data['url']
            domain = extract_domain(url)
            return Response({'Whois info': self.whois_lookup(domain)})
        return Response(serializer.errors, status=400)

    
    def whois_lookup(self,domain):
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


    

