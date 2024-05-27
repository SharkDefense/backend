from rest_framework.views import APIView
from rest_framework.response import Response
from .serializers import URLSerializer
from .models import MaliciousDomain
from .machine_model.ml import predict
from rest_framework.permissions import IsAuthenticated
from rest_framework_simplejwt.authentication import JWTAuthentication

from .utils import extract_domain
import requests
import networkx as nx
import pyvis.network as net
import socket
from bs4 import BeautifulSoup  
from datetime import datetime
import re
import time





class CheckURLView(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]

    def post(self, request):
        serializer = URLSerializer(data=request.data)
        if serializer.is_valid():
            url = serializer.validated_data['url']
            domain=extract_domain(url)
            is_virustotal_malicious = self.scan_with_virustotal(url)
            if MaliciousDomain.objects.filter(domain=domain).exists():
                return Response({'Classification_result': 'malicious found in our dataset' })
            elif is_virustotal_malicious:
                return Response({'Classification_result': 'malicious from virustotal' })

            return Response({'Classification_result': predict(url) })
        return Response(serializer.errors, status=400)


    def scan_with_virustotal(self,url):
        VIRUSTOTAL_API_KEY = '6721398630d0d3deca1d1516fc3a56428f8eea1425386eeb90fd4a9ffe9dcb6b'
        headers = {
            "x-apikey": VIRUSTOTAL_API_KEY
        }
        params = {
            'url': url
        }
        response = requests.post('https://www.virustotal.com/api/v3/urls', headers=headers, data=params)
        analysis_id = response.json()['data']['id']
        analysis_url = f'https://www.virustotal.com/api/v3/analyses/{analysis_id}'
        
        time.sleep(10)
        analysis_response = requests.get(analysis_url, headers=headers)
        if 'data' in analysis_response.json() and 'attributes' in analysis_response.json()['data']:
            stats = analysis_response.json()['data']['attributes']['stats']
            malicious = stats['malicious'] if 'malicious' in stats else 0
            return malicious > 0
        return False

class ScreenshotView(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]

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
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]

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
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]

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
                result = response.json().get('data', {})
                return result
                
            else:
                print(f"Error occurred while retrieving reputation information. Status code: {response.status_code}")

        except requests.exceptions.RequestException as e:
            print(f"Error occurred while retrieving reputation information: {e}")   


class WhoisView(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]  

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
            try:
                whois_data = soup.find(class_="df-block")
            except Exception as e:
                print(f"Error: {e}")
                return 'invalid domain' 

            domain=whois_data.contents[1].find(class_="df-value").text
            registrar=whois_data.contents[2].find(class_="df-value").text
            registered_on=whois_data.contents[3].find(class_="df-value").text
            expires_on=whois_data.contents[4].find(class_="df-value").text
            updated_on=whois_data.contents[5].find(class_="df-value").text
            status=whois_data.contents[6].find(class_="df-value").get_text(separator="\n").split('\n')
            try:
                name_servers=whois_data.contents[7].find(class_="df-value").get_text(separator="\n").split('\n') 
            except:
                name_servers=None

            result = {}
            if domain:
                result["Domain name"] = domain

            if registrar:
                result["Registrar"] = registrar

            if registered_on:
                result["Creation Date"] = registered_on
            if expires_on:
                result["Expiry Date"] = expires_on
            if updated_on:
                result["Updated on"] = updated_on
            if status:
                result["Status"] = status

            if name_servers:
                result["Name Servers"] = name_servers

            return result    
    
        else:
            print(f"Failed to retrieve WHOIS data for {domain}")
            return None 
    

       


    




    

