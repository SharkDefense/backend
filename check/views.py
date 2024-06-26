from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.permissions import AllowAny
from .serializers import URLSerializer
from .models import MaliciousDomain,TestedURL
from .utils import extract_domain
from .predictor import predict
import requests
import networkx as nx
import pyvis.network as net
import socket
from bs4 import BeautifulSoup  
import os
from PIL import Image
import matplotlib.pyplot as plt
import base64
from io import BytesIO
from dotenv import load_dotenv
import io


load_dotenv()



class CheckURLView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        serializer = URLSerializer(data=request.data)
        if serializer.is_valid():
            url = serializer.validated_data['url']
            test=self.check(url)

              # Save the tested URL to the database
            tested_url, created = TestedURL.objects.get_or_create(
            url=url,
            defaults={ 'state': test, 'count': 1}
                                 )
        
            if not created:
                tested_url.count += 1
                tested_url.state=test
                tested_url.save()

          
            return Response({'Classification_result': test })
            
        return Response(serializer.errors, status=400)

    def check(self,url):

        domain = extract_domain(url)
        
        if MaliciousDomain.objects.filter(domain=domain).exists():
            return 'malicious found in our dataset'
        
        prediction = predict(url)
        print(f"Prediction result: {prediction}")
        return prediction


    
              

class ScreenshotView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        serializer = URLSerializer(data=request.data)
        if serializer.is_valid():
            url = serializer.validated_data['url']
            return Response({'screenshot': self.get_screenshot(url)})  
        return Response(serializer.errors, status=400)

    
    def get_screenshot(self,url):

        GOOGLE_API_KEY = os.environ.get("GOOGLE_API_KEY")
        PSI_API_URL = f'https://www.googleapis.com/pagespeedonline/v5/runPagespeed?key={GOOGLE_API_KEY}'

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
                screenshot_data=screenshot_data.split(',')[1]
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
            graph_image=self.generate_graph(domain,subdomains)
            return Response({'Graph_visualization': graph_image})
        return Response(serializer.errors, status=400)


    def get_subdomains(self, domain):
        
        subdomain_api_key =os.environ.get("subdomain_api_key")
        api_url = f"https://www.virustotal.com/api/v3/domains/{domain}/subdomains"
        headers = {"x-apikey": subdomain_api_key}

        response = requests.get(api_url, headers=headers)

        if response.status_code == 200:
            data = response.json()
            return [subdomain['id'] for subdomain in data['data']]
        else:
            print(f"Failed to fetch subdomains. Status code: {response.status_code}")
            return []


   
    def generate_graph(self,domain, subdomains):
        # Initialize a directed graph
        graph = nx.DiGraph()

        # Add URL as the central node
        graph.add_node(domain)

        # Add subdomains as nodes and edges
        for subdomain in subdomains[:40]:
            graph.add_node(subdomain)
            graph.add_edge(domain, subdomain)

        # Create the graph visualization
        plt.figure(figsize=(10, 8))
        pos = nx.spring_layout(graph)
        nx.draw_networkx_nodes(graph, pos)
        nx.draw_networkx_edges(graph, pos)
        nx.draw_networkx_labels(graph, pos)

        # Save the graph as a BytesIO object
        buf = io.BytesIO()
        plt.savefig(buf, format='png')
        buf.seek(0)

        # Convert the image to a base64-encoded string
        graph_image = base64.b64encode(buf.getvalue()).decode('utf-8')

        return graph_image    
    
class IPReputationView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        serializer = URLSerializer(data=request.data)
        if serializer.is_valid():
            url = serializer.validated_data['url']
            domain = extract_domain(url)
            ip_address=self.get_ip_address(domain)
            
            return Response({'IP_Reputation': self.check_ip_reputation(ip_address)})
        return Response(serializer.errors, status=400)



    def get_ip_address(self,domain):  
        try:
            ip_address = socket.gethostbyname(domain)
            return ip_address
        except socket.gaierror as e:
            print(f"Error occurred while resolving IP address: {e}")
            return None
        
    def check_ip_reputation(self,ip_address):
        abusedb_api_key= os.environ.get("abusedb_api_key")
        try:
            url = 'https://api.abuseipdb.com/api/v2/check'

            querystring = {
                'ipAddress': f'{ip_address}',
                'maxAgeInDays': '90'
            }

            headers = {
                'Accept': 'application/json',
                'Key': abusedb_api_key
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
    permission_classes = [AllowAny]

    def post(self, request):
        serializer = URLSerializer(data=request.data)
        if serializer.is_valid():
            url = serializer.validated_data['url']
            domain = extract_domain(url)
            return Response({'Whois_info': self.whois_lookup(domain)})
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
            try:
                domain=whois_data.contents[1].find(class_="df-value").text
            except Exception as e:
                print(f"Error: {e}")
                domain=None   
            try:
                registrar=whois_data.contents[2].find(class_="df-value").text
            except Exception as e:
                print(f"Error: {e}")
                registrar=None   
            try:      
                registered_on=whois_data.contents[3].find(class_="df-value").text
            except Exception as e:
                print(f"Error: {e}")
                registered_on=None
            try:    
                expires_on=whois_data.contents[4].find(class_="df-value").text
            except Exception as e:
                print(f"Error: {e}")
                expires_on=None  
            try:      
                updated_on=whois_data.contents[5].find(class_="df-value").text
            except Exception as e:
                print(f"Error: {e}")
                updated_on=None 
            try:       
                status=whois_data.contents[6].find(class_="df-value").get_text(separator="\n").split('\n')
            except Exception as e:
                print(f"Error: {e}")
                status=None     
            try:
                name_servers=whois_data.contents[7].find(class_="df-value").get_text(separator="\n").split('\n') 
            except:
                name_servers=None

            result = {}
            if domain:
                result["Domain_name"] = domain

            if registrar:
                result["Registrar"] = registrar

            if registered_on:
                result["Creation_Date"] = registered_on
            if expires_on:
                result["Expiry_Date"] = expires_on
            if updated_on:
                result["Updated_on"] = updated_on
            if status:
                result["Status"] = status

            if name_servers:
                result["Name_Servers"] = name_servers

            return result    
    
        else:
            print(f"Failed to retrieve WHOIS data for {domain}")
            return None 
    