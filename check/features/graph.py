import requests
import networkx as nx
import pyvis.network as net
from urllib.parse import urlparse

api_key = 'j92HQnvQF5mSqDgfkRQ8L2kCTGM9DsG_'

def extract_domain_from_url(url):
    domain = None
    try:
        parsed_url = urlparse(url)
        domain = parsed_url.netloc
    except Exception as e:
        print(f"Error occurred while parsing the URL: {e}")
    return domain

def get_subdomains(api_key, domain):
    api_url = f'https://api.securitytrails.com/v1/domain/{domain}/subdomains'
    headers = {'APIKEY': api_key}

    response = requests.get(api_url, headers=headers)
    
    if response.status_code == 200:
        subdomains = response.json().get('subdomains', [])
        return subdomains
    else:
        print(f"Failed to fetch subdomains. Status code: {response.status_code}")
        return []
    
def generate_graph(main_domain,subdomains):
    # Initialize a directed graph
    graph = nx.DiGraph()

    # Add URL as the central node
    graph.add_node(main_domain)

    # Add subdomains as nodes and edges
    for subdomain in subdomains[:40]:
        graph.add_node(subdomain)
        graph.add_edge(main_domain, subdomain)

    # Create the graph visualization
    pyvis_graph = net.Network(height="500px", width="100%", directed=True, notebook=False)
    pyvis_graph.from_nx(graph)
    pyvis_graph.show_buttons(filter_=['nodes'])
    html = pyvis_graph.generate_html()
    return html


def graph(url):
    main_domain=extract_domain_from_url(url)
    subdomains = get_subdomains(api_key, main_domain)
    graph_html=generate_graph(main_domain,subdomains)
    return graph_html





#usage example

# url = 'https://www.google.com'
# x=graph(url)
# print(x)

# Save the HTML to a file

# with open('subdomain_graph.html', 'w') as file:
#     file.write(graph_html)
