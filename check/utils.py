from urllib.parse import urlparse



def extract_domain(url):
    parsed_url = urlparse(url)
    domain = parsed_url.netloc
    return domain
    
        

    