from urllib.parse import urlparse



def extract_domain(url):
    parsed_url = urlparse(url)
    if parsed_url.netloc:
        domain = parsed_url.netloc.lower()
        if domain.startswith("www."):
            domain = domain[4:]  # Remove "www." prefix
        return domain
    else:
        return None
    
        

    