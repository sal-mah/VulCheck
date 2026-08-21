import nmap
import requests
import ipaddress  
import socket    
from html.parser import HTMLParser
from urllib.parse import urljoin, urlparse

class _LinkParser(HTMLParser):
    def __init__(self):
        super().__init__()  
        self.links = []  

    def handle_starttag(self, tag, attrs):
        if tag.lower() == "a":              
            href = dict(attrs).get("href")  
            if href:                        
                self.links.append(href)    

def validate_target(target):
    try:
        ipaddress.ip_address(target)
        return True
    except ValueError:
        try:
            socket.gethostbyname(target)  
            return True
        except socket.gaierror:
            return False

def scan_ports_nmap(target, ports=None, timeout=5):
   
    nm = nmap.PortScanner()
    
    if ports is None:
        ports = "1-1000" 
    else:

        if isinstance(ports, list):
            ports = ",".join(map(str, ports))
    
    try:

        scan_args = f"-sV -T4 -p {ports}"
        
        print(f"[*] Scanning {target} with Nmap...")
        nm.scan(hosts=target, arguments=scan_args)
        
        open_ports = []
        services = []
        
        for host in nm.all_hosts():
            for proto in nm[host].all_protocols():
                ports_info = nm[host][proto]
                for port, info in ports_info.items():
                    if info['state'] == 'open':
                        open_ports.append(port)
                        services.append({
                            "port": port,
                            "service": info.get('name', 'Unknown'),
                            "product": info.get('product', ''),
                            "version": info.get('version', ''),
                            "banner": info.get('banner', ''),
                            "extra": info.get('extrainfo', '')
                        })
        
        return open_ports, services
    
    except nmap.PortScannerError as e:
        print(f"[-] Nmap Error: {e}")
        return [], []
    except Exception as e:
        print(f"[-] Error: {e}")
        return [], []

def detect_http(target, open_ports):
    web_services = []
    if 80 in open_ports:
        web_services.append({
            "scheme": "http",
            "url": f"http://{target}"
        })
    if 443 in open_ports:
        web_services.append({
            "scheme": "https",
            "url": f"https://{target}"
        })
    return web_services

def http_recon(url, timeout=5):
    result = {
        "url": url,
        "status_code": None,
        "headers": {},
        "server": None,
        "powered_by": None,
        "content_type": None,
        "error": None
    }
    try:
        response = requests.get(url, timeout=timeout, allow_redirects=True)
        result["url"] = response.url
        result["status_code"] = response.status_code
        result["headers"] = dict(response.headers)
        result["server"] = response.headers.get("Server")
        result["powered_by"] = response.headers.get("X-Powered-By")
        result["content_type"] = response.headers.get("Content-Type")
    except requests.RequestException as e:
        result["error"] = str(e)
    return result

def crawl_endpoints(url, timeout=5):
    endpoints = set()
    try:
        response = requests.get(url, timeout=timeout, allow_redirects=True)
        base_url = response.url
        parsed_base = urlparse(base_url)
        endpoints.add(base_url)
        
        parser = _LinkParser()
        parser.feed(response.text)
        
        for href in parser.links:
            full_url = urljoin(base_url, href)
            parsed_url = urlparse(full_url)
            if parsed_url.netloc == parsed_base.netloc:
                endpoints.add(full_url)
    except requests.RequestException:
        pass
    return sorted(endpoints)

def detect_os_clues(services, http_results):
    clues = []
    
    # من Nmap - معلومات نظام التشغيل
    for service in services:
        banner = service.get("banner", "").lower()
        product = service.get("product", "").lower()
        version = service.get("version", "").lower()
        
        # Windows
        if "windows" in banner or "windows" in product:
            clues.append({
                "os_family": "Windows",
                "os_clue": "Windows",
                "confidence": "High",
                "source": f"Nmap - {service['service']}"
            })
        
        # Linux
        if "ubuntu" in banner or "ubuntu" in product:
            clues.append({
                "os_family": "Linux",
                "os_clue": "Ubuntu",
                "confidence": "High",
                "source": f"Nmap - {service['service']}"
            })
        elif "debian" in banner or "debian" in product:
            clues.append({
                "os_family": "Linux",
                "os_clue": "Debian",
                "confidence": "High",
                "source": f"Nmap - {service['service']}"
            })
        elif "linux" in banner or "linux" in product:
            clues.append({
                "os_family": "Linux",
                "os_clue": "Linux (generic)",
                "confidence": "Medium",
                "source": f"Nmap - {service['service']}"
            })
    
    # من HTTP
    for http_info in http_results:
        server = (http_info["server"] or "").lower()
        if "ubuntu" in server:
            clues.append({
                "os_family": "Linux",
                "os_clue": "Ubuntu",
                "confidence": "Medium",
                "source": "HTTP Server header"
            })
    
    return clues

def run_recon_scan(target):
    result = {
        "module": "recon",
        "target": target,
        "status": "success",
        "host": {
            "reachable": False,
            "os_clues": []
        },
        "ports": [],
        "services": [],
        "web_services": [],
        "http_results": [],
        "endpoints": [],
        "findings": [],
        "errors": []
    }
    
    if not validate_target(target):
        result["status"] = "error"
        result["errors"].append("Invalid target")
        return result
    
    # فحص المنافذ باستخدام Nmap
    ports = [21, 22, 23, 25, 53, 80, 110, 139, 443, 445]
    open_ports, services = scan_ports_nmap(target, ports)
    
    result["ports"] = open_ports
    result["services"] = services
    
    if not open_ports:
        result["host"]["reachable"] = False
        result["status"] = "error"
        result["errors"].append("No open ports found")
        return result
    
    result["host"]["reachable"] = True
    
    # اكتشاف خدمات الويب
    web_services = detect_http(target, open_ports)
    result["web_services"] = web_services
    
    # HTTP Recon
    http_results = []
    for web in web_services:
        http_info = http_recon(web["url"])
        http_results.append(http_info)
        endpoints = crawl_endpoints(web["url"])
        result["endpoints"].extend(endpoints)
    
    result["http_results"] = http_results
    result["endpoints"] = sorted(set(result["endpoints"]))
    
    # اكتشاف نظام التشغيل
    os_clues = detect_os_clues(services, http_results)
    result["host"]["os_clues"] = os_clues
    
    return result

if __name__ == "__main__":
    target = input("Enter target IP or domain: ").strip()
    print(f"[+] Target: {target}")
    
    recon_data = run_recon_scan(target)
    
    if recon_data["status"] == "error":
        print(f"[-] Recon failed")
        for error in recon_data["errors"]:
            print(f"    Error: {error}")
    else:
        print("\n[+] Host is reachable")
        
        print("\n[+] Open ports:")
        for port in recon_data["ports"]:
            print(f"    - {port}")
        
        print("\n[+] Service Detection (from Nmap):")
        for service in recon_data["services"]:
            print(f"\n    Port: {service['port']}")
            print(f"    Service: {service['service']}")
            if service.get('product'):
                print(f"    Product: {service['product']}")
            if service.get('version'):
                print(f"    Version: {service['version']}")
            if service.get('banner'):
                print(f"    Banner: {service['banner']}")
            else:
                print("    Banner: Not available")
        
        print("\n[+] Web Services")
        if recon_data["web_services"]:
            for web in recon_data["web_services"]:
                print(f"    {web['scheme'].upper()} -> {web['url']}")
        else:
            print("    No web services found")
        
        print("\n[+] HTTP Recon")
        for http_info in recon_data["http_results"]:
            print(f"\n    URL: {http_info['url']}")
            print(f"    Status Code: {http_info['status_code']}")
            print(f"    Server: {http_info['server']}")
            print(f"    X-Powered-By: {http_info['powered_by']}")
            print(f"    Content-Type: {http_info['content_type']}")
            if http_info["error"]:
                print(f"    Error: {http_info['error']}")
        
        print("\n[+] Endpoint Crawling")
        if recon_data["endpoints"]:
            for endpoint in recon_data["endpoints"]:
                print(f"    - {endpoint}")
        else:
            print("    No endpoints found")
        
        print("\n[+] OS Clues")
        if recon_data["host"]["os_clues"]:
            for clue in recon_data["host"]["os_clues"]:
                print(f"    OS Family: {clue['os_family']}")
                print(f"    OS Clue: {clue['os_clue']}")
                print(f"    Confidence: {clue['confidence']}")
                print(f"    Source: {clue['source']}")
        else:
            print("    No OS clues found")
