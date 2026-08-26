import nmap
import requests
import ipaddress
import socket
import re

from html.parser import HTMLParser
from pathlib import Path
from urllib.parse import urljoin, urlparse


# ============================================================================
# CONFIGURATION
# ============================================================================

BASE_DIR = Path(__file__).resolve().parent.parent

PORT_LIST_FILE = BASE_DIR / "all_ports_list.txt"


# ============================================================================
# HTML LINK PARSER
# ============================================================================

class _LinkParser(HTMLParser):

    def __init__(self):
        super().__init__()
        self.links = []

    def handle_starttag(self, tag, attrs):

        if tag.lower() != "a":
            return

        href = dict(attrs).get("href")

        if href:
            self.links.append(href)


# ============================================================================
# TARGET NORMALIZATION
# ============================================================================

def normalize_target(target):
    """
    Accept:

        192.168.64.129
        localhost
        example.com
        http://127.0.0.1:8080/WebGoat
        https://example.com/app

    Returns a normalized target structure.
    """

    target = target.strip()

    if not target:
        return None

    # If the user supplied a URL without a scheme
    # such as:
    #
    # 127.0.0.1:8080/WebGoat
    #
    # treat it as HTTP.
    if "://" not in target:

        # Detect host:port/path
        if "/" in target:

            target = "http://" + target

        # Detect host:port
        elif re.match(r"^[^:]+:\d+$", target):

            target = "http://" + target

        else:
            # Plain IP/domain
            host = target

            return {
                "original": target,
                "host": host,
                "port": None,
                "scheme": None,
                "base_url": None,
                "path": None,
                "is_url": False
            }

    parsed = urlparse(target)

    if not parsed.hostname:
        return None

    scheme = parsed.scheme.lower()

    if scheme not in ("http", "https"):
        return None

    host = parsed.hostname

    if parsed.port:
        port = parsed.port

    elif scheme == "https":
        port = 443

    else:
        port = 80

    path = parsed.path or "/"

    if parsed.query:
        path += "?" + parsed.query

    base_url = f"{scheme}://{parsed.netloc}"

    return {
        "original": target,
        "host": host,
        "port": port,
        "scheme": scheme,
        "base_url": base_url,
        "path": path,
        "is_url": True
    }


# ============================================================================
# TARGET VALIDATION
# ============================================================================

def validate_target(target):

    normalized = normalize_target(target)

    if normalized is None:
        return False

    host = normalized["host"]

    try:

        ipaddress.ip_address(host)

        return True

    except ValueError:

        try:

            socket.gethostbyname(host)

            return True

        except socket.gaierror:

            return False


# ============================================================================
# PORT LIST
# ============================================================================

def load_scan_ports(port_file=PORT_LIST_FILE):

    ports = []
    seen = set()

    path = Path(port_file)

    if not path.exists():

        raise FileNotFoundError(
            f"Port list file not found: {path}"
        )

    for line in path.read_text(
        encoding="utf-8"
    ).splitlines():

        stripped = line.strip()

        if not stripped:
            continue

        # Example:
        #
        # Range: 1 to 1000
        #
        range_match = re.match(
            r"^Range:\s*(\d{1,5})\s+to\s+(\d{1,5})",
            stripped,
            re.IGNORECASE
        )

        if range_match:

            start = int(range_match.group(1))
            end = int(range_match.group(2))

            if start == 0:
                start = 1

            if 1 <= start <= end <= 65535:

                value = f"{start}-{end}"

                if value not in seen:

                    ports.append(value)

                    seen.add(value)

            continue

        # Normal port line
        port_match = re.match(
            r"^(\d{1,5})\s+",
            stripped
        )

        if not port_match:
            continue

        port = int(port_match.group(1))

        if 1 <= port <= 65535 and port not in seen:

            ports.append(port)

            seen.add(port)

    if not ports:

        raise ValueError(
            f"No valid ports found in port list file: {path}"
        )

    return ports


# ============================================================================
# NMAP SCANNING
# ============================================================================

def scan_ports_nmap(
    target,
    ports=None,
    timeout=5
):

    nm = nmap.PortScanner()

    if ports is None:

        ports = "1-1000"

    elif isinstance(ports, list):

        converted = []

        for port in ports:

            converted.append(str(port))

        ports = ",".join(converted)

    try:

        scan_args = (
            f"-sV -T4 -p {ports}"
        )

        print(
            f"[*] Scanning {target} with Nmap..."
        )

        nm.scan(
            hosts=target,
            arguments=scan_args
        )

        open_ports = []
        services = []

        for host in nm.all_hosts():

            for proto in nm[host].all_protocols():

                ports_info = nm[host][proto]

                for port, info in ports_info.items():

                    if info["state"] != "open":
                        continue

                    open_ports.append(port)

                    services.append({

                        "port": port,

                        "service": info.get(
                            "name",
                            "Unknown"
                        ),

                        "product": info.get(
                            "product",
                            ""
                        ),

                        "version": info.get(
                            "version",
                            ""
                        ),

                        "banner": info.get(
                            "banner",
                            ""
                        ),

                        "extra": info.get(
                            "extrainfo",
                            ""
                        )

                    })

        return open_ports, services

    except nmap.PortScannerError as e:

        print(f"[-] Nmap Error: {e}")

        return [], []

    except Exception as e:

        print(f"[-] Error: {e}")

        return [], []


# ============================================================================
# HTTP SERVICE DETECTION
# ============================================================================

def detect_http(
    normalized_target,
    open_ports,
    services
):

    web_services = []

    requested_scheme = normalized_target["scheme"]
    requested_port = normalized_target["port"]
    requested_path = normalized_target["path"] or "/"

    original_url = normalized_target["original"]

    # ------------------------------------------------------------------------
    # URL target
    # ------------------------------------------------------------------------

    if normalized_target["is_url"]:

        # If the requested port is actually open, use the original URL.
        if requested_port in open_ports:

            web_services.append({

                "scheme": requested_scheme,

                "url": original_url,

                "host": normalized_target["host"],

                "port": requested_port,

                "source": "user-supplied URL"

            })

            return web_services

    # ------------------------------------------------------------------------
    # Detect HTTP services from Nmap
    # ------------------------------------------------------------------------

    for service in services:

        port = service["port"]

        service_name = (
            service.get("service") or ""
        ).lower()

        product = (
            service.get("product") or ""
        ).lower()

        banner = (
            service.get("banner") or ""
        ).lower()

        extra = (
            service.get("extra") or ""
        ).lower()

        combined = " ".join([
            service_name,
            product,
            banner,
            extra
        ])

        is_http = False

        if "http" in service_name:
            is_http = True

        elif "http" in product:
            is_http = True

        elif "apache" in product:
            is_http = True

        elif "nginx" in product:
            is_http = True

        elif "http" in combined:
            is_http = True

        # Common HTTP ports as fallback
        elif port in (
            80,
            81,
            3000,
            5000,
            8000,
            8080,
            8081,
            8088,
            8888,
            9000,
            9090,
            9443
        ):
            is_http = True

        if not is_http:
            continue

        # Determine scheme
        if port == 443 or port == 9443:

            scheme = "https"

        else:

            scheme = "http"

        # If this is the requested URL's port,
        # preserve its path.
        if (
            normalized_target["is_url"]
            and port == requested_port
        ):

            url = original_url

        else:

            host = normalized_target["host"]

            default_port = (
                (scheme == "http" and port == 80)
                or
                (scheme == "https" and port == 443)
            )

            if default_port:

                base = f"{scheme}://{host}"

            else:

                base = (
                    f"{scheme}://"
                    f"{host}:{port}"
                )

            url = base + "/"

        web_services.append({

            "scheme": scheme,

            "url": url,

            "host": normalized_target["host"],

            "port": port,

            "source": "Nmap service detection"

        })

    # Remove duplicates
    unique = {}

    for web in web_services:

        key = web["url"]

        unique[key] = web

    return list(unique.values())


# ============================================================================
# HTTP RECON
# ============================================================================

def http_recon(
    url,
    timeout=5
):

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

        response = requests.get(

            url,

            timeout=timeout,

            allow_redirects=True

        )

        result["url"] = response.url

        result["status_code"] = (
            response.status_code
        )

        result["headers"] = dict(
            response.headers
        )

        result["server"] = (
            response.headers.get("Server")
        )

        result["powered_by"] = (
            response.headers.get(
                "X-Powered-By"
            )
        )

        result["content_type"] = (
            response.headers.get(
                "Content-Type"
            )
        )

    except requests.RequestException as e:

        result["error"] = str(e)

    return result


# ============================================================================
# ENDPOINT CRAWLING
# ============================================================================

def crawl_endpoints(
    url,
    timeout=5
):

    endpoints = set()

    try:

        response = requests.get(

            url,

            timeout=timeout,

            allow_redirects=True

        )

        base_url = response.url

        parsed_base = urlparse(
            base_url
        )

        endpoints.add(base_url)

        parser = _LinkParser()

        parser.feed(
            response.text
        )

        for href in parser.links:

            full_url = urljoin(
                base_url,
                href
            )

            parsed_url = urlparse(
                full_url
            )

            if (
                parsed_url.netloc
                == parsed_base.netloc
            ):

                endpoints.add(full_url)

    except requests.RequestException:

        pass

    return sorted(endpoints)


# ============================================================================
# OS CLUES
# ============================================================================

def detect_os_clues(
    services,
    http_results
):

    clues = []

    # ------------------------------------------------------------------------
    # Nmap clues
    # ------------------------------------------------------------------------

    for service in services:

        banner = (
            service.get(
                "banner",
                ""
            ) or ""
        ).lower()

        product = (
            service.get(
                "product",
                ""
            ) or ""
        ).lower()

        version = (
            service.get(
                "version",
                ""
            ) or ""
        ).lower()

        combined = " ".join([
            banner,
            product,
            version
        ])

        # Windows
        if "windows" in combined:

            clues.append({

                "os_family": "Windows",

                "os_clue": "Windows",

                "confidence": "High",

                "source":
                    f"Nmap - {service['service']}"

            })

        # Ubuntu
        elif "ubuntu" in combined:

            clues.append({

                "os_family": "Linux",

                "os_clue": "Ubuntu",

                "confidence": "High",

                "source":
                    f"Nmap - {service['service']}"

            })

        # Debian
        elif "debian" in combined:

            clues.append({

                "os_family": "Linux",

                "os_clue": "Debian",

                "confidence": "High",

                "source":
                    f"Nmap - {service['service']}"

            })

        # Generic Linux
        elif "linux" in combined:

            clues.append({

                "os_family": "Linux",

                "os_clue": "Linux (generic)",

                "confidence": "Medium",

                "source":
                    f"Nmap - {service['service']}"

            })

    # ------------------------------------------------------------------------
    # HTTP clues
    # ------------------------------------------------------------------------

    for http_info in http_results:

        server = (
            http_info.get(
                "server"
            ) or ""
        ).lower()

        powered_by = (
            http_info.get(
                "powered_by"
            ) or ""
        ).lower()

        combined = (
            server + " " + powered_by
        )

        if "ubuntu" in combined:

            clues.append({

                "os_family": "Linux",

                "os_clue": "Ubuntu",

                "confidence": "Medium",

                "source":
                    "HTTP headers"

            })

        elif "debian" in combined:

            clues.append({

                "os_family": "Linux",

                "os_clue": "Debian",

                "confidence": "Medium",

                "source":
                    "HTTP headers"

            })

    return clues


# ============================================================================
# MAIN RECON FUNCTION
# ============================================================================

def run_recon_scan(target):

    result = {

        "module": "recon",

        "target": target,

        "status": "success",

        "normalized_target": None,

        "port_source": str(
            PORT_LIST_FILE
        ),

        "ports_scanned": [],

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

    # ========================================================================
    # NORMALIZE TARGET
    # ========================================================================

    normalized = normalize_target(
        target
    )

    if normalized is None:

        result["status"] = "error"

        result["errors"].append(
            "Invalid target format"
        )

        return result

    result[
        "normalized_target"
    ] = normalized

    # ========================================================================
    # VALIDATE HOST
    # ========================================================================

    if not validate_target(target):

        result["status"] = "error"

        result["errors"].append(
            "Invalid target or hostname"
        )

        return result

    host = normalized["host"]

    # ========================================================================
    # LOAD PORT LIST
    # ========================================================================

    try:

        ports = load_scan_ports()

    except (OSError, ValueError) as error:

        result["status"] = "error"

        result["errors"].append(
            str(error)
        )

        return result

    # ========================================================================
    # IMPORTANT:
    #
    # If the user supplied a URL with a custom port such as:
    #
    # http://127.0.0.1:8080/WebGoat
    #
    # make sure that port is scanned even if it is not present in the
    # configured port file.
    # ========================================================================

    if normalized["is_url"]:

        requested_port = normalized["port"]

        if requested_port not in ports:

            ports.append(
                requested_port
            )

    result[
        "ports_scanned"
    ] = ports

    # ========================================================================
    # NMAP
    # ========================================================================

    open_ports, services = scan_ports_nmap(
        host,
        ports
    )

    result["ports"] = open_ports

    result["services"] = services

    # ========================================================================
    # NO OPEN PORTS
    # ========================================================================

    if not open_ports:

        # For a URL target, we distinguish between:
        #
        # "target invalid"
        #
        # and
        #
        # "host reachable but requested service unavailable".

        result["host"]["reachable"] = False

        result["status"] = "error"

        if normalized["is_url"]:

            result["errors"].append(

                "No open ports found on "
                f"{host}; requested web port "
                f"{normalized['port']} "
                "may be unavailable."

            )

        else:

            result["errors"].append(
                "No open ports found"
            )

        return result

    # ========================================================================
    # HOST IS REACHABLE
    # ========================================================================

    result[
        "host"
    ]["reachable"] = True

    # ========================================================================
    # WEB SERVICES
    # ========================================================================

    web_services = detect_http(

        normalized,

        open_ports,

        services

    )

    result[
        "web_services"
    ] = web_services

    # ========================================================================
    # HTTP RECON
    # ========================================================================

    http_results = []

    for web in web_services:

        http_info = http_recon(
            web["url"]
        )

        http_results.append(
            http_info
        )

        endpoints = crawl_endpoints(
            web["url"]
        )

        result[
            "endpoints"
        ].extend(endpoints)

    result[
        "http_results"
    ] = http_results

    result[
        "endpoints"
    ] = sorted(
        set(
            result["endpoints"]
        )
    )

    # ========================================================================
    # OS CLUES
    # ========================================================================

    os_clues = detect_os_clues(

        services,

        http_results

    )

    result[
        "host"
    ]["os_clues"] = os_clues

    return result


# ============================================================================
# STANDALONE TEST
# ============================================================================

if __name__ == "__main__":

    target = input(
        "Enter target IP, domain, or URL: "
    ).strip()

    print(
        f"[+] Target: {target}"
    )

    recon_data = run_recon_scan(
        target
    )

    print(
        "\n=============================================================================="
    )

    print(
        "RECON MODULE"
    )

    print(
        "=============================================================================="
    )

    print(
        f"Status: {recon_data['status']}"
    )

    print(
        f"Target: {recon_data['target']}"
    )

    # ------------------------------------------------------------------------
    # Normalized Target
    # ------------------------------------------------------------------------

    normalized = (
        recon_data.get(
            "normalized_target"
        )
    )

    if normalized:

        print(
            "\nTarget Normalization:"
        )

        print(
            f"    Host: "
            f"{normalized['host']}"
        )

        print(
            f"    Port: "
            f"{normalized['port']}"
        )

        print(
            f"    Scheme: "
            f"{normalized['scheme']}"
        )

        print(
            f"    Path: "
            f"{normalized['path']}"
        )

        print(
            f"    URL Target: "
            f"{normalized['is_url']}"
        )

    # ------------------------------------------------------------------------
    # Errors
    # ------------------------------------------------------------------------

    if recon_data["errors"]:

        print(
            "\nErrors:"
        )

        for error in recon_data["errors"]:

            print(
                f"    - {error}"
            )

    # ------------------------------------------------------------------------
    # Host
    # ------------------------------------------------------------------------

    print(
        "\nHost Reachability:"
    )

    print(
        f"    Reachable: "
        f"{recon_data['host']['reachable']}"
    )

    # ------------------------------------------------------------------------
    # Ports
    # ------------------------------------------------------------------------

    print(
        "\nPort Scan Configuration:"
    )

    print(
        f"    Source: "
        f"{recon_data['port_source']}"
    )

    print(
        f"    Ports configured: "
        f"{len(recon_data['ports_scanned'])}"
    )

    print(
        "\nOpen Ports:"
    )

    if recon_data["ports"]:

        for port in recon_data["ports"]:

            print(
                f"    - {port}"
            )

    else:

        print(
            "    No open ports found."
        )

    # ------------------------------------------------------------------------
    # Services
    # ------------------------------------------------------------------------

    print(
        "\nService Detection:"
    )

    if recon_data["services"]:

        for service in recon_data["services"]:

            print(
                f"\n    Port: "
                f"{service['port']}"
            )

            print(
                f"    Service: "
                f"{service['service']}"
            )

            if service.get("product"):

                print(
                    f"    Product: "
                    f"{service['product']}"
                )

            if service.get("version"):

                print(
                    f"    Version: "
                    f"{service['version']}"
                )

            if service.get("banner"):

                print(
                    f"    Banner: "
                    f"{service['banner']}"
                )

            if service.get("extra"):

                print(
                    f"    Extra: "
                    f"{service['extra']}"
                )

    else:

        print(
            "    No services detected."
        )

    # ------------------------------------------------------------------------
    # Web Services
    # ------------------------------------------------------------------------

    print(
        "\nWeb Services:"
    )

    if recon_data["web_services"]:

        for web in recon_data["web_services"]:

            print(
                f"    {web['scheme'].upper()} "
                f"-> {web['url']}"
            )

            print(
                f"       Port: "
                f"{web['port']}"
            )

            print(
                f"       Source: "
                f"{web['source']}"
            )

    else:

        print(
            "    No web services found."
        )

    # ------------------------------------------------------------------------
    # HTTP Recon
    # ------------------------------------------------------------------------

    print(
        "\nHTTP Recon:"
    )

    if recon_data["http_results"]:

        for http_info in recon_data[
            "http_results"
        ]:

            print(
                f"\n    URL: "
                f"{http_info['url']}"
            )

            print(
                f"    Status Code: "
                f"{http_info['status_code']}"
            )

            print(
                f"    Server: "
                f"{http_info['server']}"
            )

            print(
                f"    X-Powered-By: "
                f"{http_info['powered_by']}"
            )

            print(
                f"    Content-Type: "
                f"{http_info['content_type']}"
            )

            if http_info["error"]:

                print(
                    f"    Error: "
                    f"{http_info['error']}"
                )

    else:

        print(
            "    No HTTP information collected."
        )

    # ------------------------------------------------------------------------
    # Endpoints
    # ------------------------------------------------------------------------

    print(
        "\nEndpoint Crawling:"
    )

    if recon_data["endpoints"]:

        for endpoint in recon_data[
            "endpoints"
        ]:

            print(
                f"    - {endpoint}"
            )

    else:

        print(
            "    No endpoints found."
        )

    # ------------------------------------------------------------------------
    # OS Clues
    # ------------------------------------------------------------------------

    print(
        "\nOS Clues:"
    )

    if recon_data[
        "host"
    ]["os_clues"]:

        for clue in recon_data[
            "host"
        ]["os_clues"]:

            print(
                f"    OS Family: "
                f"{clue['os_family']}"
            )

            print(
                f"    OS Clue: "
                f"{clue['os_clue']}"
            )

            print(
                f"    Confidence: "
                f"{clue['confidence']}"
            )

            print(
                f"    Source: "
                f"{clue['source']}"
            )

    else:

        print(
            "    No OS clues found."
        )
import nmap
import requests
import ipaddress
import socket
import re

from html.parser import HTMLParser
from pathlib import Path
from urllib.parse import urljoin, urlparse


# ============================================================================
# CONFIGURATION
# ============================================================================

BASE_DIR = Path(__file__).resolve().parent.parent

PORT_LIST_FILE = BASE_DIR / "all_ports_list.txt"


# ============================================================================
# HTML LINK PARSER
# ============================================================================

class _LinkParser(HTMLParser):

    def __init__(self):
        super().__init__()
        self.links = []

    def handle_starttag(self, tag, attrs):

        if tag.lower() != "a":
            return

        href = dict(attrs).get("href")

        if href:
            self.links.append(href)


# ============================================================================
# TARGET NORMALIZATION
# ============================================================================

def normalize_target(target):
    """
    Accept:

        192.168.64.129
        localhost
        example.com
        http://127.0.0.1:8080/WebGoat
        https://example.com/app

    Returns a normalized target structure.
    """

    target = target.strip()

    if not target:
        return None

    # If the user supplied a URL without a scheme
    # such as:
    #
    # 127.0.0.1:8080/WebGoat
    #
    # treat it as HTTP.
    if "://" not in target:

        # Detect host:port/path
        if "/" in target:

            target = "http://" + target

        # Detect host:port
        elif re.match(r"^[^:]+:\d+$", target):

            target = "http://" + target

        else:
            # Plain IP/domain
            host = target

            return {
                "original": target,
                "host": host,
                "port": None,
                "scheme": None,
                "base_url": None,
                "path": None,
                "is_url": False
            }

    parsed = urlparse(target)

    if not parsed.hostname:
        return None

    scheme = parsed.scheme.lower()

    if scheme not in ("http", "https"):
        return None

    host = parsed.hostname

    if parsed.port:
        port = parsed.port

    elif scheme == "https":
        port = 443

    else:
        port = 80

    path = parsed.path or "/"

    if parsed.query:
        path += "?" + parsed.query

    base_url = f"{scheme}://{parsed.netloc}"

    return {
        "original": target,
        "host": host,
        "port": port,
        "scheme": scheme,
        "base_url": base_url,
        "path": path,
        "is_url": True
    }


# ============================================================================
# TARGET VALIDATION
# ============================================================================

def validate_target(target):

    normalized = normalize_target(target)

    if normalized is None:
        return False

    host = normalized["host"]

    try:

        ipaddress.ip_address(host)

        return True

    except ValueError:

        try:

            socket.gethostbyname(host)

            return True

        except socket.gaierror:

            return False


# ============================================================================
# PORT LIST
# ============================================================================

def load_scan_ports(port_file=PORT_LIST_FILE):

    ports = []
    seen = set()

    path = Path(port_file)

    if not path.exists():

        raise FileNotFoundError(
            f"Port list file not found: {path}"
        )

    for line in path.read_text(
        encoding="utf-8"
    ).splitlines():

        stripped = line.strip()

        if not stripped:
            continue

        # Example:
        #
        # Range: 1 to 1000
        #
        range_match = re.match(
            r"^Range:\s*(\d{1,5})\s+to\s+(\d{1,5})",
            stripped,
            re.IGNORECASE
        )

        if range_match:

            start = int(range_match.group(1))
            end = int(range_match.group(2))

            if start == 0:
                start = 1

            if 1 <= start <= end <= 65535:

                value = f"{start}-{end}"

                if value not in seen:

                    ports.append(value)

                    seen.add(value)

            continue

        # Normal port line
        port_match = re.match(
            r"^(\d{1,5})\s+",
            stripped
        )

        if not port_match:
            continue

        port = int(port_match.group(1))

        if 1 <= port <= 65535 and port not in seen:

            ports.append(port)

            seen.add(port)

    if not ports:

        raise ValueError(
            f"No valid ports found in port list file: {path}"
        )

    return ports


# ============================================================================
# NMAP SCANNING
# ============================================================================

def scan_ports_nmap(
    target,
    ports=None,
    timeout=5
):

    nm = nmap.PortScanner()

    if ports is None:

        ports = "1-1000"

    elif isinstance(ports, list):

        converted = []

        for port in ports:

            converted.append(str(port))

        ports = ",".join(converted)

    try:

        scan_args = (
            f"-sV -T4 -p {ports}"
        )

        print(
            f"[*] Scanning {target} with Nmap..."
        )

        nm.scan(
            hosts=target,
            arguments=scan_args
        )

        open_ports = []
        services = []

        for host in nm.all_hosts():

            for proto in nm[host].all_protocols():

                ports_info = nm[host][proto]

                for port, info in ports_info.items():

                    if info["state"] != "open":
                        continue

                    open_ports.append(port)

                    services.append({

                        "port": port,

                        "service": info.get(
                            "name",
                            "Unknown"
                        ),

                        "product": info.get(
                            "product",
                            ""
                        ),

                        "version": info.get(
                            "version",
                            ""
                        ),

                        "banner": info.get(
                            "banner",
                            ""
                        ),

                        "extra": info.get(
                            "extrainfo",
                            ""
                        )

                    })

        return open_ports, services

    except nmap.PortScannerError as e:

        print(f"[-] Nmap Error: {e}")

        return [], []

    except Exception as e:

        print(f"[-] Error: {e}")

        return [], []


# ============================================================================
# HTTP SERVICE DETECTION
# ============================================================================

def detect_http(
    normalized_target,
    open_ports,
    services
):

    web_services = []

    requested_scheme = normalized_target["scheme"]
    requested_port = normalized_target["port"]
    requested_path = normalized_target["path"] or "/"

    original_url = normalized_target["original"]

    # ------------------------------------------------------------------------
    # URL target
    # ------------------------------------------------------------------------

    if normalized_target["is_url"]:

        # If the requested port is actually open, use the original URL.
        if requested_port in open_ports:

            web_services.append({

                "scheme": requested_scheme,

                "url": original_url,

                "host": normalized_target["host"],

                "port": requested_port,

                "source": "user-supplied URL"

            })

            return web_services

    # ------------------------------------------------------------------------
    # Detect HTTP services from Nmap
    # ------------------------------------------------------------------------

    for service in services:

        port = service["port"]

        service_name = (
            service.get("service") or ""
        ).lower()

        product = (
            service.get("product") or ""
        ).lower()

        banner = (
            service.get("banner") or ""
        ).lower()

        extra = (
            service.get("extra") or ""
        ).lower()

        combined = " ".join([
            service_name,
            product,
            banner,
            extra
        ])

        is_http = False

        if "http" in service_name:
            is_http = True

        elif "http" in product:
            is_http = True

        elif "apache" in product:
            is_http = True

        elif "nginx" in product:
            is_http = True

        elif "http" in combined:
            is_http = True

        # Common HTTP ports as fallback
        elif port in (
            80,
            81,
            3000,
            5000,
            8000,
            8080,
            8081,
            8088,
            8888,
            9000,
            9090,
            9443
        ):
            is_http = True

        if not is_http:
            continue

        # Determine scheme
        if port == 443 or port == 9443:

            scheme = "https"

        else:

            scheme = "http"

        # If this is the requested URL's port,
        # preserve its path.
        if (
            normalized_target["is_url"]
            and port == requested_port
        ):

            url = original_url

        else:

            host = normalized_target["host"]

            default_port = (
                (scheme == "http" and port == 80)
                or
                (scheme == "https" and port == 443)
            )

            if default_port:

                base = f"{scheme}://{host}"

            else:

                base = (
                    f"{scheme}://"
                    f"{host}:{port}"
                )

            url = base + "/"

        web_services.append({

            "scheme": scheme,

            "url": url,

            "host": normalized_target["host"],

            "port": port,

            "source": "Nmap service detection"

        })

    # Remove duplicates
    unique = {}

    for web in web_services:

        key = web["url"]

        unique[key] = web

    return list(unique.values())


# ============================================================================
# HTTP RECON
# ============================================================================

def http_recon(
    url,
    timeout=5
):

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

        response = requests.get(

            url,

            timeout=timeout,

            allow_redirects=True

        )

        result["url"] = response.url

        result["status_code"] = (
            response.status_code
        )

        result["headers"] = dict(
            response.headers
        )

        result["server"] = (
            response.headers.get("Server")
        )

        result["powered_by"] = (
            response.headers.get(
                "X-Powered-By"
            )
        )

        result["content_type"] = (
            response.headers.get(
                "Content-Type"
            )
        )

    except requests.RequestException as e:

        result["error"] = str(e)

    return result


# ============================================================================
# ENDPOINT CRAWLING
# ============================================================================

def crawl_endpoints(
    url,
    timeout=5
):

    endpoints = set()

    try:

        response = requests.get(

            url,

            timeout=timeout,

            allow_redirects=True

        )

        base_url = response.url

        parsed_base = urlparse(
            base_url
        )

        endpoints.add(base_url)

        parser = _LinkParser()

        parser.feed(
            response.text
        )

        for href in parser.links:

            full_url = urljoin(
                base_url,
                href
            )

            parsed_url = urlparse(
                full_url
            )

            if (
                parsed_url.netloc
                == parsed_base.netloc
            ):

                endpoints.add(full_url)

    except requests.RequestException:

        pass

    return sorted(endpoints)


# ============================================================================
# OS CLUES
# ============================================================================

def detect_os_clues(
    services,
    http_results
):

    clues = []

    # ------------------------------------------------------------------------
    # Nmap clues
    # ------------------------------------------------------------------------

    for service in services:

        banner = (
            service.get(
                "banner",
                ""
            ) or ""
        ).lower()

        product = (
            service.get(
                "product",
                ""
            ) or ""
        ).lower()

        version = (
            service.get(
                "version",
                ""
            ) or ""
        ).lower()

        combined = " ".join([
            banner,
            product,
            version
        ])

        # Windows
        if "windows" in combined:

            clues.append({

                "os_family": "Windows",

                "os_clue": "Windows",

                "confidence": "High",

                "source":
                    f"Nmap - {service['service']}"

            })

        # Ubuntu
        elif "ubuntu" in combined:

            clues.append({

                "os_family": "Linux",

                "os_clue": "Ubuntu",

                "confidence": "High",

                "source":
                    f"Nmap - {service['service']}"

            })

        # Debian
        elif "debian" in combined:

            clues.append({

                "os_family": "Linux",

                "os_clue": "Debian",

                "confidence": "High",

                "source":
                    f"Nmap - {service['service']}"

            })

        # Generic Linux
        elif "linux" in combined:

            clues.append({

                "os_family": "Linux",

                "os_clue": "Linux (generic)",

                "confidence": "Medium",

                "source":
                    f"Nmap - {service['service']}"

            })

    # ------------------------------------------------------------------------
    # HTTP clues
    # ------------------------------------------------------------------------

    for http_info in http_results:

        server = (
            http_info.get(
                "server"
            ) or ""
        ).lower()

        powered_by = (
            http_info.get(
                "powered_by"
            ) or ""
        ).lower()

        combined = (
            server + " " + powered_by
        )

        if "ubuntu" in combined:

            clues.append({

                "os_family": "Linux",

                "os_clue": "Ubuntu",

                "confidence": "Medium",

                "source":
                    "HTTP headers"

            })

        elif "debian" in combined:

            clues.append({

                "os_family": "Linux",

                "os_clue": "Debian",

                "confidence": "Medium",

                "source":
                    "HTTP headers"

            })

    return clues


# ============================================================================
# MAIN RECON FUNCTION
# ============================================================================

def run_recon_scan(target):

    result = {

        "module": "recon",

        "target": target,

        "status": "success",

        "normalized_target": None,

        "port_source": str(
            PORT_LIST_FILE
        ),

        "ports_scanned": [],

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

    # ========================================================================
    # NORMALIZE TARGET
    # ========================================================================

    normalized = normalize_target(
        target
    )

    if normalized is None:

        result["status"] = "error"

        result["errors"].append(
            "Invalid target format"
        )

        return result

    result[
        "normalized_target"
    ] = normalized

    # ========================================================================
    # VALIDATE HOST
    # ========================================================================

    if not validate_target(target):

        result["status"] = "error"

        result["errors"].append(
            "Invalid target or hostname"
        )

        return result

    host = normalized["host"]

    # ========================================================================
    # LOAD PORT LIST
    # ========================================================================

    try:

        ports = load_scan_ports()

    except (OSError, ValueError) as error:

        result["status"] = "error"

        result["errors"].append(
            str(error)
        )

        return result

    # ========================================================================
    # IMPORTANT:
    #
    # If the user supplied a URL with a custom port such as:
    #
    # http://127.0.0.1:8080/WebGoat
    #
    # make sure that port is scanned even if it is not present in the
    # configured port file.
    # ========================================================================

    if normalized["is_url"]:

        requested_port = normalized["port"]

        if requested_port not in ports:

            ports.append(
                requested_port
            )

    result[
        "ports_scanned"
    ] = ports

    # ========================================================================
    # NMAP
    # ========================================================================

    open_ports, services = scan_ports_nmap(
        host,
        ports
    )

    result["ports"] = open_ports

    result["services"] = services

    # ========================================================================
    # NO OPEN PORTS
    # ========================================================================

    if not open_ports:

        # For a URL target, we distinguish between:
        #
        # "target invalid"
        #
        # and
        #
        # "host reachable but requested service unavailable".

        result["host"]["reachable"] = False

        result["status"] = "error"

        if normalized["is_url"]:

            result["errors"].append(

                "No open ports found on "
                f"{host}; requested web port "
                f"{normalized['port']} "
                "may be unavailable."

            )

        else:

            result["errors"].append(
                "No open ports found"
            )

        return result

    # ========================================================================
    # HOST IS REACHABLE
    # ========================================================================

    result[
        "host"
    ]["reachable"] = True

    # ========================================================================
    # WEB SERVICES
    # ========================================================================

    web_services = detect_http(

        normalized,

        open_ports,

        services

    )

    result[
        "web_services"
    ] = web_services

    # ========================================================================
    # HTTP RECON
    # ========================================================================

    http_results = []

    for web in web_services:

        http_info = http_recon(
            web["url"]
        )

        http_results.append(
            http_info
        )

        endpoints = crawl_endpoints(
            web["url"]
        )

        result[
            "endpoints"
        ].extend(endpoints)

    result[
        "http_results"
    ] = http_results

    result[
        "endpoints"
    ] = sorted(
        set(
            result["endpoints"]
        )
    )

    # ========================================================================
    # OS CLUES
    # ========================================================================

    os_clues = detect_os_clues(

        services,

        http_results

    )

    result[
        "host"
    ]["os_clues"] = os_clues

    return result


# ============================================================================
# STANDALONE TEST
# ============================================================================

if __name__ == "__main__":

    target = input(
        "Enter target IP, domain, or URL: "
    ).strip()

    print(
        f"[+] Target: {target}"
    )

    recon_data = run_recon_scan(
        target
    )

    print(
        "\n=============================================================================="
    )

    print(
        "RECON MODULE"
    )

    print(
        "=============================================================================="
    )

    print(
        f"Status: {recon_data['status']}"
    )

    print(
        f"Target: {recon_data['target']}"
    )

    # ------------------------------------------------------------------------
    # Normalized Target
    # ------------------------------------------------------------------------

    normalized = (
        recon_data.get(
            "normalized_target"
        )
    )

    if normalized:

        print(
            "\nTarget Normalization:"
        )

        print(
            f"    Host: "
            f"{normalized['host']}"
        )

        print(
            f"    Port: "
            f"{normalized['port']}"
        )

        print(
            f"    Scheme: "
            f"{normalized['scheme']}"
        )

        print(
            f"    Path: "
            f"{normalized['path']}"
        )

        print(
            f"    URL Target: "
            f"{normalized['is_url']}"
        )

    # ------------------------------------------------------------------------
    # Errors
    # ------------------------------------------------------------------------

    if recon_data["errors"]:

        print(
            "\nErrors:"
        )

        for error in recon_data["errors"]:

            print(
                f"    - {error}"
            )

    # ------------------------------------------------------------------------
    # Host
    # ------------------------------------------------------------------------

    print(
        "\nHost Reachability:"
    )

    print(
        f"    Reachable: "
        f"{recon_data['host']['reachable']}"
    )

    # ------------------------------------------------------------------------
    # Ports
    # ------------------------------------------------------------------------

    print(
        "\nPort Scan Configuration:"
    )

    print(
        f"    Source: "
        f"{recon_data['port_source']}"
    )

    print(
        f"    Ports configured: "
        f"{len(recon_data['ports_scanned'])}"
    )

    print(
        "\nOpen Ports:"
    )

    if recon_data["ports"]:

        for port in recon_data["ports"]:

            print(
                f"    - {port}"
            )

    else:

        print(
            "    No open ports found."
        )

    # ------------------------------------------------------------------------
    # Services
    # ------------------------------------------------------------------------

    print(
        "\nService Detection:"
    )

    if recon_data["services"]:

        for service in recon_data["services"]:

            print(
                f"\n    Port: "
                f"{service['port']}"
            )

            print(
                f"    Service: "
                f"{service['service']}"
            )

            if service.get("product"):

                print(
                    f"    Product: "
                    f"{service['product']}"
                )

            if service.get("version"):

                print(
                    f"    Version: "
                    f"{service['version']}"
                )

            if service.get("banner"):

                print(
                    f"    Banner: "
                    f"{service['banner']}"
                )

            if service.get("extra"):

                print(
                    f"    Extra: "
                    f"{service['extra']}"
                )

    else:

        print(
            "    No services detected."
        )

    # ------------------------------------------------------------------------
    # Web Services
    # ------------------------------------------------------------------------

    print(
        "\nWeb Services:"
    )

    if recon_data["web_services"]:

        for web in recon_data["web_services"]:

            print(
                f"    {web['scheme'].upper()} "
                f"-> {web['url']}"
            )

            print(
                f"       Port: "
                f"{web['port']}"
            )

            print(
                f"       Source: "
                f"{web['source']}"
            )

    else:

        print(
            "    No web services found."
        )

    # ------------------------------------------------------------------------
    # HTTP Recon
    # ------------------------------------------------------------------------

    print(
        "\nHTTP Recon:"
    )

    if recon_data["http_results"]:

        for http_info in recon_data[
            "http_results"
        ]:

            print(
                f"\n    URL: "
                f"{http_info['url']}"
            )

            print(
                f"    Status Code: "
                f"{http_info['status_code']}"
            )

            print(
                f"    Server: "
                f"{http_info['server']}"
            )

            print(
                f"    X-Powered-By: "
                f"{http_info['powered_by']}"
            )

            print(
                f"    Content-Type: "
                f"{http_info['content_type']}"
            )

            if http_info["error"]:

                print(
                    f"    Error: "
                    f"{http_info['error']}"
                )

    else:

        print(
            "    No HTTP information collected."
        )

    # ------------------------------------------------------------------------
    # Endpoints
    # ------------------------------------------------------------------------

    print(
        "\nEndpoint Crawling:"
    )

    if recon_data["endpoints"]:

        for endpoint in recon_data[
            "endpoints"
        ]:

            print(
                f"    - {endpoint}"
            )

    else:

        print(
            "    No endpoints found."
        )

    # ------------------------------------------------------------------------
    # OS Clues
    # ------------------------------------------------------------------------

    print(
        "\nOS Clues:"
    )

    if recon_data[
        "host"
    ]["os_clues"]:

        for clue in recon_data[
            "host"
        ]["os_clues"]:

            print(
                f"    OS Family: "
                f"{clue['os_family']}"
            )

            print(
                f"    OS Clue: "
                f"{clue['os_clue']}"
            )

            print(
                f"    Confidence: "
                f"{clue['confidence']}"
            )

            print(
                f"    Source: "
                f"{clue['source']}"
            )

    else:

        print(
            "    No OS clues found."
        )