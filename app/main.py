import socket
import os
import requests
from flask import Flask, jsonify, request
from flask_swagger_ui import get_swaggerui_blueprint
from flask_cors import CORS
from bs4 import BeautifulSoup
import dns.resolver

app = Flask(__name__)

# Swagger configuration
SWAGGER_URL = '/swagger'
API_URL = '/static/swagger.json'  # Swagger JSON URL
swaggerui_blueprint = get_swaggerui_blueprint(
    SWAGGER_URL,
    API_URL,
    config={'app_name': "BugHunter"}
)
app.register_blueprint(swaggerui_blueprint, url_prefix=SWAGGER_URL)

# Enable CORS
CORS(app)

# Helper functions
COMMON_SERVICES = {
    21: 'FTP',
    22: 'SSH',
    23: 'Telnet',
    25: 'SMTP',
    53: 'DNS',
    80: 'HTTP',
    110: 'POP3',
    143: 'IMAP',
    443: 'HTTPS',
    3306: 'MySQL',
    5432: 'PostgreSQL',
    6379: 'Redis',
    8080: 'HTTP-alt'
}


def identify_service(port):
    """Identify the common service running on a port."""
    return COMMON_SERVICES.get(port, 'Unknown')


def advanced_port_scan(target, ports):
    """Perform an advanced port scan to detect open ports, services, and versions."""
    results = {}
    for port in ports:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(1)
                result = s.connect_ex((target, port))
                if result == 0:  # Port is open
                    service = identify_service(port)
                    results[port] = {
                        "status": "open",
                        "service": service
                    }
                else:
                    results[port] = {"status": "closed"}
        except Exception as e:
            results[port] = {"status": "error", "message": str(e)}
    return results


def fetch_cve_data(software):
    """Fetch vulnerability data from the NIST NVD API or Vulners."""
    try:
        # Placeholder for an actual API call
        vulnerabilities = [
            {"id": "CVE-2022-12345", "description": "Sample vulnerability for testing."}
        ]
        return vulnerabilities
    except Exception as e:
        return {"error": str(e)}


def crawl_website(target):
    """Crawl a website to find pages."""
    try:
        response = requests.get(target)
        soup = BeautifulSoup(response.text, 'html.parser')
        links = [a['href'] for a in soup.find_all('a', href=True)]
        return links
    except Exception as e:
        return {"error": str(e)}


def detect_web_vulnerabilities(target):
    """Detect web application vulnerabilities."""
    vulnerabilities = []
    # SQL Injection example
    payload = "' OR 1=1 --"
    try:
        response = requests.get(target, params={'q': payload})
        if "syntax error" in response.text.lower():
            vulnerabilities.append({
                "type": "SQL Injection",
                "details": f"Possible vulnerability detected with payload: {payload}"
            })
    except Exception:
        pass
    # Additional checks (e.g., XSS, Directory Traversal) can be added here.
    return vulnerabilities


def find_active_subdomains(domain):
    """Find active subdomains."""
    subdomains = ["www", "mail", "ftp", "test", "admin"]
    active_subdomains = []
    for sub in subdomains:
        full_domain = f"{sub}.{domain}"
        try:
            socket.gethostbyname(full_domain)
            active_subdomains.append(full_domain)
        except socket.gaierror:
            pass
    return active_subdomains


def detect_dns_insecure_config(domain):
    """Detect insecure DNS configurations."""
    insecure_records = []
    try:
        txt_records = dns.resolver.resolve(domain, 'TXT')
        for record in txt_records:
            record_data = record.to_text()
            if "v=spf1" in record_data:
                if "~all" in record_data or "-all" not in record_data:
                    insecure_records.append({
                        "type": "SPF",
                        "details": f"Insecure SPF record: {record_data}"
                    })
            if "dkim" in record_data.lower():
                if "v=DKIM1" not in record_data:
                    insecure_records.append({
                        "type": "DKIM",
                        "details": f"Potentially insecure DKIM record: {record_data}"
                    })
    except Exception as e:
        insecure_records.append({"error": str(e)})
    return insecure_records


# Endpoints
@app.route('/scan/ports', methods=['POST'])
def scan_ports_advanced():
    data = request.get_json()
    target = data.get('target')
    ports = data.get('ports')
    if not target or not ports:
        return jsonify({"error": "Missing 'target' or 'ports' in request body"}), 400
    try:
        results = advanced_port_scan(target, ports)
        return jsonify({"target": target, "results": results}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route('/scan/vulnerabilities', methods=['POST'])
def scan_vulnerabilities():
    data = request.get_json()
    software = data.get('software')
    if not software:
        return jsonify({"error": "Missing 'software' in request body"}), 400
    try:
        vulnerabilities = fetch_cve_data(software)
        return jsonify({"software": software, "vulnerabilities": vulnerabilities}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route('/scan/web', methods=['POST'])
def scan_web():
    data = request.get_json()
    target = data.get('target')
    if not target:
        return jsonify({"error": "Missing 'target' in request body"}), 400
    try:
        pages = crawl_website(target)
        vulnerabilities = detect_web_vulnerabilities(target)
        return jsonify({"target": target, "pages_crawled": pages, "vulnerabilities": vulnerabilities}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route('/scan/dns', methods=['POST'])
def scan_dns():
    data = request.get_json()
    domain = data.get('domain')
    if not domain:
        return jsonify({"error": "Missing 'domain' in request body"}), 400
    try:
        active_subdomains = find_active_subdomains(domain)
        insecure_dns = detect_dns_insecure_config(domain)
        return jsonify({
            "domain": domain,
            "active_subdomains": active_subdomains,
            "insecure_dns_records": insecure_dns
        }), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500


if __name__ == '__main__':
    app.run(debug=True)
