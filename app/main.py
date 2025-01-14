import ssl
import socket
import requests
import nmap
import dns.resolver
from flask import Flask, jsonify, request
from flask_swagger_ui import get_swaggerui_blueprint
from flask_cors import CORS
from bs4 import BeautifulSoup

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

# Helper function for port scanning
def port_scan(target):
    nm = nmap.PortScanner()
    nm.scan(hosts=target, arguments='-sS -p 1-65535')
    results = {}
    for host in nm.all_hosts():
        results[host] = {
            'state': nm[host].state(),
            'open_ports': []
        }
        for proto in nm[host].all_protocols():
            ports = nm[host][proto].keys()
            for port in ports:
                results[host]['open_ports'].append({
                    'port': port,
                    'state': nm[host][proto][port]['state']
                })
    return results

# Helper function for vulnerability scanning
def vulnerability_scan(version):
    url = f'https://services.nvd.nist.gov/rest/json/cves/1.0?keyword={version}'
    response = requests.get(url)
    if response.status_code == 200:
        return response.json()
    else:
        return {'error': 'Failed to fetch vulnerabilities'}

# Helper function for web scanning
def web_scan(url):
    try:
        response = requests.get(url)
        soup = BeautifulSoup(response.text, 'html.parser')
        vulnerabilities = []

        # Basic vulnerability checks
        if "<script>" in response.text:
            vulnerabilities.append("Potential XSS detected")

        if "SELECT * FROM" in response.text:
            vulnerabilities.append("Potential SQL Injection detected")

        return {
            'status': 'success',
            'pages': len(soup.find_all('a')),
            'vulnerabilities': vulnerabilities
        }
    except Exception as e:
        return {'error': str(e)}

# Helper function for DNS scanning
def dns_scan(domain):
    try:
        resolver = dns.resolver.Resolver()
        records = resolver.resolve(domain, 'A')
        results = {
            'A_records': [record.to_text() for record in records]
        }

        try:
            txt_records = resolver.resolve(domain, 'TXT')
            results['TXT_records'] = [record.to_text() for record in txt_records]
        except dns.resolver.NoAnswer:
            results['TXT_records'] = []

        return results
    except Exception as e:
        return {'error': str(e)}

# Helper function for SSL/TLS scanning
def ssl_scan(domain):
    results = {}

    try:
        context = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssl_sock:
                cert = ssl_sock.getpeercert()
                results["subject"] = dict(cert["subject"])
                results["issuer"] = dict(cert["issuer"])
                results["valid_from"] = cert["notBefore"]
                results["valid_to"] = cert["notAfter"]
                results["tls_version"] = ssl_sock.version()
    except ssl.SSLError as e:
        results["error"] = f"SSL error: {str(e)}"
    except socket.timeout:
        results["error"] = "Connection timed out"
    except Exception as e:
        results["error"] = f"An error occurred: {str(e)}"

    return results

# Port Scanner Endpoint
@app.route('/scan/ports', methods=['POST'])
def scan_ports():
    data = request.get_json()
    target = data.get('target')
    if not target:
        return jsonify({"error": "Missing 'target' in request body"}), 400

    try:
        results = port_scan(target)
        return jsonify({"target": target, "results": results}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# Vulnerability Scanner Endpoint
@app.route('/scan/vulnerabilities', methods=['POST'])
def scan_vulnerabilities():
    data = request.get_json()
    version = data.get('version')
    if not version:
        return jsonify({"error": "Missing 'version' in request body"}), 400

    try:
        results = vulnerability_scan(version)
        return jsonify({"version": version, "results": results}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# Web Scanner Endpoint
@app.route('/scan/web', methods=['POST'])
def scan_web():
    data = request.get_json()
    url = data.get('url')
    if not url:
        return jsonify({"error": "Missing 'url' in request body"}), 400

    try:
        results = web_scan(url)
        return jsonify({"url": url, "results": results}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# DNS Scanner Endpoint
@app.route('/scan/dns', methods=['POST'])
def scan_dns():
    data = request.get_json()
    domain = data.get('domain')
    if not domain:
        return jsonify({"error": "Missing 'domain' in request body"}), 400

    try:
        results = dns_scan(domain)
        return jsonify({"domain": domain, "results": results}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# SSL/TLS Scanner Endpoint
@app.route('/scan/ssl', methods=['POST'])
def scan_ssl():
    data = request.get_json()
    domain = data.get('domain')
    if not domain:
        return jsonify({"error": "Missing 'domain' in request body"}), 400

    try:
        results = ssl_scan(domain)
        return jsonify({"domain": domain, "results": results}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500

if __name__ == '__main__':
    app.run(debug=True)
