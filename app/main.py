import socket
import os
import requests
from flask import Flask, jsonify, request
from flask_swagger_ui import get_swaggerui_blueprint
from flask_cors import CORS

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

# Helper functions and configurations
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
    """
    Perform an advanced port scan to detect open ports, services, and versions.
    """
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

def get_vulnerabilities(software, version):
    """
    Fetch vulnerabilities from the Vulners API for a given software and version.
    """
    API_URL = "https://vulners.com/api/v3/search/lucene/"
    API_KEY = os.getenv("VULNERS_API_KEY", "your_nist_api_key_here")  # Replace with your API key

    query = f"{software} {version}"
    params = {
        "query": query,
        "apiKey": API_KEY
    }

    try:
        response = requests.get(API_URL, params=params, timeout=10)
        if response.status_code == 200:
            data = response.json()
            vulns = []
            for item in data.get('data', {}).get('documents', []):
                vulns.append({
                    "cve_id": item.get('id'),
                    "description": item.get('description'),
                    "severity": item.get('cvss', 'Unknown')
                })
            return vulns
        else:
            return [{"error": f"API request failed with status code {response.status_code}"}]
    except Exception as e:
        return [{"error": str(e)}]

# Endpoints
@app.route('/scan/ports', methods=['POST'])
def scan_ports_advanced():
    """
    Advanced Port Scanner Endpoint
    ---
    tags:
      - Network Scanner
    parameters:
      - name: target
        in: body
        required: true
        description: The target hostname or IP to scan.
        schema:
          type: object
          properties:
            target:
              type: string
              example: "127.0.0.1"
            ports:
              type: array
              items:
                type: integer
              example: [22, 80, 443, 3306]
    responses:
      200:
        description: Advanced scan results
        schema:
          type: object
          properties:
            target:
              type: string
            results:
              type: object
              additionalProperties:
                type: object
                properties:
                  status:
                    type: string
                  service:
                    type: string
    """
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
    """
    Vulnerability Scanner Endpoint
    ---
    tags:
      - Vulnerability Scanner
    parameters:
      - name: body
        in: body
        required: true
        description: Provide the target software information.
        schema:
          type: object
          properties:
            software_versions:
              type: array
              items:
                type: object
                properties:
                  software:
                    type: string
                    example: "nginx"
                  version:
                    type: string
                    example: "1.21.6"
    responses:
      200:
        description: Vulnerabilities found
        schema:
          type: object
          properties:
            vulnerabilities:
              type: array
              items:
                type: object
                properties:
                  cve_id:
                    type: string
                    example: "CVE-2023-1234"
                  description:
                    type: string
                    example: "Buffer overflow in nginx 1.21.6"
                  severity:
                    type: string
                    example: "High"
    """
    data = request.get_json()
    software_versions = data.get('software_versions')
    if not software_versions:
        return jsonify({"error": "Missing 'software_versions' in request body"}), 400

    vulnerabilities = []
    for software_info in software_versions:
        software = software_info.get('software')
        version = software_info.get('version')
        if not software or not version:
            continue

        vulns = get_vulnerabilities(software, version)
        vulnerabilities.extend(vulns)

    return jsonify({"vulnerabilities": vulnerabilities}), 200

if __name__ == '__main__':
    app.run(debug=True)
