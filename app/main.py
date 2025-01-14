import os
import socket
import requests
import json
import nmap
import ssl
from flask import Flask, jsonify, request
from flask_swagger_ui import get_swaggerui_blueprint
from flask_cors import CORS
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas
from bs4 import BeautifulSoup
import dns.resolver

app = Flask(__name__)

# Swagger configuration
SWAGGER_URL = '/swagger'
API_URL = '/static/swagger.json'
swaggerui_blueprint = get_swaggerui_blueprint(
    SWAGGER_URL,
    API_URL,
    config={'app_name': "BugHunter"}
)
app.register_blueprint(swaggerui_blueprint, url_prefix=SWAGGER_URL)
CORS(app)

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
    return COMMON_SERVICES.get(port, 'Unknown')

def advanced_port_scan(target, ports):
    results = {}
    for port in ports:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(1)
                result = s.connect_ex((target, port))
                if result == 0:
                    service = identify_service(port)
                    results[port] = {"status": "open", "service": service}
                else:
                    results[port] = {"status": "closed"}
        except Exception as e:
            results[port] = {"status": "error", "message": str(e)}
    return results

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
    target = data.get("target")
    if not target:
        return jsonify({"error": "Missing 'target' in request body"}), 400
    # Example: Dummy response to simulate vulnerability scan
    return jsonify({
        "target": target,
        "vulnerabilities": [
            {"id": "CVE-2021-34527", "description": "PrintNightmare vulnerability", "severity": "high"},
            {"id": "CVE-2021-44228", "description": "Log4Shell vulnerability", "severity": "critical"}
        ]
    }), 200

@app.route('/scan/dns', methods=['POST'])
def dns_scan():
    data = request.get_json()
    domain = data.get("domain")
    if not domain:
        return jsonify({"error": "Missing 'domain' in request body"}), 400
    try:
        dns_results = {}
        resolver = dns.resolver.Resolver()
        for record in ["A", "MX", "TXT", "NS", "CNAME"]:
            try:
                dns_results[record] = [r.to_text() for r in resolver.resolve(domain, record)]
            except dns.resolver.NoAnswer:
                dns_results[record] = []
            except Exception as e:
                dns_results[record] = {"error": str(e)}
        return jsonify({"domain": domain, "dns_records": dns_results}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/scan/web', methods=['POST'])
def web_scan():
    data = request.get_json()
    target = data.get("target")
    if not target:
        return jsonify({"error": "Missing 'target' in request body"}), 400
    try:
        response = requests.get(target)
        soup = BeautifulSoup(response.text, "html.parser")
        links = [link.get('href') for link in soup.find_all('a', href=True)]
        return jsonify({"target": target, "links": links}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500

def create_pdf_report(filename, data):
    pdf_path = os.path.join(os.getcwd(), filename)
    c = canvas.Canvas(pdf_path, pagesize=letter)
    c.drawString(100, 750, f"Report for {data['target']}")
    y_position = 700
    details = data.get("details", {})
    for key, value in details.items():
        c.drawString(100, y_position, f"{key}: {value}")
        y_position -= 20
    c.save()
    return pdf_path

@app.route('/scan/report', methods=['POST'])
def generate_report():
    data = request.get_json()
    target = data.get("target")
    details = data.get("details")

    if isinstance(details, str):
        try:
            details = json.loads(details)
        except json.JSONDecodeError:
            return jsonify({"error": "Invalid 'details' format. Must be JSON."}), 400

    filename = f"{target}_report.pdf"
    pdf_path = create_pdf_report(filename, {"target": target, "details": details})
    return jsonify({"message": "Report generated successfully.", "path": pdf_path}), 200

if __name__ == '__main__':
    app.run(debug=True)
