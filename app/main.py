import socket
import os
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

# Habilitar o CORS
CORS(app)

# Helper function to identify common services based on ports
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

# Endpoint for advanced port scanning
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

if __name__ == '__main__':
    app.run(debug=True)
