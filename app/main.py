from flask import Flask, jsonify, request
from flask_swagger_ui import get_swaggerui_blueprint
import socket
import os

app = Flask(__name__)

# Garantir permissões para o arquivo Swagger JSON
swagger_file_path = os.path.join(os.path.dirname(__file__), '../static/swagger.json')
if os.path.exists(swagger_file_path):
    try:
        # Permissões: leitura/escrita para o proprietário e leitura para outros
        os.chmod(swagger_file_path, 0o644)
        print(f"Permissões do arquivo '{swagger_file_path}' configuradas para leitura.")
    except Exception as e:
        print(f"Erro ao configurar permissões do arquivo '{swagger_file_path}': {e}")
else:
    print(f"Arquivo Swagger JSON não encontrado em: {swagger_file_path}")


### Swagger Configuration ###
SWAGGER_URL = '/swagger'
API_URL = '/static/swagger.json'  # Swagger JSON URL
swaggerui_blueprint = get_swaggerui_blueprint(
    SWAGGER_URL,  
    API_URL,
    config={
        'app_name': "BugHunter"
    }
)
app.register_blueprint(swaggerui_blueprint, url_prefix=SWAGGER_URL)

### Utility Functions ###
def port_scan(target, ports):
    """Scan specific ports on a target host."""
    results = {}
    for port in ports:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(1)
                result = s.connect_ex((target, port))
                results[port] = 'open' if result == 0 else 'closed'
        except Exception as e:
            results[port] = f'error: {str(e)}'
    return results

### API Endpoints ###
@app.route('/')
def home():
    """
    Root endpoint to check if the server is running.
    ---
    tags:
      - General
    responses:
      200:
        description: API is running
        schema:
          type: object
          properties:
            message:
              type: string
              example: "Welcome to BugHunter API! Visit /swagger for documentation."
    """
    return jsonify({
        "message": "Welcome to BugHunter API! Visit /swagger for documentation."
    }), 200

@app.route('/scan/ports', methods=['POST'])
def scan_ports():
    """
    Endpoint to scan ports on a target.
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
              example: [22, 80, 443]
    responses:
      200:
        description: Scan results
        schema:
          type: object
          properties:
            target:
              type: string
            results:
              type: object
              additionalProperties:
                type: string
    """
    data = request.get_json()
    target = data.get('target')
    ports = data.get('ports')
    if not target or not ports:
        return jsonify({"error": "Missing 'target' or 'ports' in request body"}), 400

    try:
        results = port_scan(target, ports)
        return jsonify({"target": target, "results": results}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500

if __name__ == '__main__':
    app.run(debug=True)
