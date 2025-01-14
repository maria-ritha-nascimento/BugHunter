import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
import pytest
from app.main import app

@pytest.fixture
def client():
    with app.test_client() as client:
        yield client

def test_scan_ports(client):
    response = client.post('/scan/ports', json={
        "target": "127.0.0.1",
        "ports": [80, 443, 22]
    })
    assert response.status_code == 200
    data = response.get_json()
    assert "results" in data
    assert all(port in data["results"] for port in [80, 443, 22])

def test_scan_vulnerabilities(client):
    response = client.post('/scan/vulnerabilities', json={
        "target": "example.com"
    })
    assert response.status_code == 200
    data = response.get_json()
    assert "vulnerabilities" in data
    assert isinstance(data["vulnerabilities"], list)

def test_dns_scan(client):
    response = client.post('/scan/dns', json={
        "domain": "example.com"
    })
    assert response.status_code == 200
    data = response.get_json()
    assert "dns_records" in data
    assert all(record in data["dns_records"] for record in ["A", "MX", "TXT", "NS", "CNAME"])

def test_web_scan(client):
    response = client.post('/scan/web', json={
        "target": "http://example.com"
    })
    assert response.status_code == 200
    data = response.get_json()
    assert "links" in data
    assert isinstance(data["links"], list)

def test_generate_report_valid(client):
    response = client.post('/scan/report', json={
        "target": "example.com",
        "details": {
            "ports": {"80": "open", "443": "closed"},
            "dns": {"A": ["93.184.216.34"]}
        }
    })
    assert response.status_code == 200
    data = response.get_json()
    assert "message" in data
    assert data["message"] == "Report generated successfully."
    assert "path" in data

def test_generate_report_invalid_details(client):
    response = client.post('/scan/report', json={
        "target": "example.com",
        "details": "not a valid json"
    })
    assert response.status_code == 400
    data = response.get_json()
    assert "error" in data
    assert data["error"] == "Invalid 'details' format. Must be JSON."

def test_ssl_scan(client):
    response = client.post('/scan/ssl', json={
        "target": "google.com"
    })
    assert response.status_code == 200
    data = response.get_json()
    assert "results" in data
    assert isinstance(data["results"], dict)
