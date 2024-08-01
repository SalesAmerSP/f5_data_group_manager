import socket
import json
import requests
from requests.auth import HTTPBasicAuth

# Constants
ALLOWED_EXTENSIONS = {'csv', 'json'}

def test_dns_resolution(hostname, timeout=5):
    try:
        socket.setdefaulttimeout(timeout)
        socket.gethostbyname(hostname)
        return True
    except socket.error as e:
        return False

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def read_json(file):
    try:
        with open(file, 'r') as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return []

def write_json(file, data):
    try:
        with open(file, 'w') as f:
            json.dump(data, f, indent=4)
        print(f"Successfully wrote to {file}")
    except Exception as e:
        print(f"Error writing to {file}: {e}")

def lint_csv(file_path):
    # Basic linting for CSV format
    try:
        with open(file_path, newline='') as csvfile:
            reader = csv.reader(csvfile)
            for row in reader:
                if len(row) < 2:
                    return False, "Each row must have at least two columns"
        return True, "CSV format is correct"
    except Exception as e:
        return False, str(e)

def lint_json(file_path):
    # Basic linting for JSON format
    try:
        with open(file_path) as jsonfile:
            json.load(jsonfile)
        return True, "JSON format is correct"
    except json.JSONDecodeError as e:
        return False, str(e)

def is_device_reachable(address):
    try:
        response = requests.get(f"https://{address}", verify=False, timeout=5)
        return response.status_code == 200
    except requests.RequestException:
        return False

def verify_device_credentials(address, username, password):
    if not test_dns_resolution(address):
        return False
    try:
        url = f"https://{address}/mgmt/tm/sys/clock"
        auth = HTTPBasicAuth(username, password)
        response = requests.get(url, auth=auth, verify=False, timeout=5)
        return response.status_code == 200
    except requests.RequestException:
        return False
