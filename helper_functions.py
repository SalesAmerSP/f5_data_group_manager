import socket
import json
import requests
import csv
import ipaddress
import os
from requests.auth import HTTPBasicAuth
from encryption import decrypt_password
from config import DEVICES_FILE, DATAGROUPS_FILE, TMOS_BUILT_IN_DATA_GROUPS, HIERARCHY_FILE, DNS_RESOLVERS_FILE
from flask import flash

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

def process_csv(file_path):
    new_datagroups = []
    with open(file_path, newline='') as csvfile:
        reader = csv.reader(csvfile)
        header = next(reader)

        current_datagroup = None
        for row in reader:
            dg_name, dg_type, dg_description, record_name, record_data = row
            if not current_datagroup or current_datagroup['name'] != dg_name:
                if current_datagroup:
                    new_datagroups.append(current_datagroup)
                current_datagroup = {'name': dg_name, 'type': dg_type, 'description': dg_description, 'records': []}
            current_datagroup['records'].append({'name': record_name, 'data': record_data})

        if current_datagroup:
            new_datagroups.append(current_datagroup)
    return new_datagroups

def process_json(file_path):
    with open(file_path, 'r') as jsonfile:
        new_datagroups = json.load(jsonfile)
        if not isinstance(new_datagroups, list):
            new_datagroups = [new_datagroups]
        if not all(isinstance(dg, dict) and 'name' in dg and 'type' in dg and 'records' in dg for dg in new_datagroups):
            raise ValueError('Invalid JSON format')
        for dg in new_datagroups:
            if dg['type'] not in ['string', 'integer', 'ip']:
                raise ValueError(f'Invalid data group type: {dg['type']}')
            if dg['type'] == "integer":
                for record in dg['records']:
                    if not isinstance(record['name'], int):
                        raise ValueError(f'For Data Group type "integer", all Name values must be integers: {record['name']}')
            if dg['type'] == "ip":
                for record in dg['records']:
                    if '/' in record['name']:
                        ip_network(record['name'], strict=True)
                    else:
                        ip_address(record['name'])
    return new_datagroups

def merge_datagroups(existing_datagroups, new_datagroups):
    for new_dg in new_datagroups:
        existing_dg = next((dg for dg in existing_datagroups if dg['name'] == new_dg['name']), None)
        if existing_dg:
            existing_dg['records'].extend(new_dg['records'])
        else:
            existing_datagroups.append(new_dg)
    return existing_datagroups

def lint_datagroup_csv(file_path):
    try:
        with open(file_path, newline='') as csvfile:
            reader = csv.reader(csvfile)
            header = next(reader)
            if header != ['Data Group', 'Type', 'Description', 'Name', 'Data']:
                return False, 'CSV header must be "Data Group", "Type", "Description", "Name", "Data"'
            for row in reader:
                if len(row) != 5:
                    return False, 'Each row must have exactly four values: Data Group, Type, Description, Name, Data'
                if row[1] not in ['string', 'integer', 'ip']:
                    return False, 'Data Group type must be "string", "integer", or "ip"'
                if row[1] == "integer":
                    try:
                        int(row[3])
                    except ValueError:
                        return False, 'For Data Group type "integer", all Name values must be integers'
                if row[1] == "address":
                    try:
                        if '/' in row[3]:
                            ip_network(row[3], strict=True)
                        else:
                            ip_address(row[3])
                    except ValueError:
                        return False, 'For Data Group type "ip", all Name values must be valid IPv4/IPv6 addresses or valid IPv4/IPv6 subnets in CIDR notation'
            return True, "CSV format is correct"
    except Exception as e:
        return False, str(e)

def is_builtin_datagroup(datagroup_name):
    for dg in TMOS_BUILT_IN_DATA_GROUPS:
        if dg['name'] == datagroup_name:
            return True
    return False

def import_datagroup_from_device(device, datagroup_name):
    try:
        if not test_dns_resolution(device['address']):
            flash(f'DNS resolution failed for device: {device['name']}')
            return False
    except Exception as e:
        flash(f'DNS resolution error for device: {device['name']}, error: {str(e)}')
        return False

    url = f"https://{device['address']}/mgmt/tm/ltm/data-group/internal/{datagroup_name}"
    decrypted_password = decrypt_password(device['password'])
    if not decrypted_password:
        flash(f'Failed to decrypt the password for device: {device['name']}')
        return False

    auth = HTTPBasicAuth(device['username'], decrypted_password)
    try:
        response = requests.get(url, auth=auth, verify=False, timeout=5)
        response.raise_for_status()
        datagroup = response.json()
        datagroups = read_json(DATAGROUPS_FILE)
        existing_dg = next((dg for dg in datagroups if dg['name'] == datagroup['name']), None)
        if existing_dg:
            existing_dg.update(datagroup)
        else:
            datagroups.append(datagroup)
        write_json(DATAGROUPS_FILE, datagroups)
        return True
    except requests.exceptions.Timeout:
        flash(f'Timeout exceeded while trying to reach {device['name']}')
        return []
    except requests.exceptions.RequestException as e:
        flash(f'Failed to import data group {datagroup_name} from device: {device['name']}, error: {str(e)}')
        return False

def lint_values_csv(file_path):
    try:
        with open(file_path, newline='') as csvfile:
            reader = csv.reader(csvfile)
            for row in reader:
                if len(row) != 2:
                    return False, 'Each row must have exactly two values'
            return True, "CSV format is correct"
    except Exception as e:
        return False, str(e)

def lint_values_json(file_path):
    try:
        with open(file_path) as jsonfile:
            json.load(jsonfile)
        return True, "JSON format is correct"
    except json.JSONDecodeError as e:
        return False, str(e)

def fetch_and_filter_datagroup_from_device(device, datagroup_name):
    url = f"https://{device['address']}/mgmt/tm/ltm/data-group/internal/{datagroup_name}"
    decrypted_password = decrypt_password(device['password'])
    if not decrypted_password:
        flash(f'Failed to decrypt the password for device: {device['name']}')
        return None

    auth = HTTPBasicAuth(device['username'], decrypted_password)
    try:
        response = requests.get(url, auth=auth, verify=False, timeout=5)
        response.raise_for_status()
        datagroup = response.json()
        # Remove unwanted fields
        for field in ["kind", "fullPath", "generation", "selfLink"]:
            datagroup.pop(field, None)
        return datagroup
    except requests.exceptions.Timeout:
        flash(f'Timeout exceeded while trying to reach {device['name']}')
        return []
    except requests.exceptions.RequestException as e:
        flash(f'Failed to fetch data group {datagroup_name} from device {device['name']}: {str(e)}')
        return None

def fetch_datagroup_from_bigip(devices, device_name, datagroup_name):
    device = next((d for d in devices if d['name'] == device_name), None)
    if not device:
        return None
    datagroup = fetch_and_filter_datagroup_from_device(device, datagroup_name)
    return datagroup

def fetch_datagroups_from_bigip(device):
    try:
        if not test_dns_resolution(device['address']):
            flash(f'DNS resolution failed for device: {device['name']}')
            return []
    except Exception as e:
        flash(f'DNS resolution error for device: {device['name']}, error: {str(e)}')
        return []

    url = f"https://{device['address']}/mgmt/tm/ltm/data-group/internal"
    decrypted_password = decrypt_password(device['password'])
    if not decrypted_password:
        flash(f'Failed to decrypt the password for device: {device['name']}')
        return []

    auth = HTTPBasicAuth(device['username'], decrypted_password)
    try:
        response = requests.get(url, auth=auth, verify=False, timeout=5)
        response.raise_for_status()
        datagroups = response.json().get('items', [])
        
        # Filter the datagroups to only include the desired fields
        filtered_datagroups = []
        for dg in datagroups:
            filtered_dg = {
                'name': dg.get('name'),
                'partition': dg.get('partition'),
                'type': dg.get('type'),
                'description': dg.get('description', ''),
                'records': dg.get('records', [])
            }
            filtered_datagroups.append(filtered_dg)
        
        return filtered_datagroups    
    except requests.exceptions.Timeout:
        flash(f'Timeout exceeded while trying to reach {device['name']}')
        return []
    except requests.exceptions.RequestException as e:
        flash(f'Failed to fetch data groups from device: {device['name']}, error: {str(e)}')
        return []

def delete_datagroup_from_device(device, datagroup_name):
    url = f"https://{device['address']}/mgmt/tm/ltm/data-group/internal/{datagroup_name}"
    decrypted_password = decrypt_password(device['password'])
    if not decrypted_password:
        flash(f'Failed to decrypt the password for device: {device['name']}')
        return False
    
    auth = HTTPBasicAuth(device['username'], decrypted_password)
    try:
        response = requests.delete(url, auth=auth, verify=False, timeout=5)
        response.raise_for_status()
        return True
    except requests.exceptions.Timeout:
        flash(f'Timeout exceeded while trying to reach {device['name']}')
        return []
    except requests.exceptions.RequestException as e:
        flash(f'Failed to delete data group {datagroup_name} from device {device['name']}: {str(e)}')
        return False

def deploy_datagroup_to_device(device, datagroup):
    # test name resolution prior to API call
    if not test_dns_resolution(device['address']):
        flash(f'DNS resolution failed for device: {device['name']}')
        return False
    # decrypt password from device file
    decrypted_password = decrypt_password(device['password'])
    if not decrypted_password:
        flash(f'Failed to decrypt the password for device: {device['name']}')
        return False
    # create auth
    auth = HTTPBasicAuth(device['username'], decrypted_password)
    # create headers
    headers = {'Content-Type': 'application/json'}

    url = f"https://{device['address']}/mgmt/tm/ltm/data-group/internal/{datagroup['name']}"

    # Check if the data group exists
    try:
        response = requests.get(url, auth=auth, headers=headers, verify=False, timeout=5)
        response.raise_for_status()
        exists = True
    except requests.exceptions.HTTPError as http_err:
        if response.status_code == 404:
            exists = False
        else:
            flash(f'HTTP error occurred for {device['name']}: {http_err} (Response: {response.text})')
            return False
    except requests.exceptions.Timeout:
        flash(f'Timeout exceeded while trying to reach {device['name']}')
        return []
    except Exception as err:
        flash(f'Error occurred: {err} (Payload: {datagroup}) (Response: {response.text})')
        return False

    # Create or update the data group
    try:
        if exists:
            response = requests.put(url, auth=auth, headers=headers, json=datagroup, verify=False, timeout=5)
        else:
            url = f"https://{device['address']}/mgmt/tm/ltm/data-group/internal"
            response = requests.post(url, auth=auth, headers=headers, json=datagroup, verify=False, timeout=5)
        response.raise_for_status()
        return True
    except requests.exceptions.Timeout:
        flash(f'Timeout exceeded while trying to reach {device['name']}')
        return []
    except requests.exceptions.HTTPError as http_err:
        flash(f'HTTP error occurred for {device['name']}: {http_err} (Payload: {datagroup}) (Response: {response.text})')
        return False
    except Exception as err:
        flash(f'Error occurred: {err}')
        return False

def read_hierarchy():
    try:
        with open(HIERARCHY_FILE, 'r') as file:
            return json.load(file)
    except FileNotFoundError:
        return {"datagroups": {}}

def write_hierarchy(hierarchy):
    with open(HIERARCHY_FILE, 'w') as file:
        json.dump(hierarchy, file, indent=4)
        
def dns_lookup(ip_or_fqdn):
    results = {}

    try:
        # Check if the input is an IP address
        ip = ipaddress.ip_address(ip_or_fqdn)
        is_ip = True
    except ValueError:
        # If it's not an IP, we assume it's an FQDN
        is_ip = False

    if is_ip:
        # Reverse lookup
        try:
            reverse_name = socket.gethostbyaddr(ip.exploded)
            results['reverse'] = reverse_name[0]  # The primary hostname
        except socket.herror:
            results['reverse'] = 'No reverse DNS found'
        except Exception as e:
            results['reverse'] = f'Error: {e}'
    else:
        # Forward lookup
        try:
            ipv4_addresses = socket.gethostbyname_ex(ip_or_fqdn)[2]
            results['A'] = ipv4_addresses
        except socket.gaierror:
            results['A'] = 'No A record found'
        except Exception as e:
            results['A'] = f'Error: {e}'

        try:
            ipv6_addresses = socket.getaddrinfo(ip_or_fqdn, None, socket.AF_INET6)
            results['AAAA'] = [item[4][0] for item in ipv6_addresses]
        except socket.gaierror:
            results['AAAA'] = 'No AAAA record found'
        except Exception as e:
            results['AAAA'] = f'Error: {e}'

    return results

def load_dns_resolvers():
    """
    Load the DNS resolvers from the configuration file.
    Returns a list of resolvers.
    """
    if os.path.exists(DNS_RESOLVERS_FILE):
        with open(DNS_RESOLVERS_FILE, 'r') as f:  # Open the file in read mode
            return json.load(f)
    else:
        return []

def save_dns_resolvers_to_config(dns_resolvers):
    """
    Save the DNS resolvers to the configuration file.
    """
    with open(DNS_RESOLVERS_FILE, 'w') as f:
        json.dump(dns_resolvers, f)
