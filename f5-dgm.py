#! /usr/bin/env python3

import json
import os
import requests
import urllib3
import csv
import ipaddress
import socket
import base64
from flask_talisman import Talisman
from flask import Flask, render_template, request, redirect, url_for, flash, send_file, jsonify, make_response
from requests.auth import HTTPBasicAuth
from encryption import encrypt_password, decrypt_password  # Correctly import encryption functions
from datetime import datetime  # Import datetime module
from werkzeug.utils import secure_filename
from datetime import datetime, timezone
from io import StringIO, BytesIO, TextIOWrapper
from urllib.parse import unquote
from ipaddress import ip_address, ip_network
from helper_functions import (
    test_dns_resolution, encode_base64, decode_base64, allowed_file, read_json, write_json,
    lint_csv, lint_json, is_device_reachable, verify_device_credentials
)
# Disable SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Create the Flask app
app = Flask(__name__)

# Enforce HTTPS
talisman = Talisman(app)

csp = {
    'default-src': [
        '\'self\'', 
        'https://*',
        '\'unsafe-inline\'', 
        '\'unsafe-eval\''
    ],
    'script-src': [
        '\'self\'',
        'https://*',
        '\'unsafe-inline\'',  # Allow inline scripts
        '\'unsafe-eval\''
        '*'
    ],
}
# HTTP Strict Transport Security (HSTS) Header
hsts = {
	'max-age': 31536000,
	'includeSubDomains': True
}

# Enforce HTTPS and other headers
talisman.force_https = True
talisman.force_file_save = True
talisman.x_xss_protection = True
talisman.session_cookie_secure = True
talisman.session_cookie_samesite = 'Lax'

# Add the headers to Talisman
talisman.content_security_policy = csp
talisman.strict_transport_security = hsts

# Load secret key from file with error handling
try:
    with open('secret.key', 'r') as f:
        app.secret_key = f.read().strip()
        if not app.secret_key:
            raise ValueError("Secret key file is empty")
except FileNotFoundError:
    print("Error: 'secret.key' file not found. Please ensure the file exists.")
    exit(1)
except PermissionError:
    print("Error: Permission denied when trying to read 'secret.key'.")
    exit(1)
except ValueError as e:
    print(f"Error: {e}")
    exit(1)
except Exception as e:
    print(f"An unexpected error occurred while reading 'secret.key': {e}")
    exit(1)

# Create the Uploads folder if necessary
app.config['UPLOAD_FOLDER'] = 'uploads'
if not os.path.exists(app.config['UPLOAD_FOLDER']):
    os.makedirs(app.config['UPLOAD_FOLDER'])

# File paths
DEVICES_FILE = 'devices.json'
DATAGROUPS_FILE = 'datagroups.json'

# Ensure the JSON files exist
for filename in [DEVICES_FILE, DATAGROUPS_FILE]:
    if not os.path.exists(filename):
        with open(filename, 'w') as f:
            json.dump([], f)

# App route for the root page which displays all datagroups
@app.route('/')
def index():
    devices = read_json(DEVICES_FILE)
    datagroups = read_json(DATAGROUPS_FILE)
    return render_template('index.html', devices=devices, datagroups=datagroups)

# App route for creating a new data group
@app.route('/add_datagroup', methods=['GET', 'POST'])
def add_datagroup():
    if request.method == 'POST':
        dg_name = request.form['name']
        type_ = request.form['type']
        records = []
        names = request.form.getlist('records_name')
        datas = request.form.getlist('records_data')
        for record_name, record_data in zip(names, datas):
            records.append({'name': record_name, 'data': record_data})
        
        datagroups = read_json(DATAGROUPS_FILE)
        description = f"Last modified by F5 DGM on {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S')} UTC"
        datagroups.append({'name': dg_name, 'type': type_, 'description': description, 'records': records})
        write_json(DATAGROUPS_FILE, datagroups)
        flash('Data group added successfully!')
        return redirect(url_for('index'))
    
    return render_template('add_datagroup.html')

# App route for deleting a local copy of a datagroup
@app.route('/remove_datagroup', methods=['POST'])
def remove_datagroup():
    datagroup_name = request.form['datagroup_name']
    datagroups = read_json(DATAGROUPS_FILE)
    datagroups = [dg for dg in datagroups if dg['name'] != datagroup_name]
    write_json(DATAGROUPS_FILE, datagroups)
    flash('Data group removed successfully!')
    return redirect(url_for('index'))

# App route for flushing all local datagroups
@app.route('/flush_datagroups', methods=['POST'])
def flush_datagroups():
    try:
        write_json(DATAGROUPS_FILE, [])
        flash('Local data-group cache flushed successfully!')
    except Exception as e:
        flash(f'Error flushing data-group cache: {str(e)}')
    return redirect(url_for('index'))

# App route for exporting datagroup to CSV
@app.route('/export_datagroup_csv', methods=['POST'])
def export_datagroup_csv():
    datagroups = read_json(DATAGROUPS_FILE)
    datagroup_name = request.form['datagroup_name']
    datagroup = next((dg for dg in datagroups if dg['name'] == datagroup_name), None)

    if not datagroup:
        flash(f'Data group {datagroup_name} not found')
        return redirect(url_for('index'))

    # Create a string-based buffer and write CSV data to it
    csv_string = StringIO()
    writer = csv.writer(csv_string)
    writer.writerow(['Data Group', 'Type', 'Name', 'Data'])

    for record in datagroup['records']:
        writer.writerow([datagroup['name'], datagroup['type'], record['name'], record.get('data', '')])

    # Convert the string buffer to a bytes buffer
    csv_bytes = BytesIO(csv_string.getvalue().encode('utf-8'))
    csv_bytes.seek(0)

    return send_file(
        csv_bytes,
        mimetype='text/csv',
        as_attachment=True,
        download_name=f'datagroup-{datagroup['name']}-export-{datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S')}UTC.csv'
    )

# App Route for exporting to JSON
@app.route('/export_datagroup_json', methods=['POST'])
def export_datagroup_json():
    datagroups = read_json(DATAGROUPS_FILE)
    datagroup_name = request.form['datagroup_name']
    datagroup = next((dg for dg in datagroups if dg['name'] == datagroup_name), None)

    if not datagroup:
        flash(f'Data group {datagroup_name} not found')
        return redirect(url_for('index'))

    # Convert the datagroup to JSON bytes
    json_bytes = BytesIO(json.dumps(datagroup).encode('utf-8'))
    json_bytes.seek(0)

    return send_file(
        json_bytes,
        mimetype='application/json',
        as_attachment=True,
        download_name=f'datagroup-{datagroup_name}-export-{datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S')}UTC.json'
    )

# App route for importing a datagroup from file
@app.route('/import_from_file', methods=['GET', 'POST'])
def import_from_file():
    if request.method == 'POST':
        if 'file' not in request.files:
            flash('No file part')
            return redirect(request.url)
        file = request.files['file']
        if file.filename == '':
            flash('No selected file')
            return redirect(request.url)
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(file_path)

            new_datagroups = []

            if file.filename.endswith('.csv'):
                # Lint and import CSV data
                valid_csv, message_csv = lint_datagroup_csv(file_path)
                if not valid_csv:
                    flash(f'CSV Linting Error: {message_csv}')
                    return redirect(request.url)

                # Process CSV
                new_datagroups = []
                try:
                    with open(file_path, newline='') as csvfile:
                        reader = csv.reader(csvfile)
                        header = next(reader)

                        current_datagroup = None
                        for row in reader:
                            dg_name, dg_type, record_name, record_data = row
                            if not current_datagroup or current_datagroup['name'] != dg_name:
                                if current_datagroup:
                                    new_datagroups.append(current_datagroup)
                                current_datagroup = {'name': dg_name, 'type': dg_type, 'records': []}
                            current_datagroup['records'].append({'name': record_name, 'data': record_data})

                        if current_datagroup:
                            new_datagroups.append(current_datagroup)

                    datagroups = read_json(DATAGROUPS_FILE)
                    for new_dg in new_datagroups:
                        existing_dg = next((dg for dg in datagroups if dg['name'] == new_dg['name']), None)
                        if existing_dg:
                            existing_dg['records'].extend(new_dg['records'])
                        else:
                            datagroups.append(new_dg)

                    write_json(DATAGROUPS_FILE, datagroups)
                    flash('Data groups imported successfully from CSV!')

                except Exception as e:
                    flash(f'Error processing CSV file: {str(e)}')
                    return redirect(request.url)

            elif file.filename.endswith('.json'):
                # Lint and import JSON data
                try:
                    with open(file_path, 'r') as jsonfile:
                        new_datagroups = json.load(jsonfile)
                        if not isinstance(new_datagroups, list):
                            new_datagroups = [new_datagroups]
                        if not all(isinstance(dg, dict) and 'name' in dg and 'type' in dg and 'records' in dg for dg in new_datagroups):
                            flash(f'Invalid JSON format: {new_datagroups}')
                            return redirect(request.url)
                        for dg in new_datagroups:
                            if dg['type'] not in ["string", "integer", "address"]:
                                flash(f'Invalid data group type: {dg["type"]}')
                                return redirect(request.url)
                            if dg['type'] == "integer":
                                for record in dg['records']:
                                    try:
                                        int(record['name'])
                                    except ValueError:
                                        flash(f'For Data Group type "integer", all Name values must be integers: {record["name"]}')
                                        return redirect(request.url)
                            if dg['type'] == "address":
                                for record in dg['records']:
                                    try:
                                        if '/' in record['name']:
                                            ip_network(record['name'], strict=True)
                                        else:
                                            ip_address(record['name'])
                                    except ValueError:
                                        flash(f'Invalid address or subnet: {record["name"]}')
                                        return redirect(request.url)

                    datagroups = read_json(DATAGROUPS_FILE)
                    for new_dg in new_datagroups:
                        existing_dg = next((dg for dg in datagroups if dg['name'] == new_dg['name']), None)
                        if existing_dg:
                            existing_dg['records'].extend(new_dg['records'])
                        else:
                            datagroups.append(new_dg)

                    write_json(DATAGROUPS_FILE, datagroups)
                    flash('Data groups imported successfully from JSON!')

                except Exception as e:
                    flash(f'Error processing JSON file: {str(e)}')
                    return redirect(request.url)

            return redirect(url_for('index'))

    return render_template('import_from_file.html')

def lint_datagroup_csv(file_path):
    try:
        with open(file_path, newline='') as csvfile:
            reader = csv.reader(csvfile)
            header = next(reader)
            if header != ["Data Group", "Type", "Name", "Data"]:
                return False, 'CSV header must be "Data Group", "Type", "Name", "Data"'
            for row in reader:
                if len(row) != 4:
                    return False, 'Each row must have exactly four values: Data Group, Type, Name, Data'
                if row[1] not in ["string", "integer", "address"]:
                    return False, 'Data Group type must be "string", "integer", or "address"'
                if row[1] == "integer":
                    try:
                        int(row[2])
                    except ValueError:
                        return False, 'For Data Group type "integer", all Name values must be integers'
                if row[1] == "address":
                    try:
                        if '/' in row[2]:
                            ip_network(row[2], strict=True)
                        else:
                            ip_address(row[2])
                    except ValueError:
                        return False, 'For Data Group type "address", all Name values must be valid IPv4 or IPv6 addresses or subnets in CIDR notation'
            return True, "CSV format is correct"
    except Exception as e:
        return False, str(e)

# App route for importing a datagroup from URL
@app.route('/import_from_url', methods=['GET', 'POST'])
def import_from_url():
    if request.method == 'POST':
        url = request.form['url']
        if not url:
            flash('URL is required')
            return redirect(request.url)
        
        try:
            response = requests.get(url)
            response.raise_for_status()
        except requests.RequestException as e:
            flash(f'Failed to download file: {e}')
            return redirect(request.url)
        
        content_type = response.headers.get('Content-Type')
        content = response.text

        if 'application/json' in content_type or (content.strip().startswith('{') or content.strip().startswith('[')):
            # Process JSON content
            try:
                new_datagroups = json.loads(content)
                if not all(isinstance(dg, dict) and 'name' in dg and 'type' in dg and 'records' in dg for dg in new_datagroups):
                    flash('Invalid JSON format')
                    return redirect(request.url)
            except json.JSONDecodeError as e:
                flash(f'Error processing JSON file: {e}')
                return redirect(request.url)
        elif 'text/csv' in content_type or content.strip().startswith('Data Group'):
            # Process CSV content
            valid_csv, message_csv = lint_datagroup_csv(content)
            if not valid_csv:
                flash(f'CSV Linting Error: {message_csv}')
                return redirect(request.url)
            
            new_datagroups = []
            try:
                reader = csv.reader(StringIO(content))
                header = next(reader)
                current_datagroup = None
                for row in reader:
                    dg_name, dg_type, record_name, record_data = row
                    if not current_datagroup or current_datagroup['name'] != dg_name:
                        if current_datagroup:
                            new_datagroups.append(current_datagroup)
                        current_datagroup = {'name': dg_name, 'type': dg_type, 'records': []}
                    current_datagroup['records'].append({'name': record_name, 'data': record_data})
                if current_datagroup:
                    new_datagroups.append(current_datagroup)
            except Exception as e:
                flash(f'Error processing CSV file: {e}')
                return redirect(request.url)
        else:
            flash('Unsupported file type')
            return redirect(request.url)
        
        datagroups = read_json(DATAGROUPS_FILE)
        for new_dg in new_datagroups:
            existing_dg = next((dg for dg in datagroups if dg['name'] == new_dg['name']), None)
            if existing_dg:
                existing_dg['records'].extend(new_dg['records'])
            else:
                datagroups.append(new_dg)

        write_json(DATAGROUPS_FILE, datagroups)
        flash('Data groups imported successfully from URL!')
        return redirect(url_for('index'))

    return render_template('import_from_url.html')

# App route for importing datagroups from BIG-IP(s) (1 of 3)
@app.route('/import_from_bigips', methods=['GET', 'POST'])
def import_from_bigips():
    if request.method == 'POST':
        selected_devices = request.form.getlist('devices')
        devices = read_json(DEVICES_FILE)

        selected_devices_info = []
        for device_name in selected_devices:
            device = next((d for d in devices if d['name'] == device_name), None)
            if device:
                # Fetch data groups from the BIG-IP device
                datagroups = fetch_datagroups_from_bigip(device)
                if datagroups:
                    device['datagroups'] = datagroups
                    selected_devices_info.append(device)
        selected_devices_string = json.dumps(selected_devices_info)

        return render_template('select_datagroups.html', selected_devices=selected_devices_string)

    devices = read_json(DEVICES_FILE)
    return render_template('import_from_bigips.html', devices=devices)

# App route for importing datagroups from BIG-IP(s) (2 of 3)
@app.route('/select_datagroups_from_bigips', methods=['POST'])
def select_datagroups_from_bigips():
    selected_devices = request.form.getlist('devices')
    devices = read_json(DEVICES_FILE)

    selected_devices_info = []
    for device_name in selected_devices:
        device = next((d for d in devices if d['name'] == device_name), None)
        if device:
            # Fetch data groups from the BIG-IP device
            datagroups = fetch_datagroups_from_bigip(device)
            if datagroups:
                device['datagroups'] = datagroups
                selected_devices_info.append(device)

    # Encode the selected devices information in base64
    selected_devices_string = json.dumps(selected_devices_info)

    return render_template('select_datagroups.html', selected_devices=selected_devices_string)

def fetch_datagroups_from_bigip(device):
    if not test_dns_resolution(device['address']):
        flash(f'DNS resolution failed for device: {device["name"]}')
        return []
    url = f"https://{device['address']}/mgmt/tm/ltm/data-group/internal"
    decrypted_password = decrypt_password(device['password'])
    if not decrypted_password:
        flash(f'Failed to decrypt the password for device: {device["name"]}')
        return []

    auth = HTTPBasicAuth(device['username'], decrypted_password)
    try:
        response = requests.get(url, auth=auth, verify=False)
        response.raise_for_status()
        datagroups = [dg['name'] for dg in response.json().get('items', [])]
        return datagroups
    except requests.exceptions.RequestException as e:
        flash(f'Failed to fetch data groups from device: {device["name"]}')
        return []

# App route for importing datagroups from BIG-IP(s) (3 of 3)
@app.route('/import_selected_datagroups', methods=['POST'])
def import_selected_datagroups():
    try:
        selected_devices = json.loads(request.form['selected_devices'])
    except (json.JSONDecodeError, KeyError) as e:
        flash('Error parsing selected devices.')
        return redirect(url_for('index'))

    datagroups_to_import = []

    for device in selected_devices:
        datagroups = request.form.getlist(f'datagroups_{device["name"]}')
        for datagroup in datagroups:
            datagroups_to_import.append({'device': device, 'datagroup': datagroup})

    # Perform the actual import from the selected data groups
    for item in datagroups_to_import:
        device = item['device']
        datagroup_name = item['datagroup']
        import_datagroup_from_device(device, datagroup_name)

    flash('Selected data groups imported successfully!')
    return redirect(url_for('index'))

# App route for updating an existing datagroup
@app.route('/update_datagroup', methods=['GET', 'POST'])
def update_datagroup():
    datagroups = read_json(DATAGROUPS_FILE)
    if request.method == 'POST':
        name = request.form['name']
        new_records = []
        names = request.form.getlist('records_name')
        datas = request.form.getlist('records_data')
        
        for record_name, record_data in zip(names, datas):
            new_records.append({'name': record_name, 'data': record_data})
        
        description = f"Last modified by F5 DGM on {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S')} UTC"
        
        for dg in datagroups:
            if dg['name'] == name:
                dg['records'] = new_records
                dg['description'] = description
                break
        
        write_json(DATAGROUPS_FILE, datagroups)
        flash('Data group updated successfully!')
        return redirect(url_for('index'))
    
    selected_datagroup = None
    selected_name = request.args.get('name')
    if selected_name:
        selected_datagroup = next((dg for dg in datagroups if dg['name'] == selected_name), None)
    
    return render_template('update_datagroup.html', datagroups=datagroups, selected_datagroup=selected_datagroup)

# App route for importing values into an existing datagroup
@app.route('/import_values/<name>', methods=['POST'])
def import_values(name):
    if 'file' not in request.files:
        flash('No file part')
        return redirect(request.url)
    file = request.files['file']
    if file.filename == '':
        flash('No selected file')
        return redirect(request.url)
    if file and allowed_file(file.filename):
        filename = secure_filename(file.filename)
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(file_path)
        
        if filename.endswith('.csv'):
            valid, message = lint_csv(file_path)
        elif filename.endswith('.json'):
            valid, message = lint_json(file_path)
        else:
            flash('Unsupported file type.')

        if valid:
            datagroups = read_json(DATAGROUPS_FILE)
            datagroup = next((dg for dg in datagroups if dg['name'] == name), None)
            
            if datagroup:
                if filename.endswith('.csv'):
                    new_records = []
                    with open(file_path, newline='') as csvfile:
                        reader = csv.reader(csvfile)
                        for row in reader:
                            if len(row) == 2:
                                new_records.append({'name': row[0], 'data': row[1]})
                            else:
                                flash('CSV must have exactly two columns: name and data')
                                return redirect(request.url)
                else:
                    with open(file_path) as jsonfile:
                        new_records = json.load(jsonfile)
                        if not isinstance(new_records, list) or not all(isinstance(record, dict) and 'name' in record and 'data' in record for record in new_records):
                            flash('JSON must be a list of dictionaries with name and data fields')
                            return redirect(request.url)
                
                if datagroup['type'] == 'integer':
                    try:
                        new_records = [{'name': int(record['name']), 'data': record['data']} for record in new_records]
                    except ValueError:
                        flash('Name must be an integer for integer type data groups')
                        return redirect(request.url)
                elif datagroup['type'] == 'address':
                    # Add validation for address type
                    pass
                
                datagroup['records'].extend(new_records)
                write_json(DATAGROUPS_FILE, datagroups)
                flash('Values imported successfully!')
            else:
                flash('Data group not found')
        else:
            flash(f'Import Error: {message}')
        
    return redirect(url_for('update_datagroup', name=name))

# App route for the BIG-IP devices page
@app.route('/big_ips')
def big_ips():
    devices = read_json(DEVICES_FILE)
    return render_template('big_ips.html', devices=devices)

# App route for adding a BIG-IP device
@app.route('/add_device', methods=['GET', 'POST'])
def add_device():
    if request.method == 'POST':
        name = request.form['name']
        address = request.form['address']
        username = request.form['username']
        password = request.form['password']
        
        if verify_device_credentials(address, username, password):
            devices = read_json(DEVICES_FILE)
            devices.append({'name': name, 'address': address, 'username': username, 'password': encrypt_password(password)})
            write_json(DEVICES_FILE, devices)
            flash('Device added successfully!')
        else:
            flash('Failed to verify the device credentials.')
        
        return redirect(url_for('big_ips'))
    
    return render_template('add_device.html')

#App route for removing a BIG-IP device
@app.route('/remove_device', methods=['POST'])
def remove_device():
    device_name = request.form['device_name']
    devices = read_json(DEVICES_FILE)
    devices = [device for device in devices if device['name'] != device_name]
    write_json(DEVICES_FILE, devices)
    flash('Device removed successfully!')
    return redirect(url_for('big_ips'))

#App route for updating device credentials
@app.route('/update_device_credentials', methods=['GET', 'POST'])
def update_device_credentials():
    if request.method == 'POST':
        device_name = request.form['device_name']
        devices = read_json(DEVICES_FILE)
        device = next((d for d in devices if d['name'] == device_name), None)
        if device:
            new_username = request.form['username']
            new_password = request.form['password']
            if verify_device_credentials(device['address'], new_username, new_password):
                device['username'] = new_username
                device['password'] = encrypt_password(new_password)
                write_json(DEVICES_FILE, devices)
                flash('Device credentials updated successfully!')
            else:
                flash('Failed to verify the new credentials.')
            return redirect(url_for('big_ips'))
        else:
            flash('Device not found!')
            return redirect(url_for('big_ips'))
    else:
        device_name = request.args.get('device_name')
        devices = read_json(DEVICES_FILE)
        device = next((d for d in devices if d['name'] == device_name), None)
        if device:
            return render_template('update_device_credentials.html', device=device)
        else:
            flash('Device not found!')
            return redirect(url_for('big_ips'))











def get_datagroups_from_devices(device_names):
    devices = read_json(DEVICES_FILE)
    all_datagroups = {}
    
    for device_name in device_names:
        device = next((d for d in devices if d['name'] == device_name), None)
        if device:
            datagroups = import_from_bigips(device)
            if datagroups:
                for dg in datagroups:
                    if dg['name'] in all_datagroups:
                        all_datagroups[dg['name']].add(device_name)
                    else:
                        all_datagroups[dg['name']] = {device_name}
    
    # Filter to keep only the data groups that are present on all selected devices
    common_datagroups = {name: devices for name, devices in all_datagroups.items() if len(devices) == len(device_names)}
    
    return list(common_datagroups.keys())

def delete_datagroup_from_device(device, datagroup_name):
    if not test_dns_resolution(device['address']):
        flash(f'DNS resolution failed for device: {device["name"]}')
        return []
    url = f"https://{device['address']}/mgmt/tm/ltm/data-group/internal/{datagroup_name}"
    decrypted_password = decrypt_password(device['password'])
    if not decrypted_password:
        flash(f'Failed to decrypt the password for device: {device["name"]}')
        return False
    
    auth = HTTPBasicAuth(device['username'], decrypted_password)
    response = requests.delete(url, auth=auth, verify=False)
    
    return response.status_code == 200



# App Route for deploying data groups to BIG-IP(s)
@app.route('/deploy_datagroups', methods=['GET', 'POST'])
def deploy_datagroups():
    devices = read_json(DEVICES_FILE)
    datagroups = read_json(DATAGROUPS_FILE)
    if request.method == 'POST':
        selected_devices = request.form.getlist('devices')
        selected_datagroups = request.form.getlist('datagroups')
        failed_devices = []
        for device_name in selected_devices:
            device = next((d for d in devices if d['name'] == device_name), None)
            if device:
                for dg_name in selected_datagroups:
                    datagroup = next((dg for dg in datagroups if dg['name'] == dg_name), None)
                    if datagroup:
                        success = deploy_datagroup_to_device(device, datagroup)
                        if not success:
                            failed_devices.append(device_name)
        if failed_devices:
            flash(f'Failed to deploy data groups to devices: {", ".join(failed_devices)}')
        else:
            flash('Data groups deployed successfully to all selected devices!')
        return redirect(url_for('index'))
    return render_template('deploy_datagroups.html', devices=devices, datagroups=datagroups)

def deploy_datagroup_to_device(device, datagroup):
    if not test_dns_resolution(device['address']):
        flash(f'DNS resolution failed for device: {device["name"]}')
        return []
    url = f"https://{device['address']}/mgmt/tm/ltm/data-group/internal/{datagroup['name']}"
    decrypted_password = decrypt_password(device['password'])
    if not decrypted_password:
        flash(f'Failed to decrypt the password for device: {device["name"]}')
        return False

    auth = HTTPBasicAuth(device['username'], decrypted_password)
    headers = {'Content-Type': 'application/json'}
    
    # Check if the data group exists
    response = requests.get(url, auth=auth, headers=headers, verify=False)
    
    if response.status_code == 200:
        # Data group exists, update it
        update_url = f"https://{device['address']}/mgmt/tm/ltm/data-group/internal/{datagroup['name']}"
        response = requests.put(update_url, auth=auth, headers=headers, json=datagroup, verify=False)
    elif response.status_code == 404:
        # Data group does not exist, create it
        create_url = f"https://{device['address']}/mgmt/tm/ltm/data-group/internal"
        response = requests.post(create_url, auth=auth, headers=headers, json=datagroup, verify=False)
    else:
        # Handle other response codes
        return False

    return response.status_code in [200, 201]

if __name__ == '__main__':
    app.run(host="127.0.0.1", port=8443, debug=True, ssl_context='adhoc')
