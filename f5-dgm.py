#! /usr/bin/env python3

import json
import os
import requests
import urllib3
import csv
import ipaddress
import socket
import base64
import logging
from flask_talisman import Talisman
from flask import Flask, render_template, request, redirect, url_for, flash, send_file, jsonify, make_response
from requests.auth import HTTPBasicAuth
from encryption import encrypt_password, decrypt_password
from werkzeug.utils import secure_filename
from datetime import datetime, timezone
from io import StringIO, BytesIO, TextIOWrapper
from urllib.parse import unquote
from ipaddress import ip_address, ip_network
from helper_functions import (
    test_dns_resolution, 
    allowed_file, 
    read_json, 
    write_json, 
    lint_csv, 
    lint_json, 
    is_device_reachable, 
    verify_device_credentials
)

# Disable SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Create the Flask app
app = Flask(__name__)

# Enforce HTTPS
talisman = Talisman(app)

# Create app security policy
csp = {
    'default-src': ['\'self\'', 'https://*', '\'unsafe-inline\'',  '\'unsafe-eval\''],
    'script-src': ['\'self\'', 'https://*', '\'unsafe-inline\'',  '\'unsafe-eval\'', '*']
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

# Tell the client browsers to not cache any pages
@app.after_request
def add_no_cache_headers(response):
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Pragma"] = "no-cache"
    response.headers["Expires"] = "0"
    return response

# Load secret key from file with error handling
try:
    with open('secret.key', 'r') as f:
        app.secret_key = f.read().strip()
        if not app.secret_key:
            raise ValueError("Secret key file is empty. Execute the create_secret_key.py file to create one in the project root directory.")
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

# Define built-in data groups for TMOS
TMOS_BUILT_IN_DATA_GROUPS = [
    {
      "name": "aol",
      "partition": "Common",
      "type": "ip",
      "records": [
        {
          "name": "64.12.96.0/19",
          "data": ""
        },
        {
          "name": "195.93.16.0/20",
          "data": ""
        },
        {
          "name": "195.93.48.0/22",
          "data": ""
        },
        {
          "name": "195.93.64.0/19",
          "data": ""
        },
        {
          "name": "195.93.96.0/19",
          "data": ""
        },
        {
          "name": "198.81.0.0/22",
          "data": ""
        },
        {
          "name": "198.81.8.0/23",
          "data": ""
        },
        {
          "name": "198.81.16.0/20",
          "data": ""
        },
        {
          "name": "202.67.65.128/25",
          "data": ""
        },
        {
          "name": "205.188.112.0/20",
          "data": ""
        },
        {
          "name": "205.188.146.144/30",
          "data": ""
        },
        {
          "name": "205.188.192.0/20",
          "data": ""
        },
        {
          "name": "205.188.208.0/23",
          "data": ""
        },
        {
          "name": "207.200.112.0/21",
          "data": ""
        }
      ]
    },
    {
      "name": "images",
      "partition": "Common",
      "type": "string",
      "records": [
        {
          "name": ".bmp",
          "data": ""
        },
        {
          "name": ".gif",
          "data": ""
        },
        {
          "name": ".jpg",
          "data": ""
        }
      ]
    },
    {
      "name": "private_net",
      "partition": "Common",
      "type": "ip",
      "records": [
        {
          "name": "10.0.0.0/8",
          "data": ""
        },
        {
          "name": "172.16.0.0/12",
          "data": ""
        },
        {
          "name": "192.168.0.0/16",
          "data": ""
        }
      ]
    },
    {
      "name": "sys_APM_MS_Office_OFBA_DG",
      "partition": "Common",
      "description": "This internal data-group is used in _sys_APM_MS_Office_OFBA_Support irule",
      "type": "string",
      "records": [
        {
          "name": "ie_sp_session_sharing_enabled",
          "data": "0"
        },
        {
          "name": "ie_sp_session_sharing_inactivity_timeout",
          "data": "60"
        },
        {
          "name": "ofba_auth_dialog_size",
          "data": "800x600"
        },
        {
          "name": "useragent1",
          "data": "microsoft data access internet publishing provider"
        },
        {
          "name": "useragent2",
          "data": "office protocol discovery"
        },
        {
          "name": "useragent3",
          "data": "microsoft office"
        },
        {
          "name": "useragent4",
          "data": "non-browser"
        },
        {
          "name": "useragent5",
          "data": "msoffice 12"
        },
        {
          "name": "useragent6",
          "data": "microsoft-webdav-miniredir"
        },
        {
          "name": "useragent7",
          "data": "webdav-miniredir"
        },
        {
          "name": "useragent9",
          "data": "ms frontpage 1[23456789]"
        },
        {
          "name": "useragent10",
          "data": "onenote"
        }
      ]
    }
  ]


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
        description = request.form['description']
        type_ = request.form['type']
        records = []
        names = request.form.getlist('records_name')
        datas = request.form.getlist('records_data')
        for record_name, record_data in zip(names, datas):
            records.append({'name': record_name, 'data': record_data})
        
        datagroups = read_json(DATAGROUPS_FILE)
        datagroups.append({'name': dg_name, 'description': description, 'type': type_, 'description': description, 'records': records})
        write_json(DATAGROUPS_FILE, datagroups)
        flash('Data group added successfully!')
        return redirect(url_for('index'))

    return render_template('add_datagroup.html', timestamp = str(f'{datetime.now(timezone.utc).strftime('%m-%d-%Y at %H:%M:%S')} UTC'))

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
        download_name=f'datagroup-{datagroup['name']}-{datetime.now(timezone.utc).strftime('%Y-%m-%d_%H-%M-%S')}UTC.csv'
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
        download_name=f'datagroup-{datagroup_name}-{datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S')}UTC.json'
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
                            if dg['type'] not in ["string", "integer", "ip"]:
                                flash(f'Invalid data group type: {dg["type"]}')
                                return redirect(request.url)
                            if dg['type'] == "integer":
                                for record in dg['records']:
                                    try:
                                        int(record['name'])
                                    except ValueError:
                                        flash(f'For Data Group type "integer", all Name values must be integers: {record["name"]}')
                                        return redirect(request.url)
                            if dg['type'] == "ip":
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
                if row[1] not in ["string", "integer", "ip"]:
                    return False, 'Data Group type must be "string", "integer", or "ip"'
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
                        return False, 'For Data Group type "ip", all Name values must be valid IPv4 or IPv6 addresses or subnets in CIDR notation'
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

# App route for importing datagroups from BIG-IP(s)
@app.route('/import_from_bigips', methods=['GET', 'POST'])
def import_from_bigips():
    devices = read_json(DEVICES_FILE)
    device_datagroups = []

    for device in devices:
        datagroups = fetch_datagroups_from_bigip(device)
        if datagroups:
            device['datagroups'] = datagroups
            device_datagroups.append(device)

    if request.method == 'POST':
        ignore_builtin = request.form.get('ignore_builtin') == 'on'
        selected_datagroups = {}
        for device in device_datagroups:
            datagroups = request.form.getlist(f'datagroups_{device["name"]}')
            for datagroup in datagroups:
                if ignore_builtin and is_builtin_datagroup(datagroup):
                    continue
                if datagroup not in selected_datagroups:
                    selected_datagroups[datagroup] = device
                else:
                    flash(f'Duplicate data group name "{datagroup}" found across devices. Please ensure unique data group names.')
                    return render_template('import_from_bigips.html', devices=device_datagroups, TMOS_BUILT_IN_DATA_GROUPS=TMOS_BUILT_IN_DATA_GROUPS)

        success_count = 0
        failure_count = 0

        for datagroup, device in selected_datagroups.items():
            if import_datagroup_from_device(device, datagroup):
                success_count += 1
            else:
                failure_count += 1

        flash(f'Successfully imported {success_count} data groups. Failed to import {failure_count} data groups.')
        return redirect(url_for('index'))

    return render_template('import_from_bigips.html', devices=device_datagroups, TMOS_BUILT_IN_DATA_GROUPS=TMOS_BUILT_IN_DATA_GROUPS)

def is_builtin_datagroup(datagroup_name):
    for dg in TMOS_BUILT_IN_DATA_GROUPS:
        if dg['name'] == datagroup_name:
            return True
    return False

def fetch_datagroups_from_bigip(device):
    try:
        if not test_dns_resolution(device['address']):
            flash(f'DNS resolution failed for device: {device["name"]}')
            return []
    except Exception as e:
        flash(f'DNS resolution error for device: {device["name"]}, error: {str(e)}')
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
        flash(f'Failed to fetch data groups from device: {device["name"]}, error: {str(e)}')
        return []

def import_datagroup_from_device(device, datagroup_name):
    try:
        if not test_dns_resolution(device['address']):
            flash(f'DNS resolution failed for device: {device["name"]}')
            return False
    except Exception as e:
        flash(f'DNS resolution error for device: {device["name"]}, error: {str(e)}')
        return False

    url = f"https://{device['address']}/mgmt/tm/ltm/data-group/internal/{datagroup_name}"
    decrypted_password = decrypt_password(device['password'])
    if not decrypted_password:
        flash(f'Failed to decrypt the password for device: {device["name"]}')
        return False

    auth = HTTPBasicAuth(device['username'], decrypted_password)
    try:
        response = requests.get(url, auth=auth, verify=False)
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
    except requests.exceptions.RequestException as e:
        flash(f'Failed to import data group {datagroup_name} from device: {device["name"]}, error: {str(e)}')
        return False

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
                
        for dg in datagroups:
            if dg['name'] == name:
                dg['records'] = new_records
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
            valid, message = lint_values_csv(file_path)
        elif filename.endswith('.json'):
            valid, message = lint_values_json(file_path)
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
                        flash('Import failed: All name values must be an integer for integer type data groups')
                        return redirect(url_for('update_datagroup', name=name))
                elif datagroup['type'] == 'ip':
                    for record in new_records:
                        try:
                            if '/' in record['name']:
                                ip_network(record['name'], strict=True)
                            else:
                                ip_address(record['name'])
                        except ValueError:
                            flash('Import failed: All name values must be valid IPv4 or IPv6 addresses or subnets in CIDR notation with IP type data groups')
                            return redirect(url_for('update_datagroup', name=name))
                            
                datagroup['records'].extend(new_records)
                write_json(DATAGROUPS_FILE, datagroups)
                flash('Values imported successfully!')
            else:
                flash('Data group not found')
        else:
            flash(f'Import Error: {message}')
        
    return redirect(url_for('update_datagroup', name=name))

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

# App route to browsing datagroups on the BIG-IP
@app.route('/browse_datagroups/<device_name>', methods=['GET'])
def browse_datagroups(device_name):
    devices = read_json(DEVICES_FILE)
    device = next((d for d in devices if d['name'] == device_name), None)
    if not device:
        flash(f'Device {device_name} not found')
        return redirect(url_for('big_ips'))

    datagroups = fetch_datagroups_from_bigip(device)
    if not datagroups:
        flash(f'No data groups found on device {device_name}')
        return redirect(url_for('big_ips'))

    return render_template('browse_datagroups.html', device=device, datagroups=datagroups)

@app.route('/export_all_datagroups_json/<device_name>', methods=['GET'])
def export_all_datagroups_json(device_name):
    devices = read_json(DEVICES_FILE)
    device = next((d for d in devices if d['name'] == device_name), None)
    if not device:
        flash(f'Device {device_name} not found')
        return redirect(url_for('big_ips'))

    datagroups = fetch_datagroups_from_bigip(device)
    if not datagroups:
        flash(f'No data groups found on device {device_name}')
        return redirect(url_for('big_ips'))

    filename = f'all-data-groups-{device['address']}-{datetime.now(timezone.utc).strftime('%Y-%m-%d_%H-%M-%S')}UTC.json'
    
    json_bytes = BytesIO(json.dumps(datagroups).encode('utf-8'))
    json_bytes.seek(0)

    return send_file(
        json_bytes,
        mimetype='application/json',
        as_attachment=True,
        download_name=filename
    )

@app.route('/export_all_datagroups_csv/<device_name>', methods=['GET'])
def export_all_datagroups_csv(device_name):
    devices = read_json(DEVICES_FILE)
    device = next((d for d in devices if d['name'] == device_name), None)
    if not device:
        flash(f'Device {device_name} not found')
        return redirect(url_for('big_ips'))

    datagroups = fetch_datagroups_from_bigip(device)
    if not datagroups:
        flash(f'No data groups found on device {device_name}')
        return redirect(url_for('big_ips'))

    filename = f'all-data-groups-{device['address']}-{datetime.now(timezone.utc).strftime('%Y-%m-%d_%H-%M-%S')}UTC.csv'

    csv_string = StringIO()
    writer = csv.writer(csv_string)
    writer.writerow(['Data Group', 'Partition', 'Type', 'Name', 'Data'])

    for datagroup in datagroups:
        for record in datagroup['records']:
            writer.writerow([datagroup['name'], datagroup['partition'], datagroup['type'], record['name'], record['data']])

    csv_bytes = BytesIO(csv_string.getvalue().encode('utf-8'))
    csv_bytes.seek(0)

    return send_file(
        csv_bytes,
        mimetype='text/csv',
        as_attachment=True,
        download_name=filename
    )

# Route to export datagroup from BIG-IP to CSV
@app.route('/export_datagroup_from_bigip_csv', methods=['GET'])
def export_datagroup_from_bigip_csv():
    device_name = request.args.get('device_name')
    datagroup_name = request.args.get('datagroup_name')

    devices = read_json(DEVICES_FILE)
    device = next((d for d in devices if d['name'] == device_name), None)
    if not device:
        flash(f'Device {device_name} not found')
        return redirect(url_for('index'))

    datagroup = fetch_and_filter_datagroup_from_device(device, datagroup_name)
    if not datagroup:
        flash(f'Data group {datagroup_name} not found on device {device_name}')
        return redirect(url_for('index'))

    # Create a string-based buffer and write CSV data to it
    csv_string = StringIO()
    writer = csv.writer(csv_string)
    writer.writerow(['Data Group', 'Type', 'Name', 'Data'])

    for record in datagroup.get('records', []):
        writer.writerow([datagroup['name'], datagroup['type'], record['name'], record.get('data', '')])

    # Convert the string buffer to a bytes buffer
    csv_bytes = BytesIO(csv_string.getvalue().encode('utf-8'))
    csv_bytes.seek(0)

    filename = f"datagroup-{datagroup_name}_exported_from_{device['address']}-{datetime.now(timezone.utc).strftime('%Y-%m-%d_%H-%M-%S')}UTC.csv"
    return send_file(
        csv_bytes,
        mimetype='text/csv',
        as_attachment=True,
        download_name=filename
    )

# Route to export datagroup from BIG-IP to JSON
@app.route('/export_datagroup_from_bigip_json', methods=['GET'])
def export_datagroup_from_bigip_json():
    device_name = request.args.get('device_name')
    datagroup_name = request.args.get('datagroup_name')

    devices = read_json(DEVICES_FILE)
    device = next((d for d in devices if d['name'] == device_name), None)
    if not device:
        flash(f'Device {device_name} not found')
        return redirect(url_for('index'))

    datagroup = fetch_and_filter_datagroup_from_device(device, datagroup_name)
    if not datagroup:
        flash(f'Data group {datagroup_name} not found on device {device_name}')
        return redirect(url_for('index'))

    # Convert the datagroup to JSON bytes
    json_bytes = BytesIO(json.dumps(datagroup).encode('utf-8'))
    json_bytes.seek(0)

    filename = f"datagroup-{datagroup_name}_exported_from_{device['address']}-{datetime.now(timezone.utc).strftime('%Y-%m-%d_%H-%M-%S')}UTC.json"
    return send_file(
        json_bytes,
        mimetype='application/json',
        as_attachment=True,
        download_name=filename
    )

# Helper function to fetch datagroup from BIG-IP and filter fields
def fetch_and_filter_datagroup_from_device(device, datagroup_name):
    url = f"https://{device['address']}/mgmt/tm/ltm/data-group/internal/{datagroup_name}"
    decrypted_password = decrypt_password(device['password'])
    if not decrypted_password:
        flash(f'Failed to decrypt the password for device: {device["name"]}')
        return None

    auth = HTTPBasicAuth(device['username'], decrypted_password)
    try:
        response = requests.get(url, auth=auth, verify=False)
        response.raise_for_status()
        datagroup = response.json()
        # Remove unwanted fields
        for field in ["kind", "fullPath", "generation", "selfLink"]:
            datagroup.pop(field, None)
        return datagroup
    except requests.exceptions.RequestException as e:
        flash(f'Failed to fetch data group {datagroup_name} from device {device["name"]}: {str(e)}')
        return None
    
# Route for deleting datagroups on BIG-IPs
@app.route('/remove_datagroup_from_bigips', methods=['GET', 'POST'])
def remove_datagroup_from_bigips():
    devices = read_json(DEVICES_FILE)
    device_datagroups = []

    # Fetch datagroups from each device
    for device in devices:
        datagroups = fetch_datagroups_from_bigip(device)
        if datagroups:
            for dg in datagroups:
                dg['partition'] = dg.get('partition', 'Common')
                dg['records_count'] = len(dg.get('records', []))
            device['datagroups'] = datagroups
            device_datagroups.append(device)

    if request.method == 'POST':
        selected_datagroups = request.form.getlist('selected_datagroups')
        failed_removals = []

        for item in selected_datagroups:
            device_name, datagroup_name = item.split('|')
            device = next((d for d in devices if d['name'] == device_name), None)
            if device:
                success = delete_datagroup_from_device(device, datagroup_name)
                if not success:
                    failed_removals.append((device_name, datagroup_name))

        if failed_removals:
            flash(f'Failed to delete data groups from devices: {failed_removals}')
        else:
            flash('Data groups deleted successfully from all selected devices!')

        return redirect(url_for('index'))

    return render_template('remove_datagroup_from_bigips.html', devices=device_datagroups)

def fetch_datagroups_from_bigip(device):
    try:
        if not test_dns_resolution(device['address']):
            flash(f'DNS resolution failed for device: {device["name"]}')
            return []
    except Exception as e:
        flash(f'DNS resolution error for device: {device["name"]}, error: {str(e)}')
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
    except requests.exceptions.RequestException as e:
        flash(f'Failed to fetch data groups from device: {device["name"]}, error: {str(e)}')
        return []

def delete_datagroup_from_device(device, datagroup_name):
    url = f"https://{device['address']}/mgmt/tm/ltm/data-group/internal/{datagroup_name}"
    decrypted_password = decrypt_password(device['password'])
    if not decrypted_password:
        flash(f'Failed to decrypt the password for device: {device["name"]}')
        return False
    
    auth = HTTPBasicAuth(device['username'], decrypted_password)
    try:
        response = requests.delete(url, auth=auth, verify=False)
        response.raise_for_status()
        return True
    except requests.exceptions.RequestException as e:
        flash(f'Failed to delete data group {datagroup_name} from device {device["name"]}: {str(e)}')
        return False

# App Route for deploying data groups to BIG-IP(s)
@app.route('/deploy_datagroups', methods=['GET', 'POST'])
def deploy_datagroups():
    devices = read_json(DEVICES_FILE)
    datagroups = read_json(DATAGROUPS_FILE)
    
    if request.method == 'POST':
        selected_devices = request.form.getlist('devices')
        selected_datagroups = request.form.getlist('datagroups')
        
        if not selected_devices or not selected_datagroups:
            flash('Please select at least one device and one data group to deploy.')
            return redirect(url_for('deploy_datagroups'))

        failed_devices = []
        
        for device_name in selected_devices:
            device = next((d for d in devices if d['name'] == device_name), None)
            if device:
                for dg_name in selected_datagroups:
                    datagroup = next((dg for dg in datagroups if dg['name'] == dg_name), None)
                    if datagroup:
                        if not deploy_datagroup_to_device(device, datagroup):
                            failed_devices.append(device_name)
                        else:
                            flash(f"Deployed datagroup {datagroup['name']} to {device['name']} successfully!")
        
        if failed_devices:
            flash(f'Failed to deploy data groups to devices: {", ".join(failed_devices)}')
        return redirect(url_for('index'))
    
    return render_template('deploy_datagroups.html', devices=devices, datagroups=datagroups)

def deploy_datagroup_to_device(device, datagroup):
    # test name resolution prior to API call
    if not test_dns_resolution(device['address']):
        flash(f'DNS resolution failed for device: {device["name"]}')
        return False
    # decrypt password from device file
    decrypted_password = decrypt_password(device['password'])
    if not decrypted_password:
        flash(f'Failed to decrypt the password for device: {device["name"]}')
        return False
    # create auth
    auth = HTTPBasicAuth(device['username'], decrypted_password)
    # create headers
    headers = {'Content-Type': 'application/json'}

    url = f"https://{device['address']}/mgmt/tm/ltm/data-group/internal/{datagroup['name']}"

    # Check if the data group exists
    try:
        response = requests.get(url, auth=auth, headers=headers, verify=False)
        response.raise_for_status()
        exists = True
    except requests.exceptions.HTTPError as http_err:
        if response.status_code == 404:
            exists = False
        else:
            flash(f'HTTP error occurred for {device['name']}: {http_err} (Response: {response.text})')
            return False
    except Exception as err:
        flash(f'Error occurred: {err} (Payload: {datagroup}) (Response: {response.text})')
        return False

    # Create or update the data group
    try:
        if exists:
            response = requests.put(url, auth=auth, headers=headers, json=datagroup, verify=False)
        else:
            url = f"https://{device['address']}/mgmt/tm/ltm/data-group/internal"
            response = requests.post(url, auth=auth, headers=headers, json=datagroup, verify=False)
        response.raise_for_status()
        return True
    except requests.exceptions.HTTPError as http_err:
        flash(f'HTTP error occurred for {device['name']}: {http_err} (Payload: {datagroup}) (Response: {response.text})')
        return False
    except Exception as err:
        flash(f'Error occurred: {err}')
        return False


if __name__ == '__main__':
    app.run(host="127.0.0.1", port=8443, debug=True, ssl_context='adhoc')
