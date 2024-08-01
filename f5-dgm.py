#! /usr/bin/env python3

import json
import os
import requests
import urllib3
import csv
from flask import Flask, render_template, request, redirect, url_for, flash, send_file, jsonify, make_response
from requests.auth import HTTPBasicAuth
from encryption import encrypt_password, decrypt_password  # Correctly import encryption functions
from datetime import datetime  # Import datetime module
from werkzeug.utils import secure_filename
from datetime import datetime, timezone
from io import StringIO, BytesIO, TextIOWrapper
from urllib.parse import unquote
import ipaddress
import socket

# Disable SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

app = Flask(__name__)
app.secret_key = 'your_secret_key'
UPLOAD_FOLDER = 'uploads'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
ALLOWED_EXTENSIONS = {'csv', 'json'}

if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

# File paths
DEVICES_FILE = 'devices.json'
DATAGROUPS_FILE = 'datagroups.json'

# Ensure the JSON files exist
for filename in [DEVICES_FILE, DATAGROUPS_FILE]:
    if not os.path.exists(filename):
        with open(filename, 'w') as f:
            json.dump([], f)

import socket

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
        flash(f'DNS resolution failed for device: {device["name"]}')
        return []
    try:
        url = f"https://{address}/mgmt/tm/sys/clock"
        auth = HTTPBasicAuth(username, password)
        response = requests.get(url, auth=auth, verify=False, timeout=5)
        return response.status_code == 200
    except requests.RequestException:
        flash("Device credentials failed!")
        return False
    return True

@app.route('/import_datagroups_from_bigip', methods=['GET', 'POST'])
def import_datagroups_from_bigip():
    devices = read_json(DEVICES_FILE)
    return render_template('import_datagroups_from_bigip.html', devices=devices)

@app.route('/')
def index():
    devices = read_json(DEVICES_FILE)
    datagroups = read_json(DATAGROUPS_FILE)
    return render_template('index.html', devices=devices, datagroups=datagroups)


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


@app.route('/remove_datagroup', methods=['POST'])
def remove_datagroup():
    datagroup_name = request.form['datagroup_name']
    datagroups = read_json(DATAGROUPS_FILE)
    datagroups = [dg for dg in datagroups if dg['name'] != datagroup_name]
    write_json(DATAGROUPS_FILE, datagroups)
    flash('Data group removed successfully!')
    return redirect(url_for('index'))


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

def get_datagroups_from_devices(device_names):
    devices = read_json(DEVICES_FILE)
    all_datagroups = {}
    
    for device_name in device_names:
        device = next((d for d in devices if d['name'] == device_name), None)
        if device:
            datagroups = import_datagroups_from_bigip(device)
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
                        next(reader)  # Skip the header row
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

@app.route('/flush_datagroups', methods=['POST'])
def flush_datagroups():
    try:
        write_json(DATAGROUPS_FILE, [])
        flash('Local data-group cache flushed successfully!')
    except Exception as e:
        flash(f'Error flushing data-group cache: {str(e)}')
    return redirect(url_for('index'))

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

@app.route('/remove_device', methods=['POST'])
def remove_device():
    device_name = request.form['device_name']
    devices = read_json(DEVICES_FILE)
    devices = [device for device in devices if device['name'] != device_name]
    write_json(DEVICES_FILE, devices)
    flash('Device removed successfully!')
    return redirect(url_for('big_ips'))

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

            if file.filename.lower().endswith('.csv'):
                valid_csv, message_csv = lint_datagroup_csv(file_path)
                if not valid_csv:
                    flash(f'CSV Linting Error: {message_csv}')
                    return redirect(request.url)

                try:
                    with open(file_path, newline='') as csvfile:
                        reader = csv.reader(csvfile)
                        header = next(reader)

                        if header != ["Data Group", "Type", "Name", "Data"]:
                            flash('CSV header must be "Data Group", "Type", "Name", "Data"')
                            return redirect(request.url)

                        current_datagroup = None
                        for row in reader:
                            if len(row) != 4:
                                flash('Each row must have exactly four values: Data Group, Type, Name, Data')
                                return redirect(request.url)

                            dg_name, dg_type, record_name, record_data = row

                            if dg_type not in ["string", "integer", "address"]:
                                flash('Data Group type must be "string", "integer", or "address"')
                                return redirect(request.url)

                            if dg_type == "integer":
                                try:
                                    int(record_name)
                                except ValueError:
                                    flash('For Data Group type "integer", all Name values must be integers')
                                    return redirect(request.url)

                            if not current_datagroup or current_datagroup['name'] != dg_name:
                                if current_datagroup:
                                    new_datagroups.append(current_datagroup)
                                current_datagroup = {'name': dg_name, 'type': dg_type, 'description': 'Imported by F5 DGM on ' + datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S') + ' UTC' ,'records': []}
                            current_datagroup['records'].append({'name': record_name, 'data': record_data})

                        if current_datagroup:
                            new_datagroups.append(current_datagroup)

                except Exception as e:
                    flash(f'Error processing CSV file: {str(e)}')
                    return redirect(request.url)

            elif file.filename.lower().endswith('.json'):
                try:
                    with open(file_path) as jsonfile:
                        new_datagroups = json.load(jsonfile)

                    if not all(isinstance(dg, dict) and 'name' in dg and 'type' in dg and 'records' in dg for dg in new_datagroups):
                        flash('Invalid JSON format')
                        return redirect(request.url)

                except Exception as e:
                    flash(f'Error processing JSON file: {str(e)}')
                    return redirect(request.url)

            datagroups = read_json(DATAGROUPS_FILE)
            existing_datagroups = [dg for dg in new_datagroups if any(edg['name'] == dg['name'] for edg in datagroups)]

            if existing_datagroups:
                return render_template('confirm_import.html', existing_datagroups=existing_datagroups, file_path=file_path)

            for new_dg in new_datagroups:
                existing_dg = next((dg for dg in datagroups if dg['name'] == new_dg['name']), None)
                if existing_dg:
                    existing_dg['records'].extend(new_dg['records'])
                else:
                    datagroups.append(new_dg)

            write_json(DATAGROUPS_FILE, datagroups)
            flash('Data groups imported successfully!')

            return redirect(url_for('index'))

    return render_template('import_from_file.html')

@app.route('/confirm_import', methods=['POST'])
def confirm_import():
    file_path = request.form['file_path']
    overwrite = request.form.get('overwrite', 'no') == 'yes'

    if not overwrite:
        flash('Import cancelled by user.')
        return redirect(url_for('index'))

    try:
        new_datagroups = []
        if file_path.lower().endswith('.csv'):
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

        elif file_path.lower().endswith('.json'):
            with open(file_path) as jsonfile:
                new_datagroups = json.load(jsonfile)

        datagroups = read_json(DATAGROUPS_FILE)
        for new_dg in new_datagroups:
            existing_dg = next((dg for dg in datagroups if dg['name'] == new_dg['name']), None)
            if existing_dg:
                existing_dg['records'] = new_dg['records']
            else:
                datagroups.append(new_dg)

        write_json(DATAGROUPS_FILE, datagroups)
        flash('Data groups imported and overwritten successfully!')

    except Exception as e:
        flash(f'Error processing file: {str(e)}')

    return redirect(url_for('index'))


def lint_datagroup_csv(file_path):
    try:
        with open(file_path, newline='') as csvfile:
            reader = csv.reader(csvfile)
            header = next(reader)
            if header != ["Data Group", "Type", "Name", "Data"]:
                return False, 'Header must have exactly four columns: "Data Group", "Type", "Name", "Data"'
            for row in reader:
                if len(row) != 4:
                    return False, "Each row must have exactly four values"
                dg_type = row[1]
                if dg_type not in ["string", "integer", "address"]:
                    return False, 'Data Group type must be "string", "integer", or "address"'
                if dg_type == "integer":
                    try:
                        int(row[2])
                    except ValueError:
                        return False, 'For Data Group type "integer", all Name values must be integers'
        return True, "CSV format is correct"
    except Exception as e:
        return False, str(e)

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

import csv
from io import BytesIO, StringIO
from flask import send_file, request, flash, redirect, url_for

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
        download_name=f'datagroup-{datagroup_name}-export-{datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S')}UTC.csv'
    )

@app.route('/big_ips')
def big_ips():
    devices = read_json(DEVICES_FILE)
    return render_template('big_ips.html', devices=devices)

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

    return render_template('select_datagroups.html', selected_devices=selected_devices_info)

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

@app.route('/import_selected_datagroups', methods=['POST'])
def import_selected_datagroups():
    try:
        selected_devices_str = request.form['selected_devices'].replace('+', '').replace("'", '"')
        selected_devices = json.loads(selected_devices_str)
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

def import_datagroup_from_device(device, datagroup_name):
    if not test_dns_resolution(device['address']):
        flash(f'DNS resolution failed for device: {device["name"]}')
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
        flash(f'Failed to import data group {datagroup_name} from device: {device["name"]}')
        return False


if __name__ == '__main__':
    app.run(debug=True)
