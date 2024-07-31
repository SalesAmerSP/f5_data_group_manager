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
import ipaddress

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
    if request.method == 'POST':
        selected_devices = request.form.getlist('devices')
        imported_datagroups = []
        for device_name in selected_devices:
            device = next((d for d in devices if d['name'] == device_name), None)
            if device:
                datagroups = import_datagroups_from_device(device)
                imported_datagroups.extend(datagroups)
        
        existing_datagroups = read_json(DATAGROUPS_FILE)
        updated_datagroups = existing_datagroups + imported_datagroups
        write_json(DATAGROUPS_FILE, updated_datagroups)
        
        flash('Data groups imported successfully from BIG-IP!')
        return redirect(url_for('index'))
    
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
        # Handle file upload and import
        pass
    return render_template('import_from_file.html')

@app.route('/import_from_url', methods=['GET', 'POST'])
def import_from_url():
    if request.method == 'POST':
        url = request.form['url']
        # Handle import from URL
        pass
    return render_template('import_from_url.html')

@app.route('/export_datagroup_csv', methods=['POST'])
def export_datagroup_csv():
    datagroups = read_json(DATAGROUPS_FILE)
    if request.method == 'POST':
        selected_datagroups = request.form.getlist('datagroup')
        if selected_datagroups:
            csvfile = BytesIO()
            wrapper = TextIOWrapper(csvfile, 'utf-8', newline='')
            writer = csv.writer(wrapper)
            writer.writerow(['Data Group', 'Type', 'Name', 'Data'])
            for datagroup in datagroups:
                if datagroup['name'] in selected_datagroups:
                    for record in datagroup['records']:
                        writer.writerow([datagroup['name'], datagroup['type'], record['name'], record['data']])
            wrapper.flush()
            wrapper.detach()
            csvfile.seek(0)
            return send_file(
                csvfile,
                mimetype='text/csv',
                as_attachment=True,
                download_name=f'datagroup-{datagroup['name']}-export-{datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S')}UTC.csv'
            )
    return render_template('export_datagroup.html', datagroups=datagroups, export_type='CSV')

@app.route('/export_datagroup_json', methods=['GET', 'POST'])
def export_datagroup_json():
    datagroups = read_json(DATAGROUPS_FILE)
    if request.method == 'POST':
        selected_datagroup = request.form.getlist('datagroup')
        if selected_datagroup:
            export_data = [dg for dg in datagroups if dg['name'] in selected_datagroup]
            if export_data:
                jsonfile = BytesIO()
                jsonfile.write(json.dumps(export_data).encode('utf-8'))
                jsonfile.seek(0)
                return send_file(
                    jsonfile,
                    mimetype='application/json',
                    as_attachment=True,
                    download_name=f'datagroup-{selected_datagroup}-export-{datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S')}UTC.json'
                )
    return render_template('export_datagroup.html', datagroups=datagroups, export_type='JSON')

@app.route('/big_ips')
def big_ips():
    devices = read_json(DEVICES_FILE)
    return render_template('big_ips.html', devices=devices)



if __name__ == '__main__':
    app.run(debug=True)
