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

@app.route('/import_datagroups_from_bigip', methods=['GET', 'POST'])
def import_datagroups_from_bigip(devices):
    if request.method == 'POST':
        imported_datagroups = []
        for device_name in devices:
            device = next((d for d in devices if d['name'] == device_name), None)
            if device:
                datagroups = import_datagroups_from_bigip(device)
                imported_datagroups.extend(datagroups)
        
        existing_datagroups = read_json(DATAGROUPS_FILE)
        updated_datagroups = existing_datagroups + imported_datagroups
        write_json(DATAGROUPS_FILE, updated_datagroups)
        
        flash('Data groups imported successfully from BIG-IP!')
        return redirect(url_for('index'))
    
    return render_template('import_datagroups_from_bigip.html', devices=devices)

def is_device_reachable(address):
    try:
        response = requests.get(f"https://{address}", verify=False, timeout=5)
        return response.status_code == 200
    except requests.RequestException:
        return False

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



@app.route('/remove_datagroup', methods=['GET', 'POST'])
def remove_datagroup():
    devices = read_json(DEVICES_FILE)
    
    if request.method == 'POST':
        selected_devices = request.form.getlist('devices')
        if 'step' in request.form and request.form['step'] == '2':
            selected_datagroups = request.form.getlist('datagroups')
            failed_devices = []
            for device_name in selected_devices:
                device = next((d for d in devices if d['name'] == device_name), None)
                if device:
                    for dg_name in selected_datagroups:
                        success = delete_datagroup_from_device(device, dg_name)
                        if not success:
                            failed_devices.append(device_name)
            
            if failed_devices:
                flash(f'Failed to delete data groups from devices: {", ".join(failed_devices)}')
            else:
                flash('Data groups deleted successfully from all selected devices!')
            
            return redirect(url_for('index'))
        
        datagroups = get_datagroups_from_devices(selected_devices)
        return render_template('remove_datagroup_step2.html', datagroups=datagroups, devices=selected_devices)
    
    return render_template('remove_datagroup_step1.html', devices=devices)


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
        type_ = request.form['type']
        new_records = []
        names = request.form.getlist('records_name')
        datas = request.form.getlist('records_data')
        
        # Debugging prints to check form data
        print(f"Received names: {names}")
        print(f"Received datas: {datas}")
        
        for record_name, record_data in zip(names, datas):
            new_records.append({'name': record_name, 'data': record_data})
        
        description = f"Last modified by F5 DGM on {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S')} UTC"
        
        # Update the datagroup
        for dg in datagroups:
            if dg['name'] == name:
                dg['type'] = type_
                dg['records'] = new_records
                dg['description'] = description
                break
        
        # Debugging print to check updated datagroups
        print(f"Updated datagroups: {datagroups}")
        
        write_json(DATAGROUPS_FILE, datagroups)
        flash('Data group updated successfully!')
        return redirect(url_for('index'))
    
    selected_datagroup = None
    selected_name = request.args.get('name')
    if selected_name:
        selected_datagroup = next((dg for dg in datagroups if dg['name'] == selected_name), None)
    
    return render_template('update_datagroup.html', datagroups=datagroups, selected_datagroup=selected_datagroup)


@app.route('/import_datagroups', methods=['GET', 'POST'])
def import_datagroups():
    if request.method == 'POST':
        device_name = request.form['device']
        devices = read_json(DEVICES_FILE)
        device = next((d for d in devices if d['name'] == device_name), None)
        
        if device:
            data_groups = import_datagroups_from_bigip(device)
            if data_groups is not None:
                current_datagroups = read_json(DATAGROUPS_FILE)
                for dg in data_groups:
                    existing_dg = next((cdg for cdg in current_datagroups if cdg['name'] == dg['name']), None)
                    if existing_dg:
                        existing_dg.update(dg)
                    else:
                        current_datagroups.append(dg)
                write_json(DATAGROUPS_FILE, current_datagroups)
                flash('Data groups imported successfully!')
            else:
                flash('Failed to import data groups from the device.')
        else:
            flash('Device not found.')
        
        return redirect(url_for('index'))
    devices = read_json(DEVICES_FILE)
    return render_template('import_datagroups.html', devices=devices)

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
        password = encrypt_password(request.form['password'])
        devices = read_json(DEVICES_FILE)
        devices.append({'name': name, 'address': address, 'username': username, 'password': password})
        write_json(DEVICES_FILE, devices)
        flash('Device added successfully!')
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
            device['username'] = request.form['username']
            device['password'] = encrypt_password(request.form['password'])
            write_json(DEVICES_FILE, devices)
            flash('Device credentials updated successfully!')
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

@app.route('/import_datagroup_csv', methods=['GET', 'POST'])
def import_datagroup_csv():
    datagroups = read_json(DATAGROUPS_FILE)
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
            valid, message = lint_csv(file_path)
            if valid:
                new_datagroups = {}
                with open(file_path, newline='') as csvfile:
                    reader = csv.reader(csvfile)
                    next(reader)  # Skip the header row
                    for row in reader:
                        if len(row) >= 3:
                            dg_name, record_name, record_data = row
                            if dg_name not in new_datagroups:
                                new_datagroups[dg_name] = {'name': dg_name, 'type': 'string', 'records': []}
                            new_dataggroups[dg_name]['records'].append({'name': record_name, 'data': record_data})
                
                for dg_name, new_dg in new_datagroups.items():
                    existing_dg = next((dg for dg in datagroups if dg['name'] == dg_name), None)
                    if existing_dg:
                        existing_dg['records'].extend(new_dg['records'])
                    else:
                        datagroups.append(new_dg)
                
                write_json(DATAGROUPS_FILE, datagroups)
                
                flash('Data groups imported successfully from CSV!')
            else:
                flash(f'CSV Linting Error: {message}')
            return redirect(url_for('index'))
    return render_template('import_values.html', import_type='CSV', action='Import Data Group from CSV', datagroups=datagroups)

@app.route('/import_values_csv', methods=['GET', 'POST'])
def import_values_csv():
    datagroups = read_json(DATAGROUPS_FILE)
    if request.method == 'POST':
        selected_datagroup = request.form['datagroup']
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
            valid, message = lint_csv(file_path)
            if valid:
                new_records = []
                with open(file_path, newline='') as csvfile:
                    reader = csv.reader(csvfile)
                    next(reader)  # Skip the header row if it exists
                    for row in reader:
                        if len(row) >= 2:
                            new_records.append({'name': row[0], 'data': row[1]})
                
                for dg in datagroups:
                    if dg['name'] == selected_datagroup:
                        dg['records'].extend(new_records)
                        break
                write_json(DATAGROUPS_FILE, datagroups)
                
                flash('Values imported successfully into data group from CSV!')
            else:
                flash(f'CSV Linting Error: {message}')
            return redirect(url_for('index'))
    return render_template('import_values.html', import_type='CSV', action='Import Values into Data Group from CSV', datagroups=datagroups)

@app.route('/import_datagroup_json', methods=['GET', 'POST'])
def import_datagroup_json():
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
            valid, message = lint_json(file_path)
            if valid:
                # Process the JSON file to import datagroups
                flash('Data group imported successfully from JSON!')
            else:
                flash(f'JSON Linting Error: {message}')
            return redirect(url_for('index'))
    return render_template('import_file.html', import_type='JSON', action='Import Data Group from JSON')

@app.route('/import_values_json', methods=['GET', 'POST'])
def import_values_json():
    datagroups = read_json('datagroups.json')
    if request.method == 'POST':
        selected_datagroup = request.form['datagroup']
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
            valid, message = lint_json(file_path)
            if valid:
                # Process the JSON file to import values into the selected datagroup
                flash('Values imported successfully into data group from JSON!')
            else:
                flash(f'JSON Linting Error: {message}')
            return redirect(url_for('index'))
    return render_template('import_values.html', import_type='JSON', action='Import Values into Data Group from JSON', datagroups=datagroups)

@app.route('/export_datagroup_csv', methods=['GET', 'POST'])
def export_datagroup_csv():
    datagroups = read_json(DATAGROUPS_FILE)
    if request.method == 'POST':
        selected_datagroups = request.form.getlist('datagroups')
        print(f'Selected Data Groups for CSV: {selected_datagroups}')  # Debug print
        if selected_datagroups:
            csvfile = BytesIO()
            wrapper = TextIOWrapper(csvfile, 'utf-8', newline='')
            writer = csv.writer(wrapper)
            writer.writerow(['Data Group', 'Name', 'Data'])
            for datagroup in datagroups:
                if datagroup['name'] in selected_datagroups:
                    for record in datagroup['records']:
                        writer.writerow([datagroup['name'], record['name'], record['data']])
            wrapper.flush()
            wrapper.detach()
            csvfile.seek(0)
            return send_file(
                csvfile,
                mimetype='text/csv',
                as_attachment=True,
                download_name='datagroups.csv'
            )
    return render_template('export_datagroup.html', datagroups=datagroups, export_type='CSV')

@app.route('/export_datagroup_json', methods=['GET', 'POST'])
def export_datagroup_json():
    datagroups = read_json(DATAGROUPS_FILE)
    if request.method == 'POST':
        selected_datagroups = request.form.getlist('datagroups')
        if selected_datagroups:
            export_data = [dg for dg in datagroups if dg['name'] in selected_datagroups]
            if export_data:
                jsonfile = BytesIO()
                jsonfile.write(json.dumps(export_data).encode('utf-8'))
                jsonfile.seek(0)
                return send_file(
                    jsonfile,
                    mimetype='application/json',
                    as_attachment=True,
                    download_name='datagroups.json'
                )
    return render_template('export_datagroup.html', datagroups=datagroups, export_type='JSON')

@app.route('/big_ips')
def big_ips():
    devices = read_json(DEVICES_FILE)
    return render_template('big_ips.html', devices=devices)

if __name__ == '__main__':
    app.run(debug=True)
