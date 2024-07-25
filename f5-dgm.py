#! /usr/bin/env python3
import json
import os
import requests
from flask import Flask, render_template, request, redirect, url_for, flash
from requests.auth import HTTPBasicAuth
import urllib3
from encryption import encrypt_password, decrypt_password  # Correctly import encryption functions

# Disable SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

app = Flask(__name__)
app.secret_key = 'your_secret_key'

# File paths
DEVICES_FILE = 'devices.json'
DATAGROUPS_FILE = 'datagroups.json'

# Ensure the JSON files exist
for filename in [DEVICES_FILE, DATAGROUPS_FILE]:
    if not os.path.exists(filename):
        with open(filename, 'w') as f:
            json.dump([], f)

def read_json(file):
    try:
        with open(file, 'r') as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return []

def write_json(file, data):
    with open(file, 'w') as f:
        json.dump(data, f, indent=4)

def import_datagroups_from_bigip(device):
    try:
        url = f"https://{device['address']}/mgmt/tm/ltm/data-group/internal"
        decrypted_password = decrypt_password(device['password'])
        if not decrypted_password:
            flash('Failed to decrypt the password for device: ' + device['name'])
            return None
        auth = HTTPBasicAuth(device['username'], decrypted_password)
        headers = {'Content-Type': 'application/json'}
        
        response = requests.get(url, auth=auth, headers=headers, verify=False)
        
        if response.status_code == 200:
            data_groups = response.json().get('items', [])
            return [{
                'name': dg['name'],
                'type': dg['type'],
                'description': dg.get('description', 'N/A'),
                'records': dg.get('records', [])
            } for dg in data_groups]
        else:
            flash('Failed to retrieve data groups from the device.')
            return None
    except KeyError as e:
        flash(f'Missing key in device configuration: {e}')
        return None

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

@app.route('/add_device', methods=['GET', 'POST'])
def add_device():
    if request.method == 'POST':
        name = request.form['name']
        address = request.form['address']
        username = request.form['username']
        password = request.form['password']
        
        if is_device_reachable(address):
            devices = read_json(DEVICES_FILE)
            encrypted_password = encrypt_password(password)  # Encrypt the password before saving
            devices.append({'name': name, 'address': address, 'username': username, 'password': encrypted_password})
            write_json(DEVICES_FILE, devices)
            flash('Device added successfully!')
        else:
            flash('Failed to reach the device. Please check the address and try again.')
        
        return redirect(url_for('index'))
    return render_template('add_device.html')

@app.route('/remove_device', methods=['GET', 'POST'])
def remove_device():
    devices = read_json(DEVICES_FILE)
    if request.method == 'POST':
        name = request.form['name']
        confirm = request.form.get('confirm')
        
        if confirm:
            devices = [device for device in devices if device['name'] != name]
            write_json(DEVICES_FILE, devices)
            flash('Device removed successfully!')
        else:
            flash('Please confirm the removal of the device.')
        
        return redirect(url_for('index'))
    return render_template('remove_device.html', devices=devices)

@app.route('/add_datagroup', methods=['GET', 'POST'])
def add_datagroup():
    if request.method == 'POST':
        name = request.form['name']
        type = request.form['type']
        records = []
        keys = request.form.getlist('records_key')
        values = request.form.getlist('records_value')
        for key, value in zip(keys, values):
            records.append({'key': key, 'value': value})
        datagroups = read_json(DATAGROUPS_FILE)
        datagroups.append({'name': name, 'type': type, 'records': records})
        write_json(DATAGROUPS_FILE, datagroups)
        flash('Data group added successfully!')
        return redirect(url_for('index'))
    return render_template('add_datagroup.html')

@app.route('/remove_datagroup', methods=['GET', 'POST'])
def remove_datagroup():
    datagroups = read_json(DATAGROUPS_FILE)
    if request.method == 'POST':
        name = request.form['name']
        confirm = request.form.get('confirm')
        
        if confirm:
            datagroups = [dg for dg in datagroups if dg['name'] != name]
            write_json(DATAGROUPS_FILE, datagroups)
            flash('Data group removed successfully!')
        else:
            flash('Please confirm the removal of the data group.')
        
        return redirect(url_for('index'))
    return render_template('remove_datagroup.html', datagroups=datagroups)

@app.route('/update_datagroup', methods=['GET', 'POST'])
def update_datagroup():
    datagroups = read_json(DATAGROUPS_FILE)
    if request.method == 'POST':
        name = request.form['name']
        new_records = []
        keys = request.form.getlist('records_key')
        values = request.form.getlist('records_value')
        for key, value in zip(keys, values):
            new_records.append({'key': key, 'value': value})
        for dg in datagroups:
            if dg['name'] == name:
                dg['records'] = new_records
                break
        write_json(DATAGROUPS_FILE, datagroups)
        flash('Data group updated successfully!')
        return redirect(url_for('index'))
    return render_template('update_datagroup.html', datagroups=datagroups)

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
        selected_datagroup = request.form['datagroup']
        selected_devices = request.form.getlist('devices')
        
        datagroup = next((dg for dg in datagroups if dg['name'] == selected_datagroup), None)
        
        if not datagroup:
            flash('Selected data group not found.')
            return redirect(url_for('deploy_datagroups'))

        failed_devices = []
        for device_name in selected_devices:
            device = next((d for d in devices if d['name'] == device_name), None)
            if device:
                success = deploy_datagroup_to_device(device, datagroup)
                if not success:
                    failed_devices.append(device_name)
        
        if failed_devices:
            flash(f'Failed to deploy to devices: {", ".join(failed_devices)}')
        else:
            flash('Data group deployed successfully to all selected devices!')
        
        return redirect(url_for('index'))
    
    return render_template('deploy_datagroups.html', devices=devices, datagroups=datagroups)

def deploy_datagroup_to_device(device, datagroup):
    url = f"https://{device['address']}/mgmt/tm/ltm/data-group/internal"
    decrypted_password = decrypt_password(device['password'])
    if not decrypted_password:
        flash(f'Failed to decrypt the password for device: {device["name"]}')
        return False
    
    auth = HTTPBasicAuth(device['username'], decrypted_password)
    headers = {'Content-Type': 'application/json'}
    
    data = {
        'name': datagroup['name'],
        'type': datagroup['type'],
        'records': [{'name': record['key'], 'data': record['value']} for record in datagroup['records']]
    }
    
    response = requests.post(url, auth=auth, headers=headers, json=data, verify=False)
    
    if response.status_code in [200, 201]:
        return True
    else:
        print(f"Failed to deploy to {device['name']}: {response.text}")
        return False

@app.route('/flush_datagroups', methods=['POST'])
def flush_datagroups():
    try:
        write_json(DATAGROUPS_FILE, [])
        flash('Local data-group cache flushed successfully!')
    except Exception as e:
        flash(f'Error flushing data-group cache: {str(e)}')
    return redirect(url_for('index'))

if __name__ == '__main__':
    app.run(debug=True)
