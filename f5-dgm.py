#! /usr/bin/env python3

from requests.auth import HTTPBasicAuth
from flask import Flask, render_template, request, redirect, url_for, flash
import requests
import json
import os
import urllib3

# Disable SSL self-signed certificates 
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
    url = f"https://{device['address']}/mgmt/tm/ltm/data-group/internal"
    auth = HTTPBasicAuth(device['username'], device['password'])
    headers = {'Content-Type': 'application/json'}
    
    response = requests.get(url, auth=auth, headers=headers, verify=False)
    
    if response.status_code == 200:
        data_groups = response.json().get('items', [])
        return [{'name': dg['name'], 'type': dg['type'], 'records': dg.get('records', [])} for dg in data_groups]
    else:
        return None

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
        devices = read_json(DEVICES_FILE)
        devices.append({'name': name, 'address': address})
        write_json(DEVICES_FILE, devices)
        flash('Device added successfully!')
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
        records = request.form.getlist('records')
        datagroups = read_json(DATAGROUPS_FILE)
        datagroups.append({'name': name, 'type': type, 'records': records})
        write_json(DATAGROUPS_FILE, datagroups)
        flash('Data group added successfully!')
        return redirect(url_for('index'))
    return render_template('add_datagroup.html')

@app.route('/remove_datagroup', methods=['GET', 'POST'])
def remove_datagroup():
    if request.method == 'POST':
        name = request.form['name']
        datagroups = read_json(DATAGROUPS_FILE)
        datagroups = [dg for dg in datagroups if dg['name'] != name]
        write_json(DATAGROUPS_FILE, datagroups)
        flash('Data group removed successfully!')
        return redirect(url_for('index'))
    return render_template('remove_datagroup.html')

@app.route('/update_datagroup', methods=['GET', 'POST'])
def update_datagroup():
    if request.method == 'POST':
        name = request.form['name']
        new_records = request.form.getlist('records')
        datagroups = read_json(DATAGROUPS_FILE)
        for dg in datagroups:
            if dg['name'] == name:
                dg['records'] = new_records
                break
        write_json(DATAGROUPS_FILE, datagroups)
        flash('Data group updated successfully!')
        return redirect(url_for('index'))
    return render_template('update_datagroup.html')

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
                current_datagroups.extend(data_groups)
                write_json(DATAGROUPS_FILE, current_datagroups)
                flash('Data groups imported successfully!')
            else:
                flash('Failed to import data groups from the device.')
        else:
            flash('Device not found.')
        
        return redirect(url_for('index'))
    devices = read_json(DEVICES_FILE)
    return render_template('import_datagroups.html', devices=devices)

if __name__ == '__main__':
    app.run(debug=True)
