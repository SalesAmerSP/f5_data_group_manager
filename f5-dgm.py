from flask import Flask, render_template, request, redirect, url_for, flash
import json
import os

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
    with open(file, 'r') as f:
        return json.load(f)

def write_json(file, data):
    with open(file, 'w') as f:
        json.dump(data, f, indent=4)

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
    if request.method == 'POST':
        name = request.form['name']
        devices = read_json(DEVICES_FILE)
        devices = [device for device in devices if device['name'] != name]
        write_json(DEVICES_FILE, devices)
        flash('Device removed successfully!')
        return redirect(url_for('index'))
    return render_template('remove_device.html')

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

if __name__ == '__main__':
    app.run(debug=True)
