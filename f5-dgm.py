#! /usr/bin/env python3

import json
import os
import requests
import urllib3
import csv
import ipaddress
import socket
import logging
import shutil
import threading
import time
import zipfile
from config import DSC_GROUPS_FILE, DATAGROUPS_FILE, TMOS_BUILT_IN_DATA_GROUPS,SNAPSHOTS_DIR
from flask_talisman import Talisman
from flask import Flask, render_template, request, redirect, url_for, flash, send_file, jsonify, make_response
from requests.auth import HTTPBasicAuth
from encryption import encrypt_password, decrypt_password
from werkzeug.utils import secure_filename
from datetime import datetime, timezone
from io import StringIO, BytesIO
from ipaddress import ip_address, ip_network
from helper_functions import *

# Configure logging
logging.basicConfig(level=logging.ERROR)

# Disable SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Create the Flask app
app = Flask(__name__)

# Enforce HTTPS
talisman = Talisman(app)

# Monitor the DATAGROUPS_FILE for changes and takes a snapshot if changes are detected
# Start the file monitoring in a separate thread
try:
    # Start the file monitoring in a separate thread
    monitoring_thread = threading.Thread(target=monitor_file)
    monitoring_thread.daemon = True
    monitoring_thread.start()
    print("File monitoring thread started successfully.")
except Exception as e:
    print(f"Error starting file monitoring thread: {e}")

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
            raise ValueError('Secret key file is empty. Execute the create_secret_key.py file to create one and update config.py to point to the new file. For security purposes, save this in a folder that only has read permission by the local user, such as ~/')
except (FileNotFoundError, PermissionError) as e:
    logging.error(f"Error: {e}")
    exit(1)
except ValueError as e:
    logging.error(f"Error: {e}")
    exit(1)
except Exception as e:
    logging.error(f"An unexpected error occurred while reading 'secret.key': {e}")
    exit(1)

# Create the Uploads folder if necessary
app.config['UPLOAD_FOLDER'] = os.path.join(os.getcwd(), 'uploads')
try:
    if not os.path.exists(app.config['UPLOAD_FOLDER']):
        os.makedirs(app.config['UPLOAD_FOLDER'])
except OSError as e:
    logging.error(f"Failed to create upload folder: {e}")
    exit(1)

# Ensure the JSON files exist
for filename in [DSC_GROUPS_FILE, DATAGROUPS_FILE]:
    if not os.path.exists(filename):
        with open(filename, 'w') as f:
            json.dump([], f)


# App route for the root page which displays all datagroups
@app.route('/')
def index():
    try:
        dsc_groups = read_json(DSC_GROUPS_FILE)
    except Exception as e:
        logging.error(f"Error reading {DSC_GROUPS_FILE}: {e}")
        dsc_groups = []

    try:
        datagroups = read_json(DATAGROUPS_FILE)
    except Exception as e:
        logging.error(f"Error reading {DATAGROUPS_FILE}: {e}")
        datagroups = []

    return render_template('index.html', dsc_groups=dsc_groups, datagroups=datagroups)

# App route for creating a new data group
@app.route('/add_datagroup', methods=['GET', 'POST'])
def add_datagroup():
    if request.method == 'POST':
        dg_name = request.form.get('name')
        description = request.form.get('description')
        dg_type = request.form.get('type')

        if not dg_name or not dg_type:
            flash('All fields are required!')
            return redirect(url_for('add_datagroup'))

        records = []
        names = request.form.getlist('records_name')
        datas = request.form.getlist('records_data')
        records = [{'name': name, 'data': data} for name, data in zip(request.form.getlist('records_name'), request.form.getlist('records_data'))]
        
        try:
            datagroups = read_json(DATAGROUPS_FILE)
            datagroups.append({'name': dg_name, 'description': description, 'type': dg_type, 'records': records})
            write_json(DATAGROUPS_FILE, datagroups)
            flash('Data group added successfully!')
        except Exception as e:
            flash(f'An error occurred: {e}')

        return redirect(url_for('index'))

    return render_template('add_datagroup.html', timestamp = f'{datetime.now(timezone.utc).strftime('%m-%d-%Y at %H:%M:%S')} UTC')

# App route for deleting a local copy of a datagroup
@app.route('/remove_datagroup', methods=['POST'])
def remove_datagroup():
    try:
        datagroup_name = request.form.get('datagroup_name')
        datagroups = read_json(DATAGROUPS_FILE)

        # Check if the datagroup exists before attempting to remove it
        if not any(dg['name'] == datagroup_name for dg in datagroups):
            flash('Data group not found!')
            return redirect(url_for('index'))

        datagroups = [dg for dg in datagroups if dg['name'] != datagroup_name]
        write_json(DATAGROUPS_FILE, datagroups)
        flash('Data group removed successfully!')
    except KeyError:
        flash('Invalid form data!')
    except FileNotFoundError:
        flash('Data groups file not found!')
    except Exception as e:
        flash(f'An error occurred: {e}')
    
    return redirect(url_for('index'))

# App route for flushing all local datagroups
@app.route('/flush_datagroups', methods=['GET'])
def flush_datagroups():
    try:
        write_json(DATAGROUPS_FILE, [])
        flash('Local data-group cache flushed successfully!')
    except Exception as e:
        flash(f'Unexpected error: {str(e)}')
    return redirect(url_for('index'))

# App route for exporting datagroup to CSV
@app.route('/export_datagroup_csv', methods=['POST'])
def export_datagroup_csv():
    try:
        datagroups = read_json(DATAGROUPS_FILE)
        datagroup_name = request.form.get('datagroup_name')
        datagroup = next((dg for dg in datagroups if dg['name'] == datagroup_name), None)

        if not datagroup:
            flash(f'Data group {datagroup_name} not found')
            return redirect(url_for('index'))

        # Create a string-based buffer and write CSV data to it
        csv_string = StringIO()
        writer = csv.writer(csv_string)
        writer.writerow(['Data Group', 'Type', 'Description', 'Name', 'Data'])

        for record in datagroup['records']:
            writer.writerow([datagroup['name'], datagroup['type'], datagroup['description'], record['name'], record.get('data', '')])

        # Convert the string buffer to a bytes buffer
        csv_bytes = BytesIO(csv_string.getvalue().encode('utf-8'))
        csv_bytes.seek(0)

        return send_file(
            csv_bytes,
            mimetype='text/csv',
            as_attachment=True,
            download_name=f'datagroup-{datagroup['name']}-{datetime.now(timezone.utc).strftime('%Y-%m-%d_%H-%M-%S')}UTC.csv'
        )
    except Exception as e:
        flash(f'Unexpected error: {str(e)}')

# App Route for exporting to JSON
@app.route('/export_datagroup_json', methods=['POST'])
def export_datagroup_json():
    try:
        datagroups = read_json(DATAGROUPS_FILE)
        datagroup_name = request.form.get('datagroup_name')
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
            download_name=f'datagroup-{datagroup_name}-{datetime.now(timezone.utc).strftime('%Y-%m-%d_%H-%M-%S')}UTC.json'
        )
    except Exception as e:
        flash(f'Unexpected error: {str(e)}')

# App route for importing a datagroup from file
@app.route('/import_from_file', methods=['GET', 'POST'])
def import_from_file():
    if request.method == 'POST':
        if 'file' not in request.files:
            flash('No file specified')
            return redirect(request.url)
        file = request.files['file']
        if file.filename == '':
            flash('No selected file')
            return redirect(request.url)
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(file_path)

            try:
                if file.filename.endswith('.csv'):
                    valid_csv, message_csv = lint_datagroup_csv(file_path)
                    if not valid_csv:
                        flash(f'CSV Linting Error: {message_csv}')
                        return redirect(request.url)
                    new_datagroups = process_csv(file_path)
                elif file.filename.endswith('.json'):
                    new_datagroups = process_json(file_path)

                datagroups = read_json(DATAGROUPS_FILE)
                datagroups = merge_datagroups(datagroups, new_datagroups)
                write_json(DATAGROUPS_FILE, datagroups)
                flash('Data groups imported successfully!')

            except ValueError as ve:
                flash(str(ve))
            except Exception as e:
                flash(f'Error processing file: {str(e)}')
            return redirect(url_for('index'))

        return redirect(url_for('index'))

    # Render the import_from_file template for GET requests
    return render_template('import_from_file.html')

# App route for importing a datagroup from URL
@app.route('/import_from_url', methods=['GET', 'POST'])
def import_from_url():
    if request.method == 'POST':
        url = request.form['url']
        if not url:
            flash('URL is required')
            return redirect(request.url)
        try:
            response = requests.get(url, verify=False, timeout=15)
            response.raise_for_status()
        except requests.exceptions.Timeout:
            flash(f'Timeout exceeded while trying to reach {dsc_group["name"]}')
            return []
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
    dsc_groups = read_json(DSC_GROUPS_FILE)
    dsc_group_datagroups = []

    for dsc_group in dsc_groups:
        datagroups = fetch_datagroups_from_bigip(dsc_group)
        if datagroups:
            dsc_group['datagroups'] = datagroups
            dsc_group_datagroups.append(dsc_group)

    if request.method == 'POST':
        ignore_builtin = request.form.get('ignore_builtin') == 'on'
        selected_datagroups = {}
        for dsc_group in dsc_group_datagroups:
            datagroups = request.form.getlist(f'datagroups_{dsc_group["name"]}')
            for datagroup in datagroups:
                if ignore_builtin and is_builtin_datagroup(datagroup):
                    continue
                if datagroup not in selected_datagroups:
                    selected_datagroups[datagroup] = dsc_group
                else:
                    flash(f'Duplicate data group name "{datagroup}" found across multiple DSCs. Please ensure unique data group names.')
                    return render_template('import_from_bigips.html', dsc_groups=dsc_group_datagroups, TMOS_BUILT_IN_DATA_GROUPS=TMOS_BUILT_IN_DATA_GROUPS)

        success_count = 0
        failure_count = 0

        for datagroup, dsc_group in selected_datagroups.items():
            if import_datagroup_from_dsc_group(dsc_group, datagroup):
                success_count += 1
            else:
                failure_count += 1

        flash(f'Successfully imported {success_count} data groups. Failed to import {failure_count} data groups.')
        return redirect(url_for('index'))

    return render_template('import_from_bigips.html', dsc_groups=dsc_group_datagroups, TMOS_BUILT_IN_DATA_GROUPS=TMOS_BUILT_IN_DATA_GROUPS)


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
    description = ""
    selected_name = request.args.get('name')
    if selected_name:
        selected_datagroup = next((dg for dg in datagroups if dg['name'] == selected_name), None)
    if 'description' in selected_datagroup:
        description = selected_datagroup['description']
    return render_template('update_datagroup.html', datagroups=datagroups, selected_datagroup=selected_datagroup, description=description)

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

# App route for the BIG-IP dsc_groups page
@app.route('/big_ips')
def big_ips():
    try:
        dsc_groups = read_json(DSC_GROUPS_FILE)
        return render_template('big_ips.html', dsc_groups=dsc_groups)
    except FileNotFoundError:
        flash('DSC groups file not found', 'error')
        return redirect(url_for('index'))
    except json.JSONDecodeError:
        flash('Error decoding JSON from DSC groups file', 'error')
        return redirect(url_for('index'))
    except Exception as e:
        flash(f'An unexpected error occurred: {str(e)}', 'error')
        return redirect(url_for('index'))

# App route for adding a BIG-IP DSC group
@app.route('/add_dsc_group', methods=['GET', 'POST'])
def add_dsc_group():
    if request.method == 'POST':
        name = request.form.get('name')
        address = request.form.get('address')
        username = request.form['username']
        password = request.form['password']
        
        if verify_dsc_group_credentials(address, username, password):
            dsc_groups = read_json(DSC_GROUPS_FILE)
            dsc_groups.append({'name': name, 'address': address, 'username': username, 'password': encrypt_password(password)})
            write_json(DSC_GROUPS_FILE, dsc_groups)
            flash('DSC group added successfully!')
            return redirect(url_for('big_ips'))    
        else:
            flash('Failed to verify the DSC group credentials.')
        
    return render_template('add_dsc_group.html')

#App route for removing a BIG-IP DSC group
@app.route('/remove_dsc_group', methods=['POST'])
def remove_dsc_group():
    dsc_group_name = request.form['dsc_group_name']
    dsc_groups = read_json(DSC_GROUPS_FILE)
    dsc_groups = [dsc_group for dsc_group in dsc_groups if dsc_group['name'] != dsc_group_name]
    write_json(DSC_GROUPS_FILE, dsc_groups)
    flash('DSC group removed successfully!')
    return redirect(url_for('big_ips'))

#App route for updating DSC group credentials
@app.route('/update_dsc_group_credentials', methods=['GET', 'POST'])
def update_dsc_group_credentials():
    if request.method == 'POST':
        dsc_group_name = request.form['dsc_group_name']
        dsc_groups = read_json(DSC_GROUPS_FILE)
        dsc_group = next((d for d in dsc_groups if d['name'] == dsc_group_name), None)
        if dsc_group:
            new_username = request.form['username']
            new_password = request.form['password']
            if verify_dsc_group_credentials(dsc_group['address'], new_username, new_password):
                dsc_group['username'] = new_username
                dsc_group['password'] = encrypt_password(new_password)
                write_json(DSC_GROUPS_FILE, dsc_groups)
                flash('DSC group credentials updated successfully!')
            else:
                flash('Failed to verify the new credentials.')
            return redirect(url_for('big_ips'))
        else:
            flash('DSC group not found!')
            return redirect(url_for('big_ips'))
    else:
        dsc_group_name = request.args.get('dsc_group_name')
        dsc_groups = read_json(DSC_GROUPS_FILE)
        dsc_group = next((d for d in dsc_groups if d['name'] == dsc_group_name), None)
        if dsc_group:
            return render_template('update_dsc_group_credentials.html', dsc_group=dsc_group)
        else:
            flash('DSC group not found!')
            return redirect(url_for('big_ips'))

# App route to browsing datagroups on the BIG-IP
@app.route('/browse_datagroups/<dsc_group_name>', methods=['GET'])
def browse_datagroups(dsc_group_name):
    dsc_groups = read_json(DSC_GROUPS_FILE)
    dsc_group = next((d for d in dsc_groups if d['name'] == dsc_group_name), None)
    if not dsc_group:
        flash(f'DSC group {dsc_group_name} not found')
        return redirect(url_for('big_ips'))

    datagroups = fetch_datagroups_from_bigip(dsc_group)
    if not datagroups:
        flash(f'No data groups found on DSC group {dsc_group_name}')
        return redirect(url_for('big_ips'))

    irules = fetch_irules_from_bigip(dsc_group)
    return render_template('browse_datagroups.html', dsc_group=dsc_group, datagroups=datagroups, irules=irules)

@app.route('/get_irules', methods=['POST'])
def get_irules():
    dsc_group_name = request.form.get('dsc_group_name')
    datagroup_name = request.form.get('datagroup_name')

    # Replace with your actual logic to get the dsc_group address and credentials
    dsc_group_address = get_dsc_group_address(dsc_group_name)
    username = get_dsc_group_username(dsc_group_name)
    password = get_dsc_group_password(dsc_group_name)

    # iControl REST API endpoint to get iRules
    url = f"https://{dsc_group_address}/mgmt/tm/ltm/rule"

    response = requests.get(url, auth=(username, password), verify=False)
    irules = []

    if response.status_code == 200:
        rules = response.json().get('items', [])
        for rule in rules:
            if datagroup_name in rule.get('apiAnonymous', ''):
                irules.append(rule['name'])

    return jsonify({'irules': irules})

@app.route('/export_all_datagroups_json/<dsc_group_name>', methods=['GET'])
def export_all_datagroups_json(dsc_group_name):
    dsc_groups = read_json(DSC_GROUPS_FILE)
    dsc_group = next((d for d in dsc_groups if d['name'] == dsc_group_name), None)
    if not dsc_group:
        flash(f'dsc_group {dsc_group_name} not found')
        return redirect(url_for('big_ips'))

    datagroups = fetch_datagroups_from_bigip(dsc_group)
    if not datagroups:
        flash(f'No data groups found on dsc_group {dsc_group_name}')
        return redirect(url_for('big_ips'))

    filename = f'all-data-groups-{dsc_group['address']}-{datetime.now(timezone.utc).strftime('%Y-%m-%d_%H-%M-%S')}UTC.json'
    
    json_bytes = BytesIO(json.dumps(datagroups).encode('utf-8'))
    json_bytes.seek(0)

    return send_file(
        json_bytes,
        mimetype='application/json',
        as_attachment=True,
        download_name=filename
    )

@app.route('/export_all_datagroups_csv/<dsc_group_name>', methods=['GET'])
def export_all_datagroups_csv(dsc_group_name):
    dsc_groups = read_json(DSC_GROUPS_FILE)
    dsc_group = next((d for d in dsc_groups if d['name'] == dsc_group_name), None)
    if not dsc_group:
        flash(f'dsc_group {dsc_group_name} not found')
        return redirect(url_for('big_ips'))

    datagroups = fetch_datagroups_from_bigip(dsc_group)
    if not datagroups:
        flash(f'No data groups found on dsc_group {dsc_group_name}')
        return redirect(url_for('big_ips'))

    filename = f'all-data-groups-{dsc_group['address']}-{datetime.now(timezone.utc).strftime('%Y-%m-%d_%H-%M-%S')}UTC.csv'

    csv_string = StringIO()
    writer = csv.writer(csv_string)
    writer.writerow(['Data Group', 'Partition', 'Type', 'Description', 'Name', 'Data'])

    for datagroup in datagroups:
        for record in datagroup['records']:
            writer.writerow([datagroup['name'], datagroup['partition'], datagroup['type'], datagroup['description'], record['name'], record['data']])

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
    dsc_group_name = request.args.get('dsc_group_name')
    datagroup_name = request.args.get('datagroup_name')

    dsc_groups = read_json(DSC_GROUPS_FILE)
    dsc_group = next((d for d in dsc_groups if d['name'] == dsc_group_name), None)
    if not dsc_group:
        flash(f'dsc_group {dsc_group_name} not found')
        return redirect(url_for('index'))

    datagroup = fetch_and_filter_datagroup_from_dsc_group(dsc_group, datagroup_name)
    if not datagroup:
        flash(f'Data group {datagroup_name} not found on dsc_group {dsc_group_name}')
        return redirect(url_for('index'))

    # Create a string-based buffer and write CSV data to it
    csv_string = StringIO()
    writer = csv.writer(csv_string)
    writer.writerow(['Data Group', 'Type', 'Description', 'Name', 'Data'])

    for record in datagroup.get('records', []):
        writer.writerow([
            datagroup.get('name', ''), 
            datagroup.get('type', ''), 
            datagroup.get('description', ''), 
            record.get('name', ''), 
            record.get('data', '')
        ])

    # Convert the string buffer to a bytes buffer
    csv_bytes = BytesIO(csv_string.getvalue().encode('utf-8'))
    csv_bytes.seek(0)

    filename = f"datagroup-{datagroup_name}_exported_from_{dsc_group['address']}-{datetime.now(timezone.utc).strftime('%Y-%m-%d_%H-%M-%S')}UTC.csv"
    return send_file(
        csv_bytes,
        mimetype='text/csv',
        as_attachment=True,
        download_name=filename
    )

# Route to export datagroup from BIG-IP to JSON
@app.route('/export_datagroup_from_bigip_json', methods=['GET'])
def export_datagroup_from_bigip_json():
    dsc_group_name = request.args.get('dsc_group_name')
    datagroup_name = request.args.get('datagroup_name')

    dsc_groups = read_json(DSC_GROUPS_FILE)
    dsc_group = next((d for d in dsc_groups if d['name'] == dsc_group_name), None)
    if not dsc_group:
        flash(f'dsc_group {dsc_group_name} not found')
        return redirect(url_for('index'))

    datagroup = fetch_and_filter_datagroup_from_dsc_group(dsc_group, datagroup_name)
    if not datagroup:
        flash(f'Data group {datagroup_name} not found on dsc_group {dsc_group_name}')
        return redirect(url_for('index'))

    # Convert the datagroup to JSON bytes
    json_bytes = BytesIO(json.dumps(datagroup).encode('utf-8'))
    json_bytes.seek(0)

    filename = f"datagroup-{datagroup_name}_exported_from_{dsc_group['address']}-{datetime.now(timezone.utc).strftime('%Y-%m-%d_%H-%M-%S')}UTC.json"
    return send_file(
        json_bytes,
        mimetype='application/json',
        as_attachment=True,
        download_name=filename
    )

# Helper function to fetch datagroup from BIG-IP and filter fields

# Route for deleting datagroups on BIG-IPs
@app.route('/remove_datagroup_from_bigips', methods=['GET', 'POST'])
def remove_datagroup_from_bigips():
    dsc_groups = read_json(DSC_GROUPS_FILE)
    dsc_group_datagroups = []

    # Fetch datagroups from each dsc_group
    for dsc_group in dsc_groups:
        datagroups = fetch_datagroups_from_bigip(dsc_group)
        if datagroups:
            for dg in datagroups:
                dg['partition'] = dg.get('partition', 'Common')
                dg['records_count'] = len(dg.get('records', []))
            dsc_group['datagroups'] = datagroups
            dsc_group_datagroups.append(dsc_group)

    if request.method == 'POST':
        selected_datagroups = request.form.getlist('selected_datagroups')
        failed_removals = []

        for item in selected_datagroups:
            dsc_group_name, datagroup_name = item.split('|')
            dsc_group = next((d for d in dsc_groups if d['name'] == dsc_group_name), None)
            if dsc_group:
                success = delete_datagroup_from_dsc_group(dsc_group, datagroup_name)
                if not success:
                    failed_removals.append((dsc_group_name, datagroup_name))

        if failed_removals:
            flash(f'Failed to delete data groups from DSC: {failed_removals}')
        else:
            flash('Data groups deleted successfully from all selected DSC!')

        return redirect(url_for('index'))

    return render_template('remove_datagroup_from_bigips.html', dsc_groups=dsc_group_datagroups)


# App Route for deploying data groups to BIG-IP(s)
@app.route('/deploy_datagroups', methods=['GET', 'POST'])
def deploy_datagroups():
    dsc_groups = read_json(DSC_GROUPS_FILE)
    datagroups = read_json(DATAGROUPS_FILE)
    
    if request.method == 'POST':
        selected_dsc_groups = request.form.getlist('dsc_groups')
        selected_datagroups = request.form.getlist('datagroups')
        
        if not selected_dsc_groups or not selected_datagroups:
            flash('Please select at least one dsc_group and one data group to deploy.')
            return redirect(url_for('deploy_datagroups'))

        failed_dsc_groups = []
        
        for dsc_group_name in selected_dsc_groups:
            dsc_group = next((d for d in dsc_groups if d['name'] == dsc_group_name), None)
            if dsc_group:
                for dg_name in selected_datagroups:
                    datagroup = next((dg for dg in datagroups if dg['name'] == dg_name), None)
                    if datagroup:
                        if not deploy_datagroup_to_dsc_group(dsc_group, datagroup):
                            failed_dsc_groups.append(dsc_group_name)
                        else:
                            flash(f"Deployed datagroup {datagroup['name']} to {dsc_group['name']} successfully!")
        
        if failed_dsc_groups:
            flash(f'Failed to deploy data groups to dsc_groups: {", ".join(failed_dsc_groups)}')
        return redirect(url_for('index'))
    
    return render_template('deploy_datagroups.html', dsc_groups=dsc_groups, datagroups=datagroups)

@app.route('/snapshots', methods=['GET'])
def snapshots():
    snapshots = [f for f in os.listdir(SNAPSHOTS_DIR) if f.endswith('.json')]
    return render_template('snapshots.html', snapshots=snapshots)

@app.route('/snapshots/list', methods=['GET'])
def list_snapshots():
    snapshots = jsonify(snapshots)
    return snapshots

@app.route('/snapshots/revert/<snapshot>', methods=['POST'])
def revert_snapshot(snapshot):
    snapshot_path = os.path.join(SNAPSHOTS_DIR, snapshot)
    if os.path.exists(snapshot_path):
        shutil.copy2(snapshot_path, DATAGROUPS_FILE)
        return jsonify({"message": "Reverted successfully"}), 200
    return jsonify({"message": "Snapshot not found"}), 404

@app.route('/snapshots/delete/<snapshot>', methods=['DELETE'])
def delete_snapshot(snapshot):
    snapshot_path = os.path.join(SNAPSHOTS_DIR, snapshot)
    if os.path.exists(snapshot_path):
        os.remove(snapshot_path)
        return jsonify({"message": "Deleted successfully"}), 200
    return jsonify({"message": "Snapshot not found"}), 404

@app.route('/snapshots/delete_all', methods=['DELETE'])
def delete_all_snapshots():
    for f in os.listdir(SNAPSHOTS_DIR):
        os.remove(os.path.join(SNAPSHOTS_DIR, f))
    return jsonify({"message": "All snapshots deleted"}), 200

@app.route('/snapshots/export', methods=['GET'])
def export_snapshots():
    snapshots = [os.path.join(SNAPSHOTS_DIR, f) for f in os.listdir(SNAPSHOTS_DIR) if f.endswith('.json')]
    return jsonify({"snapshots": snapshots})

@app.route('/snapshots/download', methods=['GET'])
def download_snapshots():
    zip_path = 'snapshots.zip'
    with zipfile.ZipFile(zip_path, 'w') as zipf:
        for file in os.listdir(SNAPSHOTS_DIR):
            zipf.write(os.path.join(SNAPSHOTS_DIR, file), file)
    return send_file(zip_path, as_attachment=True)

if __name__ == '__main__':
    app.run(host="127.0.0.1", port=8443, debug=True, ssl_context='adhoc')
