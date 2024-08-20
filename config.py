#!/usr/bin/env python3

# config.py

# Path to the file containing the secret key for session management and other security-related needs
SECRET_KEY_FILE = 'secret.key'

# File paths for storing device and data group information
DEVICES_FILE = 'devices.json'
DATAGROUPS_FILE = 'datagroups.json'
HIERARCHY_FILE = 'hierarchy.json'
DNS_RESOLVERS_FILE = 'dns_resolvers.json'

# Define built-in data groups for TMOS (Traffic Management Operating System)
# These data groups are predefined and can be used for various purposes within the application

# Data group for AOL IP addresses
TMOS_BUILT_IN_DATA_GROUPS = [
    {
        "name": "aol",
        "partition": "Common",
        "type": "ip",
        "records": [
            {"name": "64.12.96.0/19", "data": ""},
            {"name": "195.93.16.0/20", "data": ""},
            {"name": "195.93.48.0/22", "data": ""},
            {"name": "195.93.64.0/19", "data": ""},
            {"name": "195.93.96.0/19", "data": ""},
            {"name": "198.81.0.0/22", "data": ""},
            {"name": "198.81.8.0/23", "data": ""},
            {"name": "198.81.16.0/20", "data": ""},
            {"name": "202.67.65.128/25", "data": ""},
            {"name": "205.188.112.0/20", "data": ""},
            {"name": "205.188.146.144/30", "data": ""},
            {"name": "205.188.192.0/20", "data": ""},
            {"name": "205.188.208.0/23", "data": ""},
            {"name": "207.200.112.0/21", "data": ""}
        ]
    },
    # Data group for image file extensions
    {
        "name": "images",
        "partition": "Common",
        "type": "string",
        "records": [
            {"name": ".bmp", "data": ""},
            {"name": ".gif", "data": ""},
            {"name": ".jpg", "data": ""}
        ]
    },
    # Data group for private network IP ranges
    {
        "name": "private_net",
        "partition": "Common",
        "type": "ip",
        "records": [
            {"name": "10.0.0.0/8", "data": ""},
            {"name": "172.16.0.0/12", "data": ""},
            {"name": "192.168.0.0/16", "data": ""}
        ]
    },
    # Data group for Microsoft Office OFBA (Outlook Forms Based Authentication) support
    {
        "name": "sys_APM_MS_Office_OFBA_DG",
        "partition": "Common",
        "description": "This internal data-group is used in _sys_APM_MS_Office_OFBA_Support irule",
        "type": "string",
        "records": [
            {"name": "ie_sp_session_sharing_enabled", "data": "0"},
            {"name": "ie_sp_session_sharing_inactivity_timeout", "data": "60"},
            {"name": "ofba_auth_dialog_size", "data": "800x600"},
            {"name": "useragent1", "data": "microsoft data access internet publishing provider"},
            {"name": "useragent2", "data": "office protocol discovery"},
            {"name": "useragent3", "data": "microsoft office"},
            {"name": "useragent4", "data": "non-browser"},
            {"name": "useragent5", "data": "msoffice 12"},
            {"name": "useragent6", "data": "microsoft-webdav-miniredir"},
            {"name": "useragent7", "data": "webdav-miniredir"},
            {"name": "useragent9", "data": "ms frontpage 1[23456789]"},
            {"name": "useragent10", "data": "onenote"}
        ]
    }
]