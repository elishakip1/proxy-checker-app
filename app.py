from flask import Flask, request, render_template, send_from_directory, jsonify, redirect, url_for
import os
import time
import requests
from bs4 import BeautifulSoup
from concurrent.futures import ThreadPoolExecutor, as_completed
import datetime
import matplotlib.pyplot as plt
import gspread
from oauth2client.service_account import ServiceAccountCredentials
import json

app = Flask(__name__)

GOOD_PROXIES_FILE = "zero_score_proxies.txt"
PROXY_LOG_FILE = "proxy_log.txt"
MAX_WORKERS = 50
REQUEST_TIMEOUT = 4
PROXY_CHECK_HARD_LIMIT = 50 # New hard limit constant

# Google Sheets config
SCOPE = ["https://spreadsheets.google.com/feeds", "https://www.googleapis.com/auth/drive"]

def get_gsheet_client():
    json_creds = os.getenv("GOOGLE_SERVICE_ACCOUNT_JSON")
    if not json_creds:
        raise ValueError("Missing GOOGLE_SERVICE_ACCOUNT_JSON environment variable.")
    creds_dict = json.loads(json_creds)
    creds = ServiceAccountCredentials.from_json_keyfile_dict(creds_dict, SCOPE)
    return gspread.authorize(creds)

def get_sheet():
    client = get_gsheet_client()
    # Replace "UsedIPs" with your actual Google Sheet name if different
    return client.open("UsedIPs").sheet1 

def append_used_ip(ip, proxy):
    sheet = get_sheet()
    sheet.append_row([ip, proxy, str(datetime.datetime.utcnow())])

def is_ip_used(ip):
    try:
        sheet = get_sheet()
        ips = sheet.col_values(1) # Assuming IP is in the first column
        return ip in ips
    except Exception as e:
        print(f"Error checking if IP is used: {e}")
        return False

def remove_ip(ip):
    sheet = get_sheet()
    records = sheet.get_all_records()
    for i, row in enumerate(records):
        if row.get("IP") == ip: # Assuming the column header is "IP"
            sheet.delete_rows(i + 2) # +2 because sheet rows are 1-indexed and header row
            break

def list_used_ips():
    sheet = get_sheet()
    return sheet.get_all_records()

def list_good_proxies():
    if not os.path.exists(GOOD_PROXIES_FILE):
        return []
    with open(GOOD_PROXIES_FILE, "r") as f:
        return [line.strip() for line in f if line.strip()]

def get_ip_from_proxy(proxy):
    try:
        # Assuming proxy format: host:port:user:pass
        host, port, user, pw = proxy.strip().split(":")
        proxies = {
            "http": f"http://{user}:{pw}@{host}:{port}",
            "https": f"http://{user}:{pw}@{host}:{port}",
        }
        # Use a well-known IP echo service
        ip = requests.get("https://api.ipify.org", proxies=proxies, timeout=REQUEST_TIMEOUT).text
        return ip
    except Exception as e:
        print(f"❌ Failed to get IP from proxy {proxy}: {e}")
        return None

def get_fraud_score(ip):
    try:
        url = f"https://scamalytics.com/ip/{ip}"
        response = requests.get(url, timeout=REQUEST_TIMEOUT)
        if response.status_code == 200:
            soup = BeautifulSoup(response.text, 'html.parser')
            score_div = soup.find('div', class_='score')
            if score_div and "Fraud Score:" in score_div.text:
                score_text = score_div.text.strip().split(":")[1].strip()
                return int(score_text)
    except Exception as e:
        print(f"⚠️ Error checking Scamalytics for {ip}: {e}")
    return None

def single_check_proxy(proxy_line):
    ip = get_ip_from_proxy(proxy_line)
    if not ip:
        return None

    score = get_fraud_score(ip)
    if score == 0:
        return {"proxy": proxy_line, "ip": ip}
    return None

@app.route("/", methods=["GET", "POST"])
def index():
    results = []
    message = ""

    if request.method == "POST":
        proxies = []
        all_lines = []

        if 'proxyfile' in request.files and request.files['proxyfile'].filename:
            file = request.files['proxyfile']
            all_lines = file.read().decode("utf-8").strip().splitlines()
            
            # Apply the hard limit here
            proxies = all_lines[:PROXY_CHECK_HARD_LIMIT] 
            
            if len(all_lines) > PROXY_CHECK_HARD_LIMIT:
                message = f"Warning: Only the first {PROXY_CHECK_HARD_LIMIT} proxies from the uploaded file will be checked."
            elif all_lines:
                message = "Checking uploaded proxy file..."
            else:
                message = "No proxies found in the uploaded file."

        elif 'proxytext' in request.form:
            proxytext = request.form.get("proxytext", "")
            all_lines = proxytext.strip().splitlines()
            
            # Apply the hard limit here
            proxies = all_lines[:PROXY_CHECK_HARD_LIMIT]
            
            if len(all_lines) > PROXY_CHECK_HARD_LIMIT:
                message = f"Warning: Only the first {PROXY_CHECK_HARD_LIMIT} proxies from your input will be checked."
            elif all_lines:
                message = "Checking pasted proxies..."
            else:
                message = "No proxies pasted."
        
        # Ensure unique proxies and remove empty lines
        proxies = list(set(p.strip() for p in proxies if p.strip()))

        if proxies:
            with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
                futures = [executor.submit(single_check_proxy, proxy) for proxy in proxies]
                for future in as_completed(futures):
                    result = future.result()
                    if result:
                        used = is_ip_used(result["ip"])
                        results.append({
                            "proxy": result["proxy"],
                            "used": used
                        })

            if results:
                # Filter for good, unused proxies to save to file
                good_unused_proxies = [item["proxy"] for item in results if not item["used"]]
                if good_unused_proxies:
                    with open(GOOD_PROXIES_FILE, "w") as out:
                        for proxy_item in good_unused_proxies:
                            out.write(proxy_item + "\n")
                else:
                    # If no good unused proxies, clear the file or ensure it's empty
                    open(GOOD_PROXIES_FILE, "w").close()

                # Log all good proxies found (used or not)
                with open(PROXY_LOG_FILE, "a") as log:
                    log.write(f"{datetime.date.today()},{len([r for r in results if not r['used']])} good unused proxies found\n")

                if not message.startswith("Warning"): # Don't overwrite existing warnings
                    message = f"✅ {len([r for r in results if not r['used']])} good proxies found ({len([r for r in results if r['used']])} used)."
            else:
                if not message.startswith("Warning"):
                    message = "⚠️ No good proxies found."
        elif not message: # If no proxies after processing and no warning was set
            message = "⚠️ No valid proxies provided or processed."

    return render_template("index.html", results=results, message=message)

@app.route("/track-used", methods=["POST"])
def track_used():
    data = request.get_json()
    if data and "proxy" in data:
        proxy_to_track = data["proxy"]
        ip = get_ip_from_proxy(proxy_to_track)
        if ip:
            append_used_ip(ip, proxy_to_track)
        return jsonify({"status": "success"})
    return jsonify({"status": "error"}), 400

@app.route("/delete-used-ip/<ip>")
def delete_used_ip(ip):
    remove_ip(ip)
    return redirect(url_for("admin"))

@app.route("/admin")
def admin():
    stats = {}
    logs = []
    daily_data = {}

    if os.path.exists(PROXY_LOG_FILE):
        with open(PROXY_LOG_FILE) as f:
            for line in f:
                line = line.strip()
                if line:
                    logs.append(line)
                    try:
                        date_str, count_info = line.split(",", 1) # Split only on the first comma
                        count = int(count_info.split()[0]) # Get the number before "proxies" or "good unused proxies"
                        daily_data[date_str] = daily_data.get(date_str, 0) + count
                    except ValueError:
                        # Handle malformed log lines if any
                        print(f"Skipping malformed log line: {line}")

    stats["total_checks"] = len(logs)
    stats["total_good"] = sum(int(line.split(",")[1].split()[0]) for line in logs if line.strip())

    if daily_data:
        dates = sorted(daily_data.keys()) # Ensure dates are in order for plotting
        counts = [daily_data[d] for d in dates]
        plt.figure(figsize=(10, 4))
        plt.plot(dates, counts, marker="o", color="green")
        plt.title("Good Proxies per Day")
        plt.xlabel("Date")
        plt.ylabel("Count")
        plt.xticks(rotation=45)
        plt.tight_layout()
        if not os.path.exists("static"):
            os.makedirs("static")
        plt.savefig("static/proxy_stats.png")
        plt.close()

    used_ips = list_used_ips()
    good_proxies = list_good_proxies()
    return render_template("admin.html", logs=logs, stats=stats, graph_url="/static/proxy_stats.png", used_ips=used_ips, good_proxies=good_proxies)

@app.route('/static/<path:path>')
def send_static(path):
    return send_from_directory('static', path)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)), debug=True)
