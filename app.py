from flask import Flask, request, render_template, send_from_directory, jsonify, redirect, url_for
import os
import requests
from bs4 import BeautifulSoup
from concurrent.futures import ThreadPoolExecutor, as_completed
import datetime
import matplotlib
matplotlib.use('Agg')  # Use non-interactive backend for Matplotlib
import matplotlib.pyplot as plt
import gspread
from oauth2client.service_account import ServiceAccountCredentials
import json
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

app = Flask(__name__)

# --- Configuration Constants ---
GOOD_PROXIES_FILE = "zero_score_proxies.txt"
PROXY_LOG_FILE = "proxy_log.txt"
MAX_WORKERS = 25  # Reduced for better resource management on typical hosts
REQUEST_TIMEOUT = 5 # Slightly increased timeout
PROXY_CHECK_HARD_LIMIT = 50

# --- Resilient Requests Session Setup (Implements Retries) ---
# This creates a single, reusable session for all requests.
session = requests.Session()

# Define the retry strategy
# Total retries=3, backoff_factor adds a delay between retries (e.g., 0.3s, 0.6s, 1.2s)
# status_forcelist will cause retries on 5xx server errors.
retry_strategy = Retry(
    total=3,
    status_forcelist=[429, 500, 502, 503, 504],
    backoff_factor=0.3
)

# Mount the strategy to the session
adapter = HTTPAdapter(max_retries=retry_strategy)
session.mount("http://", adapter)
session.mount("https://", adapter)

# --- Human-like Headers ---
HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
}

# --- Google Sheets Configuration ---
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
    return client.open("UsedIPs").sheet1

def append_used_ip(ip, proxy):
    try:
        sheet = get_sheet()
        sheet.append_row([ip, proxy, str(datetime.datetime.utcnow())])
    except Exception as e:
        print(f"❌ Failed to append to Google Sheet: {e}")

def is_ip_used(ip):
    try:
        sheet = get_sheet()
        ips = sheet.col_values(1)
        return ip in ips
    except Exception as e:
        print(f"❌ Failed to check Google Sheet: {e}")
        return False

def remove_ip(ip):
    try:
        sheet = get_sheet()
        cell = sheet.find(ip)
        if cell:
            sheet.delete_rows(cell.row)
    except Exception as e:
        print(f"❌ Failed to remove IP from Google Sheet: {e}")


def list_used_ips():
    try:
        sheet = get_sheet()
        return sheet.get_all_records()
    except Exception as e:
        print(f"❌ Failed to list IPs from Google Sheet: {e}")
        return []

def list_good_proxies():
    if not os.path.exists(GOOD_PROXIES_FILE):
        return []
    with open(GOOD_PROXIES_FILE, "r") as f:
        return [line.strip() for line in f if line.strip()]

def get_ip_from_proxy(proxy):
    try:
        host, port, user, pw = proxy.strip().split(":")
        proxies = {
            "http": f"http://{user}:{pw}@{host}:{port}",
            "https": f"http://{user}:{pw}@{host}:{port}",
        }
        # Use the global session with retry logic
        ip = session.get("https://api.ipify.org", proxies=proxies, timeout=REQUEST_TIMEOUT, headers=HEADERS).text
        return ip
    except Exception as e:
        # This will catch the final error after all retries have failed
        print(f"❌ Failed to get IP from proxy {proxy}: {e}")
        return None

def get_fraud_score(ip):
    try:
        url = f"https://scamalytics.com/ip/{ip}"
        # Use the global session with retry logic and human-like headers
        response = session.get(url, timeout=REQUEST_TIMEOUT, headers=HEADERS)
        if response.status_code == 200:
            soup = BeautifulSoup(response.text, 'html.parser')
            score_div = soup.find('div', class_='score')
            if score_div and "Fraud Score:" in score_div.text:
                score_text = score_div.text.strip().split(":")[1].strip()
                return int(score_text)
    except Exception as e:
        # This will catch the final error after all retries have failed
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
        input_count = 0
        truncation_warning = ""

        if 'proxyfile' in request.files and request.files['proxyfile'].filename:
            file = request.files['proxyfile']
            all_lines = file.read().decode("utf-8", errors="ignore").strip().splitlines()
        elif 'proxytext' in request.form:
            proxytext = request.form.get("proxytext", "")
            all_lines = proxytext.strip().splitlines()

        input_count = len(all_lines)
        if input_count > PROXY_CHECK_HARD_LIMIT:
            truncation_warning = f" Only the first {PROXY_CHECK_HARD_LIMIT} proxies were processed."
            all_lines = all_lines[:PROXY_CHECK_HARD_LIMIT]
        
        proxies = list(set(p.strip() for p in all_lines if p.strip()))
        processed_count = len(proxies)

        if proxies:
            # The ThreadPoolExecutor already provides controlled concurrency
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
                with open(GOOD_PROXIES_FILE, "w") as out:
                    for item in results:
                        if not item["used"]:
                            out.write(item["proxy"] + "\n")

                with open(PROXY_LOG_FILE, "a") as log:
                    log.write(f"{datetime.date.today()},{len([r for r in results if not r['used']])} proxies\n")

                good_count = len([r for r in results if not r['used']])
                used_count = len([r for r in results if r['used']])
                
                message = f"✅ Processed {processed_count} proxies ({input_count} submitted). Found {good_count} good proxies ({used_count} used).{truncation_warning}"
            else:
                message = f"⚠️ Processed {processed_count} proxies ({input_count} submitted). No good proxies found.{truncation_warning}"
        else:
            message = "⚠️ No valid proxies provided."

    return render_template("index.html", results=results, message=message)


@app.route("/track-used", methods=["POST"])
def track_used():
    data = request.get_json()
    if data and "proxy" in data:
        ip = get_ip_from_proxy(data["proxy"])
        if ip:
            append_used_ip(ip, data["proxy"])
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
                        date_str, count_str = line.split(",")
                        count = int(count_str.split()[0])
                        daily_data[date_str] = daily_data.get(date_str, 0) + count
                    except ValueError:
                        print(f"Could not parse log line: {line}")

    stats["total_checks"] = len(logs)
    stats["total_good"] = sum(daily_data.values())

    if daily_data:
        # Sort data by date for a proper graph
        sorted_dates = sorted(daily_data.keys(), key=lambda d: datetime.datetime.strptime(d, '%Y-%m-%d'))
        counts = [daily_data[d] for d in sorted_dates]
        
        plt.figure(figsize=(10, 4))
        plt.plot(sorted_dates, counts, marker="o", color="green")
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
