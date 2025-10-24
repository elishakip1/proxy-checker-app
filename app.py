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
import random
from requests.adapters import HTTPAdapter
from requests.packages.urllib3.util.retry import Retry
import urllib3
import ssl

# Disable SSL warnings for testing
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

app = Flask(__name__)

# --- Configuration ---
LOW_SCORE_PROXIES_FILE = "low_score_proxies.txt"
PROXY_LOG_FILE = "proxy_log.txt"
MAX_WORKERS = 4
REQUEST_TIMEOUT = 10  # Increased timeout
PROXY_CHECK_HARD_LIMIT = 50
MIN_DELAY = 0.5
MAX_DELAY = 2.5
MAX_ACCEPTABLE_FRAUD_SCORE = 8

# User agents to rotate
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.6 Safari/605.1.15",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/118.0",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.0.0 Safari/537.36",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 16_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.6 Mobile/15E148 Safari/604.1"
]

# Google Sheets config
SCOPE = ["https://spreadsheets.google.com/feeds", "https://www.googleapis.com/auth/drive"]

def get_gsheet_client():
    json_creds = os.getenv("GOOGLE_SERVICE_ACCOUNT_JSON")
    if not json_creds:
        # Try alternative environment variable name
        json_creds = os.getenv("GOOGLE_CREDENTIALS")
    if not json_creds:
        raise ValueError("Missing Google Sheets credentials environment variable.")
    creds_dict = json.loads(json_creds)
    creds = ServiceAccountCredentials.from_json_keyfile_dict(creds_dict, SCOPE)
    return gspread.authorize(creds)

def get_sheet():
    client = get_gsheet_client()
    return client.open("Used IPs").sheet1

def append_used_ip(ip, proxy):
    try:
        sheet = get_sheet()
        sheet.append_row([ip, proxy, str(datetime.datetime.utcnow())])
    except Exception as e:
        print(f"Error appending to sheet: {e}")

def is_ip_used(ip):
    try:
        sheet = get_sheet()
        ips = sheet.col_values(1)
        return ip in ips
    except Exception as e:
        print(f"Error checking IP usage in sheet: {e}")
        return False

def remove_ip(ip):
    try:
        sheet = get_sheet()
        records = sheet.get_all_records()
        for i, row in enumerate(records):
            if row.get("IP") == ip:
                sheet.delete_rows(i + 2)
                break
    except Exception as e:
        print(f"Error removing IP from sheet: {e}")

def list_used_ips():
    try:
        sheet = get_sheet()
        return sheet.get_all_records()
    except Exception as e:
        print(f"Error listing used IPs: {e}")
        return []

def list_low_score_proxies():
    if not os.path.exists(LOW_SCORE_PROXIES_FILE):
        return []
    with open(LOW_SCORE_PROXIES_FILE, "r") as f:
        return [line.strip() for line in f if line.strip()]

def parse_proxy_line(proxy_line):
    """Parse proxy line and return components"""
    try:
        parts = proxy_line.strip().split(":")
        if len(parts) == 4:
            return parts[0], parts[1], parts[2], parts[3]  # host, port, user, pass
        elif len(parts) == 2:
            return parts[0], parts[1], None, None  # host, port only
        else:
            return None
    except:
        return None

def get_ip_from_proxy(proxy_line):
    try:
        proxy_parts = parse_proxy_line(proxy_line)
        if not proxy_parts:
            return None
            
        host, port, user, pw = proxy_parts
        
        # Build proxy URL based on authentication
        if user and pw:
            proxy_url = f"http://{user}:{pw}@{host}:{port}"
        else:
            proxy_url = f"http://{host}:{port}"
            
        proxies = {
            "http": proxy_url,
            "https": proxy_url,
        }
        
        # Create session with better error handling
        session = requests.Session()
        retries = Retry(
            total=2,
            backoff_factor=0.3,
            status_forcelist=[500, 502, 503, 504]
        )
        session.mount('http://', HTTPAdapter(max_retries=retries))
        session.mount('https://', HTTPAdapter(max_retries=retries))
        
        # Try HTTP first, then HTTPS with verify=False
        try:
            response = session.get(
                "http://api.ipify.org",  # Use HTTP instead of HTTPS
                proxies=proxies,
                timeout=REQUEST_TIMEOUT,
                headers={"User-Agent": random.choice(USER_AGENTS)},
                verify=False
            )
            if response.status_code == 200:
                return response.text.strip()
        except:
            # Fallback to HTTPS with SSL verification disabled
            try:
                response = session.get(
                    "https://api.ipify.org",
                    proxies=proxies,
                    timeout=REQUEST_TIMEOUT,
                    headers={"User-Agent": random.choice(USER_AGENTS)},
                    verify=False
                )
                if response.status_code == 200:
                    return response.text.strip()
            except Exception as e:
                print(f"❌ Both HTTP and HTTPS failed for proxy {host}:{port}: {e}")
                return None
                
    except Exception as e:
        print(f"❌ Failed to get IP from proxy {proxy_line}: {e}")
        return None

def get_fraud_score(ip, proxy_line):
    try:
        proxy_parts = parse_proxy_line(proxy_line)
        if not proxy_parts:
            return None
            
        host, port, user, pw = proxy_parts
        
        # Build proxy URL
        if user and pw:
            proxy_url = f"http://{user}:{pw}@{host}:{port}"
        else:
            proxy_url = f"http://{host}:{port}"
            
        proxies = {
            "http": proxy_url,
            "https": proxy_url,
        }
        
        session = requests.Session()
        retries = Retry(total=2, backoff_factor=1, status_forcelist=[429, 500, 502, 503, 504])
        session.mount('http://', HTTPAdapter(max_retries=retries))
        session.mount('https://', HTTPAdapter(max_retries=retries))
        
        url = f"https://scamalytics.com/ip/{ip}"
        headers = {
            "User-Agent": random.choice(USER_AGENTS),
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
            "Connection": "keep-alive",
            "Upgrade-Insecure-Requests": "1",
        }
        
        response = session.get(
            url,
            headers=headers,
            proxies=proxies,
            timeout=REQUEST_TIMEOUT,
            verify=False
        )
        
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
    time.sleep(random.uniform(MIN_DELAY, MAX_DELAY))
    
    ip = get_ip_from_proxy(proxy_line)
    if not ip:
        return None

    score = get_fraud_score(ip, proxy_line)
    
    if score is not None and score <= MAX_ACCEPTABLE_FRAUD_SCORE:
        return {"proxy": proxy_line, "ip": ip, "score": score}
    
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
            all_lines = file.read().decode("utf-8").strip().splitlines()
            input_count = len(all_lines)
            if input_count > PROXY_CHECK_HARD_LIMIT:
                truncation_warning = f" Only the first {PROXY_CHECK_HARD_LIMIT} proxies were processed."
                all_lines = all_lines[:PROXY_CHECK_HARD_LIMIT]
            proxies = all_lines
        elif 'proxytext' in request.form:
            proxytext = request.form.get("proxytext", "")
            all_lines = proxytext.strip().splitlines()
            input_count = len(all_lines)
            if input_count > PROXY_CHECK_HARD_LIMIT:
                truncation_warning = f" Only the first {PROXY_CHECK_HARD_LIMIT} proxies were processed."
                all_lines = all_lines[:PROXY_CHECK_HARD_LIMIT]
            proxies = all_lines

        # Filter valid proxy formats
        valid_proxies = []
        for proxy in proxies:
            proxy = proxy.strip()
            if proxy and parse_proxy_line(proxy):
                valid_proxies.append(proxy)
        
        processed_count = len(valid_proxies)

        if valid_proxies:
            with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
                futures = [executor.submit(single_check_proxy, proxy) for proxy in valid_proxies]
                for future in as_completed(futures):
                    result = future.result()
                    if result:
                        used = is_ip_used(result["ip"])
                        results.append({
                            "proxy": result["proxy"],
                            "used": used,
                            "score": result.get("score", "N/A")
                        })

            if results:
                with open(LOW_SCORE_PROXIES_FILE, "w") as out:
                    for item in results:
                        if not item["used"]:
                            out.write(item["proxy"] + "\n")

                with open(PROXY_LOG_FILE, "a") as log:
                    log.write(f"{datetime.date.today()},{len([r for r in results if not r['used']])} proxies\n")

                good_count = len([r for r in results if not r['used']])
                used_count = len([r for r in results if r['used']])
                
                message = f"✅ Processed {processed_count} valid proxies ({input_count} submitted). Found {good_count} proxies with score ≤ {MAX_ACCEPTABLE_FRAUD_SCORE} ({used_count} used).{truncation_warning}"
            else:
                message = f"⚠️ Processed {processed_count} valid proxies ({input_count} submitted). No low-score proxies found.{truncation_warning}"
        else:
            message = f"❌ No valid proxies provided. Submitted {input_count} lines, but none were valid proxy formats."

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
                    except:
                        continue

    stats["total_checks"] = len(logs)
    stats["total_good"] = sum(int(line.split(",")[1].split()[0]) for line in logs if line.split(",")[1].split()[0].isdigit())

    if daily_data:
        dates = list(daily_data.keys())
        counts = list(daily_data.values())
        plt.figure(figsize=(10, 4))
        plt.plot(dates, counts, marker="o", color="green")
        plt.title(f"Low-Score Proxies per Day (Score ≤ {MAX_ACCEPTABLE_FRAUD_SCORE})")
        plt.xlabel("Date")
        plt.ylabel("Count")
        plt.xticks(rotation=45)
        plt.tight_layout()
        if not os.path.exists("static"):
            os.makedirs("static")
        plt.savefig("static/proxy_stats.png")
        plt.close()

    used_ips = list_used_ips()
    good_proxies = list_low_score_proxies()
    return render_template("admin.html", logs=logs, stats=stats, graph_url="/static/proxy_stats.png", used_ips=used_ips, good_proxies=good_proxies)

@app.route('/static/<path:path>')
def send_static(path):
    return send_from_directory('static', path)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)), debug=False)
