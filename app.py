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
import uuid
from collections import deque
from threading import Thread, Lock
import logging
import traceback

app = Flask(__name__)

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Configuration
GOOD_PROXIES_FILE = "zero_score_proxies.txt"
PROXY_LOG_FILE = "proxy_log.txt"
MAX_WORKERS = 50
REQUEST_TIMEOUT = 10  # Increased timeout
MAX_PROXIES_PER_CHECK = 50
MAX_QUEUE_SIZE = 5  # Max tasks in queue

# Task queue system
task_queue = deque()
task_queue_lock = Lock()
task_status = {}  # task_id: status ('queued', 'processing', 'completed')
task_results = {}

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
    return client.open("UsedIPs").sheet1

def append_used_ip(ip, proxy):
    try:
        sheet = get_sheet()
        sheet.append_row([ip, proxy, str(datetime.datetime.utcnow())])
    except Exception as e:
        logger.error(f"Error appending used IP: {str(e)}")

def is_ip_used(ip):
    try:
        sheet = get_sheet()
        ips = sheet.col_values(1)
        return ip in ips
    except Exception as e:
        logger.error(f"Error checking if IP is used: {str(e)}")
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
        logger.error(f"Error removing IP: {str(e)}")

def list_used_ips():
    try:
        sheet = get_sheet()
        return sheet.get_all_records()
    except Exception as e:
        logger.error(f"Error listing used IPs: {str(e)}")
        return []

def list_good_proxies():
    if not os.path.exists(GOOD_PROXIES_FILE):
        return []
    try:
        with open(GOOD_PROXIES_FILE, "r") as f:
            return [line.strip() for line in f if line.strip()]
    except Exception as e:
        logger.error(f"Error listing good proxies: {str(e)}")
        return []

def get_ip_from_proxy(proxy):
    try:
        parts = proxy.strip().split(":")
        if len(parts) < 4:
            logger.error(f"Invalid proxy format: {proxy}")
            return None
            
        host, port, user, pw = parts[:4]
        proxies = {
            "http": f"http://{user}:{pw}@{host}:{port}",
            "https": f"http://{user}:{pw}@{host}:{port}",
        }
        response = requests.get("https://api.ipify.org", proxies=proxies, timeout=REQUEST_TIMEOUT)
        response.raise_for_status()
        return response.text
    except Exception as e:
        logger.error(f"Failed to get IP from proxy {proxy}: {str(e)}")
        return None

def get_fraud_score(ip):
    try:
        if not ip:
            return None
            
        url = f"https://scamalytics.com/ip/{ip}"
        response = requests.get(url, timeout=REQUEST_TIMEOUT)
        if response.status_code == 200:
            soup = BeautifulSoup(response.text, 'html.parser')
            score_div = soup.find('div', class_='score')
            if score_div and "Fraud Score:" in score_div.text:
                score_text = score_div.text.strip().split(":")[1].strip()
                return int(score_text)
    except Exception as e:
        logger.error(f"Error checking Scamalytics for {ip}: {str(e)}")
    return None

def single_check_proxy(proxy_line):
    try:
        ip = get_ip_from_proxy(proxy_line)
        if not ip:
            return None

        score = get_fraud_score(ip)
        if score == 0:
            return {"proxy": proxy_line, "ip": ip}
    except Exception as e:
        logger.error(f"Error checking proxy {proxy_line}: {str(e)}")
    return None

def process_proxies(proxies, task_id):
    logger.info(f"Starting processing for task {task_id} with {len(proxies)} proxies")
    results = []
    try:
        with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
            futures = [executor.submit(single_check_proxy, proxy) for proxy in proxies]
            for future in as_completed(futures):
                try:
                    result = future.result()
                    if result:
                        used = is_ip_used(result["ip"])
                        results.append({
                            "proxy": result["proxy"],
                            "used": used
                        })
                except Exception as e:
                    logger.error(f"Error processing proxy: {str(e)}")
    except Exception as e:
        logger.error(f"Error processing proxies: {str(e)}")
    
    logger.info(f"Completed processing for task {task_id}. Found {len(results)} good proxies")
    
    # Store results
    with task_queue_lock:
        task_results[task_id] = results
        task_status[task_id] = 'completed'

def task_worker():
    logger.info("Task worker thread started")
    while True:
        try:
            with task_queue_lock:
                if task_queue:
                    task_id, proxies = task_queue.popleft()
                    task_status[task_id] = 'processing'
                else:
                    task_id = None
                    
            if task_id:
                try:
                    process_proxies(proxies, task_id)
                except Exception as e:
                    logger.error(f"Task processing error: {str(e)}")
                    with task_queue_lock:
                        task_status[task_id] = 'completed'
                        task_results[task_id] = []
        except Exception as e:
            logger.error(f"Worker thread error: {str(e)}")
            
        time.sleep(1)

# Start worker thread
worker_thread = Thread(target=task_worker, daemon=True)
worker_thread.start()
logger.info("Worker thread started successfully")

@app.route("/", methods=["GET", "POST"])
def index():
    results = []
    message = ""
    task_id = None

    if request.method == "POST":
        proxies = []

        if 'proxyfile' in request.files and request.files['proxyfile'].filename:
            file = request.files['proxyfile']
            try:
                content = file.read()
                if isinstance(content, bytes):
                    content = content.decode("utf-8", errors="replace")
                proxies = content.strip().splitlines()
                message = "Checking uploaded proxy file..."
                logger.info(f"Received file with {len(proxies)} proxies")
            except Exception as e:
                message = f"⚠️ Error reading file: {str(e)}"
                logger.error(f"File read error: {str(e)}")
        elif 'proxytext' in request.form:
            proxytext = request.form.get("proxytext", "")
            proxies = proxytext.strip().splitlines()
            message = "Checking pasted proxies..."
            logger.info(f"Received {len(proxies)} proxies from text input")

        proxies = list(set(p.strip() for p in proxies if p.strip()))
        
        # Validate proxy count
        if len(proxies) > MAX_PROXIES_PER_CHECK:
            message = f"⚠️ Maximum {MAX_PROXIES_PER_CHECK} proxies allowed per check."
            return render_template("index.html", message=message, results=None)
        
        # Check queue status
        with task_queue_lock:
            queue_size = len(task_queue)
            if queue_size >= MAX_QUEUE_SIZE:
                message = "⚠️ Queue is full. Please try again later."
                return render_template("index.html", message=message, results=None)
            
            # Create task
            task_id = f"{time.time()}_{uuid.uuid4().hex}"
            task_queue.append((task_id, proxies))
            task_status[task_id] = 'queued'
            position = queue_size + 1  # +1 because we just added this task
            
            logger.info(f"Created task {task_id} with {len(proxies)} proxies. Queue position: {position}")
            
            # Return the task ID in a hidden field
            return render_template("index.html", message=message, results=None, task_id=task_id)

    return render_template("index.html", results=results, message=message, task_id=None)

@app.route("/queue-status")
def queue_status():
    task_id = request.args.get('task_id')
    if not task_id:
        return jsonify({'error': 'Missing task_id'}), 400
        
    with task_queue_lock:
        status = task_status.get(task_id, 'not_found')
        logger.info(f"Queue status request for task {task_id}: {status}")
        
        if status == 'processing':
            return jsonify({
                'status': 'processing',
                'queue_size': len(task_queue) + 1  # +1 for current task
            })
        elif status == 'queued':
            # Find position in queue
            position = 0
            for i, (tid, _) in enumerate(task_queue):
                if tid == task_id:
                    position = i + 1
                    break
                    
            return jsonify({
                'status': 'queued',
                'position': position,
                'queue_size': len(task_queue) + 1  # +1 for current task
            })
        elif status == 'completed':
            return jsonify({'status': 'completed'})
        else:
            return jsonify({'status': 'not_found'}), 404

@app.route("/get-results")
def get_results():
    task_id = request.args.get('task_id')
    if not task_id:
        return jsonify({'error': 'Missing task_id'}), 400
        
    with task_queue_lock:
        if task_id in task_results:
            results = task_results[task_id]
            
            # Save results to file
            if results:
                try:
                    with open(GOOD_PROXIES_FILE, "w") as out:
                        for item in results:
                            if not item["used"]:
                                out.write(item["proxy"] + "\n")

                    with open(PROXY_LOG_FILE, "a") as log:
                        log.write(f"{datetime.date.today()},{len([r for r in results if not r['used']])} proxies\n")
                except Exception as e:
                    logger.error(f"Error saving results: {str(e)}")
            
            return jsonify({
                'results': results,
                'message': f"✅ {len([r for r in results if not r['used']])} good proxies found ({len([r for r in results if r['used']])} used)."
            })
    
    return jsonify({'error': 'Results not found'}), 404

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
                    except Exception as e:
                        logger.error(f"Error parsing log line: {line} - {str(e)}")

    stats["total_checks"] = len(logs)
    stats["total_good"] = sum([int(line.split(",")[1].split()[0]) for line in logs if line])

    if daily_data:
        dates = list(daily_data.keys())
        counts = list(daily_data.values())
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
