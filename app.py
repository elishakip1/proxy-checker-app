from flask import Flask, request, render_template, abort
import os
import time
import requests
import logging
from bs4 import BeautifulSoup
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime

app = Flask(__name__)

GOOD_PROXIES_FILE = "zero_score_proxies.txt"
LOG_FILE = "logs/proxy_checks.log"
MAX_WORKERS = 50
MAX_ATTEMPTS = 2
RETRY_DELAY = 1
REQUEST_TIMEOUT = 4

ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD", "secret123")  # Optional password

os.makedirs("logs", exist_ok=True)
logging.basicConfig(filename=LOG_FILE, level=logging.INFO, format="%(asctime)s - %(message)s")


def get_ip_from_proxy(proxy):
    try:
        host, port, user, pw = proxy.strip().split(":")
        proxies = {
            "http": f"http://{user}:{pw}@{host}:{port}",
            "https": f"http://{user}:{pw}@{host}:{port}",
        }
        ip = requests.get("https://api.ipify.org", proxies=proxies, timeout=REQUEST_TIMEOUT).text
        return ip
    except Exception as e:
        logging.info(f"❌ {proxy} - Failed to get IP: {e}")
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
        logging.info(f"⚠️ Scamalytics error for {ip}: {e}")
    return None


def triple_check_proxy(proxy_line):
    ip = get_ip_from_proxy(proxy_line)
    if not ip:
        return None

    scores = []
    for _ in range(MAX_ATTEMPTS):
        score = get_fraud_score(ip)
        if score is not None:
            scores.append(score)
        time.sleep(RETRY_DELAY)

    avg_score = sum(scores) / len(scores) if scores else None
    logging.info(f"{proxy_line} → {ip} → Scores: {scores} → Avg: {avg_score}")

    if scores.count(0) == MAX_ATTEMPTS:
        return proxy_line
    return None


@app.route("/", methods=["GET", "POST"])
def index():
    results = []
    message = ""
    if request.method == "POST":
        proxies = []

        if 'proxyfile' in request.files and request.files['proxyfile'].filename:
            file = request.files['proxyfile']
            proxies = file.read().decode("utf-8").strip().splitlines()
            message = "Checking uploaded proxy file..."
        elif 'proxytext' in request.form:
            proxytext = request.form.get("proxytext", "")
            proxies = proxytext.strip().splitlines()
            message = "Checking pasted proxies..."

        proxies = list(set(p.strip() for p in proxies if p.strip()))

        if proxies:
            with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
                futures = [executor.submit(triple_check_proxy, proxy) for proxy in proxies]
                for future in as_completed(futures):
                    result = future.result()
                    if result:
                        results.append(result)

            if results:
                with open(GOOD_PROXIES_FILE, "w") as out:
                    for proxy in results:
                        out.write(proxy + "\n")
                message = f"✅ {len(results)} good proxies found."
            else:
                message = "⚠️ No good proxies found."
        else:
            message = "⚠️ No proxies provided."

    return render_template("index.html", results=results, message=message)


@app.route("/admin")
def admin():
    if request.args.get("pw") != ADMIN_PASSWORD:
        return abort(403)

    log_lines = []
    if os.path.exists(LOG_FILE):
        with open(LOG_FILE, "r") as f:
            log_lines = f.readlines()[-100:]

    good_count = 0
    total_checked = 0

    for line in log_lines:
        if "Scores: [0, 0]" in line:
            good_count += 1
        if "→" in line:
            total_checked += 1

    stats = {
        "total_checked": total_checked,
        "good_count": good_count,
        "log_lines": log_lines[::-1],
    }

    return render_template("admin.html", stats=stats)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)), debug=True)
