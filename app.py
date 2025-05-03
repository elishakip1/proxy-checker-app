from flask import Flask, request, render_template, send_from_directory
import os
import time
import requests
from bs4 import BeautifulSoup
from concurrent.futures import ThreadPoolExecutor, as_completed
import datetime
import matplotlib.pyplot as plt

app = Flask(__name__)

GOOD_PROXIES_FILE = "zero_score_proxies.txt"
PROXY_LOG_FILE = "proxy_log.txt"
MAX_WORKERS = 50
REQUEST_TIMEOUT = 4  # seconds


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
                futures = [executor.submit(single_check_proxy, proxy) for proxy in proxies]
                for future in as_completed(futures):
                    result = future.result()
                    if result:
                        results.append(result)

            if results:
                with open(GOOD_PROXIES_FILE, "w") as out:
                    for proxy in results:
                        out.write(proxy + "\n")

                # Log result
                with open(PROXY_LOG_FILE, "a") as log:
                    log.write(f"{datetime.date.today()},{len(results)} proxies\n")

                message = f"✅ {len(results)} good proxies found."
            else:
                message = "⚠️ No good proxies found."
        else:
            message = "⚠️ No proxies provided."

    return render_template("index.html", results=results, message=message)


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
                    date_str, count_str = line.split(",")
                    count = int(count_str.split()[0])
                    daily_data[date_str] = daily_data.get(date_str, 0) + count

    stats["total_checks"] = len(logs)
    stats["total_good"] = sum(int(line.split(",")[1].split()[0]) for line in logs)

    # Generate graph
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

    return render_template("admin.html", logs=logs, stats=stats, graph_url="/static/proxy_stats.png")


@app.route('/static/<path:path>')
def send_static(path):
    return send_from_directory('static', path)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)), debug=True)
