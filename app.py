from flask import Flask, request, render_template
from flask_socketio import SocketIO, emit
import os
import time
import requests
from bs4 import BeautifulSoup
from concurrent.futures import ThreadPoolExecutor, as_completed

app = Flask(__name__)
socketio = SocketIO(app)

GOOD_PROXIES_FILE = "zero_score_proxies.txt"
MAX_WORKERS = 50
MAX_ATTEMPTS = 2
RETRY_DELAY = 1  # seconds
REQUEST_TIMEOUT = 4  # reduced timeout


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


def triple_check_proxy(proxy_line):
    ip = get_ip_from_proxy(proxy_line)
    if not ip:
        return None

    scores = []
    for attempt in range(MAX_ATTEMPTS):
        score = get_fraud_score(ip)
        if score is not None:
            scores.append(score)
        time.sleep(RETRY_DELAY)

    if scores.count(0) == MAX_ATTEMPTS:
        return proxy_line
    return None


@app.route("/", methods=["GET", "POST"])
def index():
    return render_template("index.html")


@app.route("/paste", methods=["GET", "POST"])
def paste():
    return index()


@socketio.on('check_proxies')
def handle_check_proxies(data):
    proxies = data['proxies']
    results = []
    message = "Checking proxies..."
    
    # Filter out empty lines and duplicates
    proxies = list(set(p.strip() for p in proxies if p.strip()))

    if proxies:
        with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
            futures = [executor.submit(triple_check_proxy, proxy) for proxy in proxies]
            for future in as_completed(futures):
                result = future.result()
                if result:
                    results.append(result)
                # Emit progress update
                emit('update_progress', {'message': f"Checked {len(results)} proxies"})
            
        if results:
            with open(GOOD_PROXIES_FILE, "w") as out:
                for proxy in results:
                    out.write(proxy + "\n")
            message = f"✅ {len(results)} good proxies found."
        else:
            message = "⚠️ No good proxies found."
    else:
        message = "⚠️ No proxies provided."
    
    # Send final results
    emit('final_results', {'results': results, 'message': message})


if __name__ == "__main__":
    socketio.run(app, host="0.0.0.0", port=int(os.environ.get("PORT", 5000)), debug=True)
