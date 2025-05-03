from flask import Flask, request, render_template
import os
import time
import requests
from bs4 import BeautifulSoup
from concurrent.futures import ThreadPoolExecutor, as_completed

app = Flask(__name__)

GOOD_PROXIES_FILE = "zero_score_proxies.txt"
MAX_WORKERS = 30
MAX_ATTEMPTS = 3
RETRY_DELAY = 2  # seconds


def get_ip_from_proxy(proxy):
    try:
        host, port, user, pw = proxy.strip().split(":")
        proxies = {
            "http": f"http://{user}:{pw}@{host}:{port}",
            "https": f"http://{user}:{pw}@{host}:{port}",
        }
        ip = requests.get("https://api.ipify.org", proxies=proxies, timeout=10).text
        return ip
    except Exception as e:
        print(f"❌ Failed to get IP from proxy {proxy}: {e}")
        return None


def get_fraud_score(ip):
    try:
        url = f"https://scamalytics.com/ip/{ip}"
        response = requests.get(url, timeout=10)
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
        else:
            print(f"⚠️ Attempt {attempt+1}: No score returned for {ip}")
        time.sleep(RETRY_DELAY)

    if scores.count(0) == MAX_ATTEMPTS:
        print(f"✅ {ip} passed all checks ➜ Fraud Score: 0")
        return proxy_line
    else:
        print(f"❌ {ip} failed ➜ Scores: {scores}")
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


@app.route("/paste", methods=["GET", "POST"])
def paste():
    return index()


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)), debug=True)
