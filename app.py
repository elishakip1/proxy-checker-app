from flask import Flask, request, render_template
import os
import time
import requests
from bs4 import BeautifulSoup
from concurrent.futures import ThreadPoolExecutor, as_completed

app = Flask(__name__)

GOOD_PROXIES_FILE = "zero_score_proxies.txt"
MAX_WORKERS = 60  # Increased threads
REQUEST_TIMEOUT = 3  # Shorter timeout

session = requests.Session()
adapter = requests.adapters.HTTPAdapter(pool_connections=100, pool_maxsize=100)
session.mount('http://', adapter)
session.mount('https://', adapter)


def get_ip_and_score(proxy):
    try:
        host, port, user, pw = proxy.strip().split(":")
        proxies = {
            "http": f"http://{user}:{pw}@{host}:{port}",
            "https": f"http://{user}:{pw}@{host}:{port}",
        }

        ip_resp = session.get("https://api.ipify.org", proxies=proxies, timeout=REQUEST_TIMEOUT)
        ip = ip_resp.text.strip()

        scam_url = f"https://scamalytics.com/ip/{ip}"
        scam_resp = session.get(scam_url, timeout=REQUEST_TIMEOUT)
        if scam_resp.status_code == 200:
            soup = BeautifulSoup(scam_resp.text, 'html.parser')
            score_div = soup.find('div', class_='score')
            if score_div and "Fraud Score:" in score_div.text:
                score = int(score_div.text.split(":")[1].strip())
                if score == 0:
                    print(f"✅ {ip} passed ➜ Score 0")
                    return proxy
    except Exception as e:
        print(f"❌ Error for proxy {proxy}: {e}")
    return None


@app.route("/", methods=["GET", "POST"])
def index():
    results = []
    message = ""
    hide_input = False

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
                futures = [executor.submit(get_ip_and_score, proxy) for proxy in proxies]
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
            hide_input = True
        else:
            message = "⚠️ No proxies provided."

    return render_template("index.html", results=results, message=message, hide_input=hide_input)


@app.route("/paste", methods=["GET", "POST"])
def paste():
    return index()


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)), debug=True)
