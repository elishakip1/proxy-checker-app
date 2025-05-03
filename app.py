from flask import Flask, request, render_template, jsonify
from concurrent.futures import ThreadPoolExecutor
from threading import Lock
import requests
from bs4 import BeautifulSoup

app = Flask(__name__)
executor = ThreadPoolExecutor(max_workers=60)

REQUEST_TIMEOUT = 3
GOOD_PROXIES_FILE = "zero_score_proxies.txt"
results = []
results_lock = Lock()


def get_ip_and_score(proxy):
    try:
        host, port, user, pw = proxy.strip().split(":")
        proxies = {
            "http": f"http://{user}:{pw}@{host}:{port}",
            "https": f"http://{user}:{pw}@{host}:{port}",
        }

        ip_resp = requests.get("https://api.ipify.org", proxies=proxies, timeout=REQUEST_TIMEOUT)
        ip = ip_resp.text.strip()

        scam_url = f"https://scamalytics.com/ip/{ip}"
        scam_resp = requests.get(scam_url, timeout=REQUEST_TIMEOUT)
        if scam_resp.status_code == 200:
            soup = BeautifulSoup(scam_resp.text, 'html.parser')
            score_div = soup.find('div', class_='score')
            if score_div and "Fraud Score:" in score_div.text:
                score = int(score_div.text.split(":")[1].strip())
                if score == 0:
                    with results_lock:
                        results.append(proxy)
                    return
    except:
        pass


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/submit", methods=["POST"])
def submit():
    global results
    results = []
    proxies = []

    if 'proxyfile' in request.files and request.files['proxyfile'].filename:
        file = request.files['proxyfile']
        proxies = file.read().decode("utf-8").strip().splitlines()
    elif 'proxytext' in request.form:
        proxytext = request.form.get("proxytext", "")
        proxies = proxytext.strip().splitlines()

    proxies = list(set(p.strip() for p in proxies if p.strip()))

    for proxy in proxies:
        executor.submit(get_ip_and_score, proxy)

    return jsonify({"message": f"⏳ Checking {len(proxies)} proxies..."})


@app.route("/results", methods=["GET"])
def get_results():
    with results_lock:
        return jsonify({"results": results})


if __name__ == "__main__":
    app.run(debug=True)
