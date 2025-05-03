from flask import Flask, render_template, request, send_file
import os
import requests
from bs4 import BeautifulSoup
from concurrent.futures import ThreadPoolExecutor, as_completed
import time
from tempfile import NamedTemporaryFile

app = Flask(__name__)
MAX_WORKERS = 20
MAX_ATTEMPTS = 3
RETRY_DELAY = 2

def get_ip_from_proxy(proxy):
    try:
        parts = proxy.strip().split(":")
        if len(parts) == 4:
            host, port, user, pw = parts
            proxies = {
                "http": f"http://{user}:{pw}@{host}:{port}",
                "https": f"http://{user}:{pw}@{host}:{port}"
            }
        else:
            host, port = parts[0], parts[1]
            proxies = {
                "http": f"http://{host}:{port}",
                "https": f"http://{host}:{port}"
            }

        ip = requests.get("https://api.ipify.org", proxies=proxies, timeout=10).text
        return ip
    except:
        return None

def get_fraud_score(ip):
    try:
        url = f"https://scamalytics.com/ip/{ip}"
        response = requests.get(url, timeout=10)
        soup = BeautifulSoup(response.text, 'html.parser')
        score_div = soup.find('div', class_='score')
        if score_div and "Fraud Score:" in score_div.text:
            score_text = score_div.text.strip().split(":")[1].strip()
            return int(score_text)
    except:
        pass
    return None

def triple_check_proxy(proxy):
    ip = get_ip_from_proxy(proxy)
    if not ip:
        return None
    scores = []
    for _ in range(MAX_ATTEMPTS):
        score = get_fraud_score(ip)
        if score is not None:
            scores.append(score)
        time.sleep(RETRY_DELAY)
    return proxy if scores.count(0) == MAX_ATTEMPTS else None

@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        file = request.files['proxyfile']
        content = file.read().decode('utf-8').splitlines()
        good_proxies = []

        with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
            futures = [executor.submit(triple_check_proxy, proxy) for proxy in content]
            for future in as_completed(futures):
                result = future.result()
                if result:
                    good_proxies.append(result)

        tmp_file = NamedTemporaryFile(delete=False, mode='w', suffix='.txt')
        for proxy in good_proxies:
            tmp_file.write(proxy + "\n")
        tmp_file.close()
        return send_file(tmp_file.name, as_attachment=True, download_name="zero_fraud_proxies.txt")

    return render_template('index.html')
