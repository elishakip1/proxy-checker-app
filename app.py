from flask import Flask, render_template, request, send_file
import os
import tempfile
from concurrent.futures import ThreadPoolExecutor, as_completed
from bs4 import BeautifulSoup
import requests
import time

app = Flask(__name__)

MAX_WORKERS = 30
MAX_ATTEMPTS = 3
RETRY_DELAY = 2

def get_ip_from_proxy(proxy):
    try:
        host, port, user, pw = proxy.strip().split(":")
        proxies = {
            "http": f"http://{user}:{pw}@{host}:{port}",
            "https": f"http://{user}:{pw}@{host}:{port}",
        }
        ip = requests.get("https://api.ipify.org", proxies=proxies, timeout=10).text
        return ip
    except Exception:
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
    except:
        pass
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

    if scores.count(0) == MAX_ATTEMPTS:
        return proxy_line
    return None

@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        file = request.files['proxyfile']
        if not file:
            return "No file uploaded."

        proxies = [line.strip() for line in file.read().decode().splitlines() if line.strip()]
        good_proxies = []

        with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
            futures = [executor.submit(triple_check_proxy, proxy) for proxy in proxies]
            for future in as_completed(futures):
                result = future.result()
                if result:
                    good_proxies.append(result)

        temp_file = tempfile.NamedTemporaryFile(delete=False, mode='w', suffix='.txt')
        for proxy in good_proxies:
            temp_file.write(proxy + '\n')
        temp_file.close()

        return send_file(temp_file.name, as_attachment=True, download_name='zero_score_proxies.txt')

    return render_template('index.html')

if __name__ == '__main__':
    port = int(os.environ.get("PORT", 5000))
    app.run(debug=False, host='0.0.0.0', port=port)
