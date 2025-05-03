# Standard Library Imports
import os
import logging
from logging.handlers import RotatingFileHandler
from datetime import datetime, date, timedelta
from concurrent.futures import ThreadPoolExecutor, as_completed

# Third-Party Imports
from flask import Flask, request, render_template, send_from_directory, jsonify
from supabase import create_client, Client
import requests
from bs4 import BeautifulSoup
import matplotlib
matplotlib.use('Agg')  # Set non-interactive backend
import matplotlib.pyplot as plt
from dotenv import load_dotenv

# Initialize Flask Application
app = Flask(__name__)

# Load Environment Variables
load_dotenv()

# Configure Logging
logging.basicConfig(level=logging.INFO)
log_handler = RotatingFileHandler(
    'app.log',
    maxBytes=1_048_576,  # 1MB
    backupCount=5,
    encoding='utf-8'
)
log_handler.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))
app.logger.addHandler(log_handler)

# Constants
MAX_WORKERS = 50
REQUEST_TIMEOUT = 4  # seconds

# Initialize Supabase Client
try:
    supabase: Client = create_client(
        os.environ['SUPABASE_URL'],
        os.environ['SUPABASE_KEY'],
        options={
            'schema': 'public',
            'auto_refresh_token': False,
            'persist_session': False
        }
    )
    app.logger.info("Supabase client initialized successfully")
except KeyError as e:
    app.logger.error(f"Missing environment variable: {e}")
    raise
except Exception as e:
    app.logger.error(f"Supabase initialization failed: {e}")
    raise

# Helper Functions
def get_ip_from_proxy(proxy):
    try:
        host, port, user, pw = proxy.strip().split(':')
        proxies = {
            "http": f"http://{user}:{pw}@{host}:{port}",
            "https": f"http://{user}:{pw}@{host}:{port}"
        }
        response = requests.get(
            "https://api.ipify.org",
            proxies=proxies,
            timeout=REQUEST_TIMEOUT
        )
        response.raise_for_status()
        return response.text
    except Exception as e:
        app.logger.error(f"Proxy IP fetch failed: {e}")
        return None

def get_fraud_score(ip):
    try:
        response = requests.get(
            f"https://scamalytics.com/ip/{ip}",
            timeout=REQUEST_TIMEOUT
        )
        if response.status_code == 200:
            soup = BeautifulSoup(response.text, 'html.parser')
            score_div = soup.find('div', class_='score')
            if score_div and "Fraud Score:" in score_div.text:
                return int(score_div.text.strip().split(":")[1].strip())
    except Exception as e:
        app.logger.error(f"Fraud score check failed: {e}")
    return None

def track_used_ip(proxy):
    try:
        ip = get_ip_from_proxy(proxy)
        if ip:
            supabase.table('used_ips').upsert({
                "ip": ip,
                "proxy": proxy,
                "last_used": datetime.now().isoformat()
            }).execute()
            return ip
    except Exception as e:
        app.logger.error(f"IP tracking failed: {e}")
    return None

def is_ip_used(proxy):
    try:
        ip = get_ip_from_proxy(proxy)
        if ip:
            result = supabase.table('used_ips')\
                .select('ip')\
                .eq('ip', ip)\
                .execute()
            return len(result.data) > 0
    except Exception as e:
        app.logger.error(f"IP usage check failed: {e}")
    return False

def single_check_proxy(proxy_line):
    ip = get_ip_from_proxy(proxy_line)
    if not ip:
        return None

    score = get_fraud_score(ip)
    if score == 0:
        return proxy_line
    return None

# Application Routes
@app.route("/", methods=["GET", "POST"])
def index():
    results = []
    message = ""
    
    if request.method == "POST":
        proxies = []

        if 'proxyfile' in request.files and request.files['proxyfile'].filename:
            try:
                proxies = request.files['proxyfile'].read().decode().splitlines()
                message = "Checking uploaded proxy file..."
            except Exception as e:
                message = f"⚠️ File error: {str(e)}"
        elif 'proxytext' in request.form:
            proxies = request.form.get("proxytext", "").splitlines()
            message = "Checking pasted proxies..."

        proxies = list({p.strip() for p in proxies if p.strip()})

        if proxies:
            with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
                futures = [executor.submit(single_check_proxy, p) for p in proxies]
                for future in as_completed(futures):
                    if (result := future.result()):
                        results.append({
                            "proxy": result,
                            "used": is_ip_used(result)
                        })

            if results:
                good_count = sum(1 for r in results if not r['used'])
                if good_count:
                    try:
                        supabase.table('proxy_logs').insert({
                            "date": date.today().isoformat(),
                            "count": good_count
                        }).execute()
                    except Exception as e:
                        app.logger.error(f"Log save failed: {e}")

                message = f"✅ {good_count} good proxies found ({len(results) - good_count} used)."
            else:
                message = "⚠️ No good proxies found."
        else:
            message = "⚠️ No proxies provided."

    return render_template("index.html", results=results, message=message)

@app.route("/track-used", methods=["POST"])
def track_used():
    if not (data := request.get_json()) or "proxy" not in data:
        return jsonify({"status": "error"}), 400
    
    track_used_ip(data["proxy"])
    return jsonify({"status": "success"})

@app.route("/clear-used-ips", methods=["POST"])
def clear_used_ips():
    try:
        supabase.table('used_ips').delete().neq('id', 0).execute()
        return jsonify({
            "status": "success",
            "message": "Used IPs cleared"
        })
    except Exception as e:
        return jsonify({
            "status": "error",
            "message": str(e)
        }), 500

@app.route("/admin")
def admin():
    try:
        logs = supabase.table('proxy_logs')\
            .select('*')\
            .order('date')\
            .execute()
        
        stats = {
            "total_checks": len(logs.data),
            "total_good": supabase.rpc('sum_logs').execute().data[0]['sum'] or 0,
            "used_ips": supabase.table('used_ips')
                         .select('count', count=True)
                         .execute().count
        }

        if logs.data:
            dates = [log['date'] for log in logs.data]
            counts = [log['count'] for log in logs.data]
            
            plt.figure(figsize=(10, 4))
            plt.plot(dates, counts, 'go-')
            plt.title("Daily Good Proxies")
            plt.xlabel("Date")
            plt.ylabel("Count")
            plt.xticks(rotation=45)
            plt.tight_layout()
            
            os.makedirs("static", exist_ok=True)
            plt.savefig("static/proxy_stats.png")
            plt.close()

        return render_template(
            "admin.html",
            logs=[f"{log['date']},{log['count']} proxies" for log in logs.data],
            stats=stats,
            graph_url="/static/proxy_stats.png" if logs.data else None
        )
    except Exception as e:
        app.logger.error(f"Admin error: {e}")
        return render_template("admin.html", logs=[], stats={}, graph_url=None)

@app.route('/static/<path:path>')
def serve_static(path):
    return send_from_directory('static', path)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)))