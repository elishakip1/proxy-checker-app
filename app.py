import os
import requests
from flask import Flask, request, render_template, send_from_directory, jsonify
from bs4 import BeautifulSoup
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, date, timedelta
import matplotlib
matplotlib.use('Agg')  # Set backend before importing pyplot
import matplotlib.pyplot as plt
from supabase import create_client, Client
from dotenv import load_dotenv
import logging
from concurrent_log_handler import ConcurrentRotatingFileHandler

# Initialize Flask app
app = Flask(__name__)

# Load environment variables
load_dotenv()

# Configure logging
log_handler = ConcurrentRotatingFileHandler('app.log', 'a', 1024*1024, 5)
formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
log_handler.setFormatter(formatter)
app.logger.addHandler(log_handler)
app.logger.setLevel(logging.INFO)

# Initialize Supabase with error handling
try:
    supabase_url = os.environ['SUPABASE_URL']
    supabase_key = os.environ['SUPABASE_KEY']
    
    supabase: Client = create_client(
        supabase_url,
        supabase_key,
        options={
            'schema': 'public',
            'auto_refresh_token': False,
            'persist_session': False
        }
    )
    
    # Test connection
    supabase.table('used_ips').select("*").limit(1).execute()
    app.logger.info("Successfully connected to Supabase")
    
except KeyError as e:
    raise ValueError(f"Missing required environment variable: {e}")
except Exception as e:
    raise ConnectionError(f"Failed to initialize Supabase client: {str(e)}")

# Constants
MAX_WORKERS = 50
REQUEST_TIMEOUT = 4  # seconds

# Helper Functions
def get_ip_from_proxy(proxy):
    try:
        host, port, user, pw = proxy.strip().split(":")
        proxies = {
            "http": f"http://{user}:{pw}@{host}:{port}",
            "https": f"http://{user}:{pw}@{host}:{port}",
        }
        response = requests.get("https://api.ipify.org", 
                              proxies=proxies, 
                              timeout=REQUEST_TIMEOUT)
        response.raise_for_status()
        return response.text
    except Exception as e:
        app.logger.error(f"Failed to get IP from proxy {proxy}: {e}")
        return None

def get_fraud_score(ip):
    try:
        url = f"https://scamalytics.com/ip/{ip}"
        response = requests.get(url, timeout=REQUEST_TIMEOUT)
        if response.status_code == 200:
            soup = BeautifulSoup(response.text, 'html.parser')
            score_div = soup.find('div', class_='score')
            if score_div and "Fraud Score:" in score_div.text:
                return int(score_div.text.strip().split(":")[1].strip())
    except Exception as e:
        app.logger.error(f"Error checking Scamalytics for {ip}: {e}")
    return None

def track_used_ip(proxy):
    try:
        ip = get_ip_from_proxy(proxy)
        if ip:
            # Upsert record (update if exists, insert if new)
            supabase.table('used_ips').upsert({
                "ip": ip,
                "proxy": proxy,
                "last_used": datetime.now().isoformat()
            }).execute()
            return ip
    except Exception as e:
        app.logger.error(f"Error tracking IP: {e}")
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
        app.logger.error(f"Error checking IP usage: {e}")
    return False

def single_check_proxy(proxy_line):
    ip = get_ip_from_proxy(proxy_line)
    if not ip:
        return None

    score = get_fraud_score(ip)
    if score == 0:
        return proxy_line
    return None

# Routes
@app.route("/", methods=["GET", "POST"])
def index():
    results = []
    message = ""
    
    if request.method == "POST":
        proxies = []

        if 'proxyfile' in request.files and request.files['proxyfile'].filename:
            file = request.files['proxyfile']
            try:
                proxies = file.read().decode("utf-8").strip().splitlines()
                message = "Checking uploaded proxy file..."
            except Exception as e:
                message = f"⚠️ Error reading file: {str(e)}"
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
                        results.append({
                            "proxy": result,
                            "used": is_ip_used(result)
                        })

            if results:
                good_count = len([r for r in results if not r['used']])
                if good_count > 0:
                    try:
                        supabase.table('proxy_logs').insert({
                            "date": date.today().isoformat(),
                            "count": good_count
                        }).execute()
                    except Exception as e:
                        app.logger.error(f"Error saving log: {e}")

                message = f"✅ {good_count} good proxies found ({len(results) - good_count} used)."
            else:
                message = "⚠️ No good proxies found."
        else:
            message = "⚠️ No proxies provided."

    return render_template("index.html", results=results, message=message)

@app.route("/track-used", methods=["POST"])
def track_used():
    data = request.get_json()
    if data and "proxy" in data:
        track_used_ip(data["proxy"])
        return jsonify({"status": "success"})
    return jsonify({"status": "error"}), 400

@app.route("/clear-used-ips", methods=["POST"])
def clear_used_ips():
    try:
        supabase.table('used_ips').delete().neq('id', 0).execute()
        return jsonify({
            "status": "success",
            "message": "All used IP records cleared successfully"
        })
    except Exception as e:
        return jsonify({
            "status": "error",
            "message": f"Failed to clear used IPs: {str(e)}"
        }), 500

@app.route("/admin")
def admin():
    try:
        # Get stats
        logs = supabase.table('proxy_logs')\
            .select('*')\
            .order('date')\
            .execute()
        
        used_ips = supabase.table('used_ips')\
            .select('count', count=True)\
            .execute()
        
        total_good = supabase.rpc('sum_logs').execute()

        stats = {
            "total_checks": len(logs.data),
            "total_good": total_good.data[0]['sum'] if total_good.data else 0,
            "used_ips": used_ips.count
        }

        # Generate graph
        daily_data = {log['date']: log['count'] for log in logs.data}
        if daily_data:
            plt.figure(figsize=(10, 4))
            plt.plot(list(daily_data.keys()), list(daily_data.values()), 
                    marker="o", color="green")
            plt.title("Good Proxies per Day")
            plt.xlabel("Date")
            plt.ylabel("Count")
            plt.xticks(rotation=45)
            plt.tight_layout()
            if not os.path.exists("static"):
                os.makedirs("static")
            plt.savefig("static/proxy_stats.png")
            plt.close()

        return render_template(
            "admin.html",
            logs=[f"{log['date']},{log['count']} proxies" for log in logs.data],
            stats=stats,
            graph_url="/static/proxy_stats.png"
        )
    except Exception as e:
        app.logger.error(f"Admin error: {e}")
        return render_template("admin.html", logs=[], stats={}, graph_url=None)

@app.route('/static/<path:path>')
def send_static(path):
    return send_from_directory('static', path)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)))