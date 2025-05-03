from flask import Flask, request, render_template, send_from_directory, jsonify
from flask_sqlalchemy import SQLAlchemy
# Add this at the very top of app.py before other imports
import matplotlib
matplotlib.use('Agg')  # Set the backend before importing pyplot
import matplotlib.pyplot as plt
import os
import requests
from bs4 import BeautifulSoup
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, date, timedelta
import matplotlib.pyplot as plt
import atexit
from apscheduler.schedulers.background import BackgroundScheduler

app = Flask(__name__)

# Configure database - uses Render's PostgreSQL by default
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL', 'sqlite:///local.db').replace('postgres://', 'postgresql://')
app.config['SQLALCHEMY_ENGINE_OPTIONS'] = {
    'pool_pre_ping': True,
    'pool_recycle': 300,
    'pool_size': 20,
    'max_overflow': 0
}
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

# Database Models
class UsedIP(db.Model):
    __tablename__ = 'used_ips'
    id = db.Column(db.Integer, primary_key=True)
    ip = db.Column(db.String(50), nullable=False, unique=True)
    proxy = db.Column(db.String(200), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    last_used = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

class ProxyLog(db.Model):
    __tablename__ = 'proxy_logs'
    id = db.Column(db.Integer, primary_key=True)
    date = db.Column(db.Date, default=date.today, nullable=False)
    count = db.Column(db.Integer, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

# Constants
MAX_WORKERS = 50
REQUEST_TIMEOUT = 4  # seconds

# Database maintenance
def cleanup_old_records():
    with app.app_context():
        try:
            # Delete logs older than 30 days
            old_logs = ProxyLog.query.filter(
                ProxyLog.date < date.today() - timedelta(days=30)
            ).delete()
            
            # Delete IPs not used in 60 days
            old_ips = UsedIP.query.filter(
                UsedIP.last_used < datetime.utcnow() - timedelta(days=60)
            ).delete()
            
            db.session.commit()
            app.logger.info(f"Cleaned up {old_logs} old logs and {old_ips} old IPs")
        except Exception as e:
            db.session.rollback()
            app.logger.error(f"Cleanup error: {str(e)}")

# Initialize scheduler
scheduler = BackgroundScheduler()
scheduler.add_job(func=cleanup_old_records, trigger="interval", days=1)
scheduler.start()
atexit.register(lambda: scheduler.shutdown())

# Helper Functions
def get_ip_from_proxy(proxy):
    try:
        host, port, user, pw = proxy.strip().split(":")
        proxies = {
            "http": f"http://{user}:{pw}@{host}:{port}",
            "https": f"http://{user}:{pw}@{host}:{port}",
        }
        response = requests.get("https://api.ipify.org", proxies=proxies, timeout=REQUEST_TIMEOUT)
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
            existing = UsedIP.query.filter_by(ip=ip).first()
            if not existing:
                new_ip = UsedIP(ip=ip, proxy=proxy)
                db.session.add(new_ip)
            else:
                existing.last_used = datetime.utcnow()
            db.session.commit()
            return ip
    except Exception as e:
        app.logger.error(f"Error tracking IP: {e}")
        db.session.rollback()
    return None

def is_ip_used(proxy):
    try:
        ip = get_ip_from_proxy(proxy)
        return ip and bool(UsedIP.query.filter_by(ip=ip).first())
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
                        new_log = ProxyLog(count=good_count)
                        db.session.add(new_log)
                        db.session.commit()
                    except Exception as e:
                        db.session.rollback()
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
        num_deleted = UsedIP.query.delete()
        db.session.commit()
        return jsonify({
            "status": "success",
            "message": f"Cleared {num_deleted} used IP records"
        })
    except Exception as e:
        db.session.rollback()
        return jsonify({
            "status": "error",
            "message": f"Failed to clear used IPs: {str(e)}"
        }), 500

@app.route("/admin")
def admin():
    stats = {
        "total_checks": ProxyLog.query.count(),
        "total_good": db.session.query(db.func.sum(ProxyLog.count)).scalar() or 0,
        "used_ips": UsedIP.query.count()
    }

    # Generate graph
    logs = ProxyLog.query.order_by(ProxyLog.date).all()
    daily_data = {log.date.strftime('%Y-%m-%d'): log.count for log in logs}

    if daily_data:
        plt.figure(figsize=(10, 4))
        plt.plot(list(daily_data.keys()), list(daily_data.values()), marker="o", color="green")
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
        logs=[f"{log.date},{log.count} proxies" for log in logs],
        stats=stats,
        graph_url="/static/proxy_stats.png"
    )

@app.route('/static/<path:path>')
def send_static(path):
    return send_from_directory('static', path)

# Initialize database
with app.app_context():
    db.create_all()

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)))