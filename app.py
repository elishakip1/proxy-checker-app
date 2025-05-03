from flask import Flask, request, render_template, jsonify
import os
import logging
from logging.handlers import RotatingFileHandler
from datetime import datetime, date
from concurrent.futures import ThreadPoolExecutor, as_completed
import requests
from bs4 import BeautifulSoup
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
from dotenv import load_dotenv
from supabase import create_client

# Initialize Flask
app = Flask(__name__)
load_dotenv()

# Configure logging
logging.basicConfig(level=logging.INFO)
log_handler = RotatingFileHandler('app.log', maxBytes=1_048_576, backupCount=5)
log_handler.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))
app.logger.addHandler(log_handler)

# Initialize Supabase
try:
    supabase = create_client(
        os.getenv('SUPABASE_URL'),
        os.getenv('SUPABASE_KEY')
    )
    app.logger.info("Supabase initialized successfully")
except Exception as e:
    app.logger.error(f"Supabase initialization failed: {e}")
    supabase = None

# Constants
MAX_WORKERS = 10  # Reduced for stability
REQUEST_TIMEOUT = 15

@app.route('/', methods=['GET', 'POST'])
def index():
    results = []  # Always initialize results
    message = ""
    error = None

    try:
        if request.method == 'POST':
            proxies = []
            
            # Handle both file upload and text input
            if 'proxyfile' in request.files and request.files['proxyfile'].filename:
                try:
                    file = request.files['proxyfile']
                    proxies = file.read().decode('utf-8').splitlines()
                except Exception as e:
                    error = f"Error reading file: {str(e)}"
                    app.logger.error(error)
            
            if 'proxytext' in request.form and not error:
                proxies.extend(request.form['proxytext'].splitlines())

            if proxies and not error:
                proxies = list({p.strip() for p in proxies if p.strip()})
                
                with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
                    futures = [executor.submit(check_proxy, proxy) for proxy in proxies]
                    for future in as_completed(futures):
                        try:
                            result = future.result()
                            if result:
                                results.append(result)
                        except Exception as e:
                            app.logger.error(f"Proxy check failed: {e}")

                if results:
                    good_count = len([r for r in results if not r.get('used', True)])
                    message = f"Found {good_count} good proxies out of {len(results)}"
                    
                    # Log results if Supabase is available
                    if supabase and good_count > 0:
                        try:
                            supabase.table('proxy_logs').insert({
                                'date': date.today().isoformat(),
                                'count': good_count
                            }).execute()
                        except Exception as e:
                            app.logger.error(f"Failed to log results: {e}")

    except Exception as e:
        error = f"Server error: {str(e)}"
        app.logger.error(f"Index route error: {e}")

    return render_template(
        'index.html',
        results=results,
        message=message,
        error=error
    )

def check_proxy(proxy):
    try:
        # Validate proxy format
        parts = proxy.split(':')
        if len(parts) != 4:
            raise ValueError("Invalid proxy format (host:port:user:pass)")
        
        # Get IP through proxy
        ip = get_ip_from_proxy(proxy)
        if not ip:
            return None
        
        # Check fraud score
        score = get_fraud_score(ip)
        if score == 0:
            return {
                'proxy': proxy,
                'ip': ip,
                'used': is_ip_used(proxy) if supabase else False
            }
        return None
        
    except Exception as e:
        app.logger.error(f"Error checking proxy {proxy}: {e}")
        return None

def get_ip_from_proxy(proxy):
    try:
        host, port, user, pw = proxy.split(':')
        proxies = {
            'http': f'http://{user}:{pw}@{host}:{port}',
            'https': f'http://{user}:{pw}@{host}:{port}'
        }
        
        # Try multiple endpoints
        for endpoint in ['http://api.ipify.org', 'https://api.ipify.org']:
            try:
                response = requests.get(
                    endpoint,
                    proxies=proxies,
                    timeout=REQUEST_TIMEOUT,
                    verify=False  # Disable SSL verification for testing
                )
                response.raise_for_status()
                return response.text.strip()
            except requests.exceptions.RequestException as e:
                continue
                
        app.logger.warning(f"All IP check attempts failed for proxy: {proxy}")
        return None
        
    except Exception as e:
        app.logger.error(f"IP fetch failed for {proxy}: {e}")
        return None

def get_fraud_score(ip):
    try:
        response = requests.get(
            f'http://scamalytics.com/ip/{ip}',
            timeout=REQUEST_TIMEOUT
        )
        if response.status_code == 200:
            soup = BeautifulSoup(response.text, 'html.parser')
            score_div = soup.find('div', class_='score')
            if score_div and 'Fraud Score:' in score_div.text:
                return int(score_div.text.strip().split(':')[1].strip())
        return None
    except Exception as e:
        app.logger.error(f"Fraud score check failed for {ip}: {e}")
        return None

def is_ip_used(proxy):
    try:
        ip = get_ip_from_proxy(proxy)
        if not ip or not supabase:
            return False
            
        result = supabase.table('used_ips')\
            .select('ip')\
            .eq('ip', ip)\
            .execute()
            
        return len(result.data) > 0
        
    except Exception as e:
        app.logger.error(f"IP usage check failed: {e}")
        return False

@app.route('/track-used', methods=['POST'])
def track_used():
    try:
        data = request.get_json()
        if not data or 'proxy' not in data:
            return jsonify({'status': 'error', 'message': 'Invalid request'}), 400
            
        if not supabase:
            return jsonify({'status': 'error', 'message': 'Database not available'}), 500
            
        track_used_ip(data['proxy'])
        return jsonify({'status': 'success'})
        
    except Exception as e:
        app.logger.error(f"Track used error: {e}")
        return jsonify({'status': 'error', 'message': str(e)}), 500

def track_used_ip(proxy):
    try:
        ip = get_ip_from_proxy(proxy)
        if ip and supabase:
            supabase.table('used_ips').upsert({
                'ip': ip,
                'proxy': proxy,
                'last_used': datetime.now().isoformat()
            }).execute()
    except Exception as e:
        app.logger.error(f"Failed to track IP: {e}")
        raise

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port)