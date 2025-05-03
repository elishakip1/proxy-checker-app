# Standard Library Imports
import os
import logging
import socket
from logging.handlers import RotatingFileHandler
from datetime import datetime, date
from concurrent.futures import ThreadPoolExecutor, as_completed
import ssl

# Third-Party Imports
from flask import Flask, request, render_template, send_from_directory, jsonify
from supabase import create_client
import requests
from bs4 import BeautifulSoup
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
from dotenv import load_dotenv
from urllib3.util.retry import Retry
from requests.adapters import HTTPAdapter

# Initialize Flask App
app = Flask(__name__)
load_dotenv()

# Configure Logging
logging.basicConfig(level=logging.INFO)
log_handler = RotatingFileHandler(
    'app.log',
    maxBytes=1_048_576,
    backupCount=5,
    encoding='utf-8'
)
log_handler.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))
app.logger.addHandler(log_handler)

# Configure requests session with retries
session = requests.Session()
retries = Retry(
    total=3,
    backoff_factor=1,
    status_forcelist=[500, 502, 503, 504]
)
session.mount('https://', HTTPAdapter(max_retries=retries))

# Initialize Supabase Client
try:
    supabase = create_client(
        os.getenv('SUPABASE_URL'),
        os.getenv('SUPABASE_KEY')
    )
    app.logger.info("Supabase client initialized successfully")
except Exception as e:
    app.logger.error(f"Supabase initialization error: {e}")
    raise

# Constants
MAX_WORKERS = 20  # Reduced for better stability
REQUEST_TIMEOUT = 10  # Increased timeout
SSL_CONTEXT = ssl.create_default_context()
SSL_CONTEXT.check_hostname = False
SSL_CONTEXT.verify_mode = ssl.CERT_NONE  # Disable SSL verification (use with caution)

# Helper Functions
def get_ip_from_proxy(proxy):
    try:
        host, port, user, pw = proxy.strip().split(':')
        proxies = {
            "http": f"http://{user}:{pw}@{host}:{port}",
            "https": f"http://{user}:{pw}@{host}:{port}"
        }
        
        # Try both SSL and non-SSL endpoints
        endpoints = [
            "http://api.ipify.org",  # Try HTTP first
            "https://api.ipify.org"
        ]
        
        for endpoint in endpoints:
            try:
                response = session.get(
                    endpoint,
                    proxies=proxies,
                    timeout=REQUEST_TIMEOUT,
                    verify=False  # Disable SSL verification
                )
                response.raise_for_status()
                return response.text
            except requests.exceptions.SSLError:
                continue
            except Exception as e:
                app.logger.warning(f"Attempt failed with {endpoint}: {str(e)}")
                continue
                
        app.logger.error(f"All endpoint attempts failed for proxy: {proxy}")
        return None
        
    except Exception as e:
        app.logger.error(f"Proxy IP fetch failed: {e}")
        return None

def get_fraud_score(ip):
    if not ip:
        return None
        
    try:
        response = session.get(
            f"http://scamalytics.com/ip/{ip}",  # Using HTTP to avoid SSL issues
            timeout=REQUEST_TIMEOUT,
            verify=False
        )
        if response.status_code == 200:
            soup = BeautifulSoup(response.text, 'html.parser')
            score_div = soup.find('div', class_='score')
            if score_div and "Fraud Score:" in score_div.text:
                return int(score_div.text.strip().split(":")[1].strip())
    except Exception as e:
        app.logger.error(f"Fraud score check failed: {e}")
    return None

# [Rest of your functions remain the same...]

def is_ip_used(proxy):
    try:
        ip = get_ip_from_proxy(proxy)
        if ip:
            # First try direct Supabase connection
            try:
                result = supabase.table('used_ips')\
                    .select('ip')\
                    .eq('ip', ip)\
                    .execute()
                return len(result.data) > 0
            except Exception as e:
                app.logger.warning(f"Supabase query failed, trying fallback: {e}")
                # Fallback to direct HTTP request if Supabase fails
                headers = {
                    "apikey": os.getenv('SUPABASE_KEY'),
                    "Authorization": f"Bearer {os.getenv('SUPABASE_KEY')}",
                    "Content-Type": "application/json"
                }
                url = f"{os.getenv('SUPABASE_URL')}/rest/v1/used_ips?ip=eq.{ip}"
                response = session.get(url, headers=headers, timeout=REQUEST_TIMEOUT)
                return len(response.json()) > 0
    except Exception as e:
        app.logger.error(f"IP usage check failed: {e}")
    return False

# [Keep all your existing routes and other functions...]

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)))