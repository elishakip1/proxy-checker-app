# Standard Library Imports
import os
import logging
from logging.handlers import RotatingFileHandler
from datetime import datetime, date, timedelta
from concurrent.futures import ThreadPoolExecutor, as_completed

# Third-Party Imports
from flask import Flask, request, render_template, send_from_directory, jsonify
import requests
from bs4 import BeautifulSoup
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
from dotenv import load_dotenv

# Try multiple Supabase client initialization approaches
try:
    # Approach 1: Newest supported version
    from supabase import create_client, Client
    supabase = None
    try:
        supabase = create_client(
            os.getenv('SUPABASE_URL'),
            os.getenv('SUPABASE_KEY')
        )
    except Exception as e:
        # Approach 2: Fallback for older versions
        supabase = create_client(
            os.getenv('SUPABASE_URL'),
            os.getenv('SUPABASE_KEY'),
            {'auto_refresh_token': False}
        )
except ImportError:
    # Approach 3: Direct HTTP requests as last resort
    supabase = None
    logging.warning("Supabase client not available, using direct HTTP requests")

# Initialize Flask
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

# Constants
MAX_WORKERS = 50
REQUEST_TIMEOUT = 4

# Database Operations with Fallbacks
def supabase_insert(table, data):
    if supabase:
        try:
            return supabase.table(table).insert(data).execute()
        except Exception:
            pass
    # Fallback to direct HTTP request
    headers = {
        "apikey": os.getenv('SUPABASE_KEY'),
        "Authorization": f"Bearer {os.getenv('SUPABASE_KEY')}",
        "Content-Type": "application/json"
    }
    url = f"{os.getenv('SUPABASE_URL')}/rest/v1/{table}"
    return requests.post(url, json=data, headers=headers)

# [Keep all your existing helper functions but replace supabase calls with supabase_insert()]

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)))