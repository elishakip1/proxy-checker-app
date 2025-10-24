import gspread
from oauth2client.service_account import ServiceAccountCredentials
import os
import json
import datetime
import logging
import time  # <-- ADDED for caching

logger = logging.getLogger(__name__)

# --- Google Sheets Configuration ---
SCOPE = ["https://spreadsheets.google.com/feeds", "https://www.googleapis.com/auth/drive"]
SHEET_NAME = "Used IPs"  # The name of your Google Sheet file

# --- Caching Globals ---
_gspread_client = None          # <-- ADDED: Cache for the client
_client_auth_time = 0           # <-- ADDED: Time of last auth
_worksheet_cache = {}           # <-- ADDED: Cache for worksheet objects
_settings_cache = None          # <-- ADDED: Cache for settings data
_settings_cache_time = 0        # <-- ADDED: Time of last settings fetch
_blocked_ips_cache = None       # <-- ADDED: Cache for blocked IPs data
_blocked_ips_cache_time = 0     # <-- ADDED: Time of last blocked IPs fetch

# --- Helper Functions ---

def get_gsheet_client():
    """Gets a cached gspread client, re-authenticating every 50 minutes."""
    # <-- ENTIRELY NEW CACHING LOGIC ---
    global _gspread_client, _client_auth_time
    now = time.time()

    # Re-auth if client is None, or if it's been > 50 mins (3000 secs)
    if not _gspread_client or (now - _client_auth_time > 3000):
        try:
            logger.info("Authenticating Google Sheets client...")
            json_creds = os.getenv("GOOGLE_SERVICE_ACCOUNT_JSON")
            if not json_creds:
                raise ValueError("Missing GOOGLE_SERVICE_ACCOUNT_JSON environment variable.")
            creds_dict = json.loads(json_creds)
            creds = ServiceAccountCredentials.from_json_keyfile_dict(creds_dict, SCOPE)
            _gspread_client = gspread.authorize(creds)
            _client_auth_time = now
            _worksheet_cache.clear()  # Clear worksheet cache on re-auth
        except Exception as e:
            logger.critical(f"Failed to authorize Google Sheets: {e}")
            raise
    return _gspread_client

def get_worksheet(worksheet_name):
    """Gets a cached worksheet object."""
    # <-- ENTIRELY NEW CACHING LOGIC ---
    global _worksheet_cache

    # 1. Check if worksheet object is already in our cache
    if worksheet_name in _worksheet_cache:
        return _worksheet_cache[worksheet_name]

    # 2. If not, fetch it (this uses API reads)
    try:
        logger.info(f"Fetching and caching worksheet: {worksheet_name}")
        client = get_gsheet_client()
        sheet = client.open(SHEET_NAME)  # This is 1 read call
        worksheet = sheet.worksheet(worksheet_name)  # This is 1 read call
        _worksheet_cache[worksheet_name] = worksheet  # Cache it
        return worksheet
    except gspread.WorksheetNotFound:
        logger.warning(f"Worksheet '{worksheet_name}' not found, creating it.")
        client = get_gsheet_client()  # Ensure client is fresh
        sheet = client.open(SHEET_NAME)
        worksheet = sheet.add_worksheet(title=worksheet_name, rows=100, cols=10)
        _worksheet_cache[worksheet_name] = worksheet  # Cache new sheet
        return worksheet
    except gspread.exceptions.APIError as e:
        logger.error(f"APIError accessing worksheet '{worksheet_name}': {e}")
        # Force re-auth and clear cache if unauthorized
        if e.response.status_code in [401, 403]:
            logger.warning("Forcing re-auth due to API error.")
            _gspread_client = None  # Force re-auth on next call
            _worksheet_cache.clear()
            return get_worksheet(worksheet_name)  # Retry once
        raise
    except Exception as e:
        logger.error(f"Error accessing worksheet '{worksheet_name}': {e}")
        raise

# --- Settings Sheet Functions ---
def get_settings(default_settings):
    """Fetches settings from the 'Settings' tab, using a 60-second cache."""
    # <-- NEW CACHING LOGIC ADDED ---
    global _settings_cache, _settings_cache_time
    now = time.time()
    
    # Check cache (valid for 60 seconds)
    if _settings_cache and (now - _settings_cache_time < 60):
        return _settings_cache
    
    # --- End new logic
    
    try:
        logger.info("Refreshing settings cache from Google Sheet...")
        sheet = get_worksheet("Settings")  # <-- MODIFIED
        records = sheet.get_all_records()
        settings = {row['Key']: row['Value'] for row in records}

        # Ensure all default settings exist
        missing_keys = False
        for key, value in default_settings.items():
            if key not in settings:
                settings[key] = value
                missing_keys = True
        
        # Batch append missing keys to avoid multiple writes
        if missing_keys:
            rows_to_add = [[key, value] for key, value in default_settings.items() if key not in [r['Key'] for r in records]]
            if rows_to_add:
                sheet.append_rows(rows_to_add)

        _settings_cache = settings         # <-- ADDED: Store in cache
        _settings_cache_time = now         # <-- ADDED: Store time
        return settings
    except Exception as e:
        logger.error(f"Error getting settings: {e}. Returning defaults.")
        return default_settings

def update_setting(key, value):
    """Updates a setting in the 'Settings' tab."""
    global _settings_cache  # <-- ADDED: Invalidate cache
    try:
        sheet = get_worksheet("Settings")  # <-- MODIFIED
        cell = sheet.find(key)
        sheet.update_cell(cell.row, cell.col + 1, value)
        _settings_cache = None  # <-- ADDED: Invalidate cache
    except Exception as e:
        logger.error(f"Error updating setting {key}: {e}")

# --- UsedIPs Sheet Functions ---
def add_used_ip(ip, proxy):
    """Appends a used IP to the 'UsedIPs' tab."""
    try:
        sheet = get_worksheet("UsedIPs")  # <-- MODIFIED
        sheet.append_row([ip, proxy, str(datetime.datetime.utcnow())])
    except Exception as e:
        logger.error(f"Error appending used IP {ip}: {e}")

def get_all_used_ips():
    """Lists all records from the 'UsedIPs' tab."""
    try:
        sheet = get_worksheet("UsedIPs")  # <-- MODIFIED
        return sheet.get_all_records()
    except Exception as e:
        logger.error(f"Error listing used IPs: {e}")
        return []

def delete_used_ip(ip):
    """Deletes a row from 'UsedIPs' by IP address."""
    try:
        sheet = get_worksheet("UsedIPs")  # <-- MODIFIED
        cell = sheet.find(ip)
        if cell:
            sheet.delete_rows(cell.row)
            return True
        return False
    except Exception as e:
        logger.error(f"Error deleting used IP {ip}: {e}")
        return False

# --- GoodProxies Sheet Functions ---
def log_good_proxy(proxy, ip):
    """Logs a new good proxy to the 'GoodProxies' tab."""
    try:
        sheet = get_worksheet("GoodProxies")  # <-- MODIFIED
        sheet.append_row([proxy, ip, str(datetime.datetime.utcnow())])
    except Exception as e:
        logger.error(f"Error logging good proxy: {e}")

def get_good_proxies():
    """Lists all records from the 'GoodProxies' tab."""
    try:
        sheet = get_worksheet("GoodProxies")  # <-- MODIFIED
        return sheet.get_all_records()
    except Exception as e:
        logger.error(f"Error getting good proxies: {e}")
        return []

# --- AccessLogs Sheet Functions ---
def log_user_access(ip, user_agent):
    """Logs a user access event to the 'AccessLogs' tab."""
    try:
        sheet = get_worksheet("AccessLogs")  # <-- MODIFIED
        sheet.append_row([str(datetime.datetime.utcnow()), ip, user_agent])
    except Exception as e:
        logger.error(f"Error logging user access: {e}")

# --- BlockedIPs Sheet Functions ---
def get_blocked_ips():
    """Lists all records from the 'BlockedIPs' tab."""
    try:
        sheet = get_worksheet("BlockedIPs")  # <-- MODIFIED
        return sheet.get_all_records()
    except Exception as e:
        logger.error(f"Error getting blocked IPs: {e}")
        return []

def is_ip_blocked(ip):
    """Checks if an IP is in the 'BlockedIPs' tab, using a 60-second cache."""
    # <-- NEW CACHING LOGIC ADDED ---
    global _blocked_ips_cache, _blocked_ips_cache_time
    now = time.time()

    if _blocked_ips_cache is None or (now - _blocked_ips_cache_time > 60):
        logger.info("Refreshing blocked IP cache...")
        try:
            sheet = get_worksheet("BlockedIPs")  # <-- MODIFIED
            _blocked_ips_cache = set(sheet.col_values(1))  # Use a set for fast lookups
            _blocked_ips_cache_time = now
        except Exception as e:
            logger.error(f"Error checking if IP {ip} is blocked: {e}")
            _blocked_ips_cache = set() # Use empty set on failure
            _blocked_ips_cache_time = now # Prevent re-trying for 60s
            return False  # Fail-safe
    
    return ip in _blocked_ips_cache
    # --- End new logic

def add_blocked_ip(ip, reason):
    """Adds an IP to the 'BlockedIPs' tab."""
    global _blocked_ips_cache  # <-- ADDED: Invalidate cache
    try:
        sheet = get_worksheet("BlockedIPs")  # <-- MODIFIED
        sheet.append_row([ip, reason, str(datetime.datetime.utcnow())])
        _blocked_ips_cache = None  # <-- ADDED: Invalidate cache
        return True
    except Exception as e:
        logger.error(f"Error adding blocked IP {ip}: {e}")
        return False

def remove_blocked_ip(ip):
    """Removes an IP from the 'BlockedIPs' tab."""
    global _blocked_ips_cache  # <-- ADDED: Invalidate cache
    try:
        sheet = get_worksheet("BlockedIPs")  # <-- MODIFIED
        cell = sheet.find(ip)
        if cell:
            sheet.delete_rows(cell.row)
            _blocked_ips_cache = None  # <-- ADDED: Invalidate cache
            return True
        return False
    except Exception as e:
        logger.error(f"Error removing blocked IP {ip}: {e}")
        return False
