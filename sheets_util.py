import gspread
from oauth2client.service_account import ServiceAccountCredentials
import os
import json
import datetime
import logging

logger = logging.getLogger(__name__)

# --- Google Sheets Configuration ---
SCOPE = ["https://spreadsheets.google.com/feeds", "https://www.googleapis.com/auth/drive"]
SHEET_NAME = "Used IPs" # The name of your Google Sheet file

# --- Helper Functions ---
def get_gsheet_client():
    """Authenticates with Google Sheets and returns a client object."""
    try:
        json_creds = os.getenv("GOOGLE_SERVICE_ACCOUNT_JSON")
        if not json_creds:
            raise ValueError("Missing GOOGLE_SERVICE_ACCOUNT_JSON environment variable.")
        creds_dict = json.loads(json_creds)
        creds = ServiceAccountCredentials.from_json_keyfile_dict(creds_dict, SCOPE)
        return gspread.authorize(creds)
    except Exception as e:
        logger.critical(f"Failed to authorize Google Sheets: {e}")
        raise

def get_worksheet(client, worksheet_name):
    """Gets a specific worksheet by name, creating it if it doesn't exist."""
    try:
        sheet = client.open(SHEET_NAME)
        try:
            return sheet.worksheet(worksheet_name)
        except gspread.WorksheetNotFound:
            logger.warning(f"Worksheet '{worksheet_name}' not found, creating it.")
            return sheet.add_worksheet(title=worksheet_name, rows=100, cols=10)
    except Exception as e:
        logger.error(f"Error accessing worksheet '{worksheet_name}': {e}")
        raise

# --- Settings Sheet Functions ---
def get_settings(default_settings):
    """Fetches settings from the 'Settings' tab."""
    try:
        client = get_gsheet_client()
        sheet = get_worksheet(client, "Settings")
        records = sheet.get_all_records()
        settings = {row['Key']: row['Value'] for row in records}
        
        # Ensure all default settings exist
        for key, value in default_settings.items():
            if key not in settings:
                sheet.append_row([key, value])
                settings[key] = value
        return settings
    except Exception as e:
        logger.error(f"Error getting settings: {e}. Returning defaults.")
        return default_settings

def update_setting(key, value):
    """Updates a setting in the 'Settings' tab."""
    try:
        client = get_gsheet_client()
        sheet = get_worksheet(client, "Settings")
        cell = sheet.find(key)
        sheet.update_cell(cell.row, cell.col + 1, value)
    except Exception as e:
        logger.error(f"Error updating setting {key}: {e}")

# --- UsedIPs Sheet Functions ---
def add_used_ip(ip, proxy):
    """Appends a used IP to the 'UsedIPs' tab."""
    try:
        client = get_gsheet_client()
        sheet = get_worksheet(client, "UsedIPs")
        sheet.append_row([ip, proxy, str(datetime.datetime.utcnow())])
    except Exception as e:
        logger.error(f"Error appending used IP {ip}: {e}")

def get_all_used_ips():
    """Lists all records from the 'UsedIPs' tab."""
    try:
        client = get_gsheet_client()
        sheet = get_worksheet(client, "UsedIPs")
        return sheet.get_all_records()
    except Exception as e:
        logger.error(f"Error listing used IPs: {e}")
        return []

def delete_used_ip(ip):
    """Deletes a row from 'UsedIPs' by IP address."""
    try:
        client = get_gsheet_client()
        sheet = get_worksheet(client, "UsedIPs")
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
        client = get_gsheet_client()
        sheet = get_worksheet(client, "GoodProxies")
        sheet.append_row([proxy, ip, str(datetime.datetime.utcnow())])
    except Exception as e:
        logger.error(f"Error logging good proxy: {e}")

def get_good_proxies():
    """Lists all records from the 'GoodProxies' tab."""
    try:
        client = get_gsheet_client()
        sheet = get_worksheet(client, "GoodProxies")
        return sheet.get_all_records()
    except Exception as e:
        logger.error(f"Error getting good proxies: {e}")
        return []

# --- AccessLogs Sheet Functions ---
def log_user_access(ip, user_agent):
    """Logs a user access event to the 'AccessLogs' tab."""
    try:
        client = get_gsheet_client()
        sheet = get_worksheet(client, "AccessLogs")
        sheet.append_row([str(datetime.datetime.utcnow()), ip, user_agent])
    except Exception as e:
        logger.error(f"Error logging user access: {e}")

# --- BlockedIPs Sheet Functions ---
def get_blocked_ips():
    """Lists all records from the 'BlockedIPs' tab."""
    try:
        client = get_gsheet_client()
        sheet = get_worksheet(client, "BlockedIPs")
        return sheet.get_all_records()
    except Exception as e:
        logger.error(f"Error getting blocked IPs: {e}")
        return []

def is_ip_blocked(ip):
    """Checks if an IP is in the 'BlockedIPs' tab."""
    try:
        client = get_gsheet_client()
        sheet = get_worksheet(client, "BlockedIPs")
        ips = sheet.col_values(1)
        return ip in ips
    except Exception as e:
        logger.error(f"Error checking if IP {ip} is blocked: {e}")
        return False # Fail-safe: don't block if check fails

def add_blocked_ip(ip, reason):
    """Adds an IP to the 'BlockedIPs' tab."""
    try:
        client = get_gsheet_client()
        sheet = get_worksheet(client, "BlockedIPs")
        sheet.append_row([ip, reason, str(datetime.datetime.utcnow())])
        return True
    except Exception as e:
        logger.error(f"Error adding blocked IP {ip}: {e}")
        return False

def remove_blocked_ip(ip):
    """Removes an IP from the 'BlockedIPs' tab."""
    try:
        client = get_gsheet_client()
        sheet = get_worksheet(client, "BlockedIPs")
        cell = sheet.find(ip)
        if cell:
            sheet.delete_rows(cell.row)
            return True
        return False
    except Exception as e:
        logger.error(f"Error removing blocked IP {ip}: {e}")
        return False
