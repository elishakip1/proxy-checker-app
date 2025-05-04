import os
import json
import gspread
from oauth2client.service_account import ServiceAccountCredentials

SCOPE = [
    "https://www.googleapis.com/auth/spreadsheets",
    "https://www.googleapis.com/auth/drive"
]

SHEET_NAME = "Used IP List"  # Your exact Google Sheet name

def get_sheet():
    creds_dict = json.loads(os.environ.get("GOOGLE_CREDENTIALS"))
    creds = ServiceAccountCredentials.from_json_keyfile_dict(creds_dict, SCOPE)
    client = gspread.authorize(creds)
    return client.open(SHEET_NAME).sheet1

def add_used_ip(ip, proxy):
    sheet = get_sheet()
    sheet.append_row([ip, proxy])

def delete_used_ip(ip):
    sheet = get_sheet()
    data = sheet.get_all_values()
    for i, row in enumerate(data):
        if row and row[0] == ip:
            sheet.delete_row(i + 1)
            return True
    return False

def get_all_used_ips():
    sheet = get_sheet()
    return [row[0] for row in sheet.get_all_values() if row]
