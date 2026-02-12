import hmac
import hashlib
import base64
import json
import datetime
import urllib.request
import subprocess
from email.utils import parsedate_to_datetime
import os
from dotenv import load_dotenv

load_dotenv()
SECRET_KEY = os.getenv("SECRET_KEY").encode()

def get_hwid():
    """ 
    Gets the unique Motherboard UUID of the current computer.
    Returns a hashed version to keep it short and clean.
    """
    try:
        # Ask Windows for the Computer System Product UUID
        cmd = 'wmic csproduct get uuid'
        output = subprocess.check_output(cmd, shell=True).decode()
        # Output looks like: "UUID \n FFFFFF-AAAA-...."
        # We split by lines and grab the second one (the actual ID)
        raw_uuid = output.split('\n')[1].strip()
        
        # We hash it so it's a clean, consistent string length
        return hashlib.md5(raw_uuid.encode()).hexdigest().upper()
    except Exception:
        return "UNKNOWN_HWID"

def get_network_date():
    try:
        req = urllib.request.Request(
            "https://www.google.com", 
            method="HEAD", 
            headers={'User-Agent': 'Mozilla/5.0'}
        )
        with urllib.request.urlopen(req, timeout=5) as response:
            date_string = response.headers['Date']
            return parsedate_to_datetime(date_string).date()
    except:
        return None

def generate_license(days_valid, target_hwid):
    """ Generates a license locked to a specific HWID """
    expiration_date = datetime.date.today() + datetime.timedelta(days=days_valid)
    date_str = expiration_date.strftime("%Y-%m-%d")
    
    # Payload now includes the HWID
    data = {
        "expires": date_str,
        "hwid": target_hwid.strip()
    }
    
    payload = json.dumps(data).encode()
    b64_payload = base64.urlsafe_b64encode(payload).decode()
    signature = hmac.new(SECRET_KEY, b64_payload.encode(), hashlib.sha256).hexdigest()
    return f"{b64_payload}.{signature}", date_str

def validate_license(key):
    try:
        if "." not in key: return False, "Invalid Format"
        b64_payload, received_sig = key.split(".", 1)
        
        # 1. Verify Signature
        expected_sig = hmac.new(SECRET_KEY, b64_payload.encode(), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(expected_sig, received_sig):
            return False, "Invalid Signature (Tampered)"
            
        # 2. Extract Data
        json_payload = base64.urlsafe_b64decode(b64_payload).decode()
        data = json.loads(json_payload)
        
        expires_str = data.get("expires")
        key_hwid = data.get("hwid")
        
        # 3. HWID CHECK (The new Security Layer)
        current_hwid = get_hwid()
        if key_hwid != current_hwid:
            return False, f"Key Locked to another Machine.\nYour HWID: {current_hwid}\nKey HWID: {key_hwid}"
        
        # 4. Time Check
        expiration_date = datetime.datetime.strptime(expires_str, "%Y-%m-%d").date()
        
        current_date = get_network_date()
        
        if current_date is None:
            return False, "Connection Failed: Internet required."
        
        if current_date > expiration_date:
            return False, f"Expired on {expires_str}"
            
        return True, f"Valid until {expires_str}"
    except Exception as e:
        print(e)
        return False, "Corrupted Key"
