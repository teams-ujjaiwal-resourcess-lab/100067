import os
import time
import httpx
import sys
import json
import random
import hashlib
import threading
import uuid
import signal
from collections import defaultdict
from queue import Queue
from flask import Flask, request, jsonify, make_response
from flask_cors import CORS
from cachetools import TTLCache
from flask_caching import Cache
from cfonts import render, say
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from google.protobuf import json_format, message
from google.protobuf.message import Message
from google.protobuf.timestamp_pb2 import Timestamp
from protobuf_decoder.protobuf_decoder import Parser
import base64
import requests 
import FreeFire_pb2
import logging
import pickle  # it's 'ME' don't change!! 
import urllib3
# (third's party) DO NOT CHANGE! 
#from dataclasses import dataclass, asdict
#from typing import Dict, List, Optional, Tuple, Any
from datetime import datetime, timedelta, timezone
from time import sleep
from colorama import Fore, Style, init
import warnings
# (no need) DO NOT EDIT!
#from fastapi import FastAPI, Query
#from fastapi.responses import HTMLResponse
from urllib.parse import urlparse, parse_qs
from urllib3.exceptions import InsecureRequestWarning
from concurrent.futures import ThreadPoolExecutor, as_completed
from multiprocessing.dummy import Pool as ThreadPool
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Disable SSL warning
warnings.filterwarnings("ignore", category=InsecureRequestWarning)
# Global variables
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
warnings.filterwarnings("ignore")
# Logging setup
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("genjwt_token.log"),
        logging.StreamHandler(sys.stdout)
    ]
)

# Reduce log noise from libraries
logging.getLogger("httpx").setLevel(logging.WARNING)
logging.getLogger("urllib3").setLevel(logging.WARNING)
logging.getLogger("requests").setLevel(logging.WARNING)

# === Constants Settings from Environment Variables ===
MAIN_KEY = base64.b64decode(os.getenv('MAIN_KEY', 'WWcmdGMlREV1aDYlWmNeOA=='))
MAIN_IV = base64.b64decode(os.getenv('MAIN_IV', 'Nm95WkRyMjJFM3ljaGpNJQ=='))
CLIENT_SECRET = os.getenv('CLIENT_SECRET', '2ee44819e9b4598845141067b281621874d0d5d7af9d8f7e00c1e54715b7d1e3')
CLIENT_ID = os.getenv('CLIENT_ID', '100067')

# Cache file for pickle
CACHE_FILE = 'status_cache.pkl'

# Load cache from pickle file
def load_cache():
    if os.path.exists(CACHE_FILE):
        try:
            with open(CACHE_FILE, 'rb') as f:
                return pickle.load(f)
        except (pickle.PickleError, EOFError, FileNotFoundError):
            return {}
    return {}

# Save cache to pickle file
def save_cache(cache_data):
    try:
        with open(CACHE_FILE, 'wb') as f:
            pickle.dump(cache_data, f)
    except Exception as e:
        logging.error(f"Failed to save cache: {str(e)}")

# Initialize cache from pickle file
pickle_cache = load_cache()

# Init colorama
init(autoreset=True)

# === Flask App Setup ===
app = Flask(__name__)
CORS(app)
# Configure Flask-Caching
cache = Cache(app, config={'CACHE_TYPE': 'SimpleCache', 'CACHE_DEFAULT_TIMEOUT': 25200})

# === Connection Pooling Setup ===
def setup_connection_pool():
    """Setup connection pooling for better performance"""
    session = requests.Session()
    retry_strategy = Retry(
        total=3,
        backoff_factor=1,
        status_forcelist=[429, 500, 502, 503, 504],
    )
    adapter = HTTPAdapter(
        max_retries=retry_strategy,
        pool_connections=20,
        pool_maxsize=50,
        pool_block=False
    )
    session.mount("https://", adapter)
    session.mount("http://", adapter)
    session.verify = False
    return session

# Global session with connection pooling
SESSION = setup_connection_pool()

# Store request status
request_status = {}

# Cache metrics
cache_hits = 0
cache_misses = 0
start_time = time.time()

# === Rate Limiting per UID ===
rate_limit_uid = defaultdict(list)

def is_uid_rate_limited(uid):
    """Check if UID has exceeded rate limit (10 requests per minute)"""
    now = time.time()
    # Clean old requests (older than 60 seconds)
    rate_limit_uid[uid] = [t for t in rate_limit_uid[uid] if now - t < 60]
    
    if len(rate_limit_uid[uid]) >= 10:  # Max 10 requests per minute per UID
        return True
    
    rate_limit_uid[uid].append(now)
    return False

# === Retry Mechanism ===
def generate_with_retry(password, uid, max_retries=3):
    """Generate token with automatic retry on failure"""
    for attempt in range(max_retries):
        try:
            if attempt > 0:
                logging.info(f"Retry attempt {attempt + 1}/{max_retries} for UID: {uid}")
            
            result = generate_jwt_token(password, uid)
            
            if result and result.get('token'):
                if attempt > 0:
                    logging.info(f"Success on retry attempt {attempt + 1} for UID: {uid}")
                return result
            else:
                if attempt < max_retries - 1:
                    wait_time = (attempt + 1) * 2  # 2, 4, 6 seconds
                    logging.warning(f"Attempt {attempt + 1} failed for UID: {uid}, waiting {wait_time}s")
                    time.sleep(wait_time)
                    
        except Exception as e:
            logging.error(f"Error on attempt {attempt + 1} for UID {uid}: {str(e)}")
            if attempt < max_retries - 1:
                time.sleep((attempt + 1) * 2)
    
    logging.error(f"All {max_retries} attempts failed for UID: {uid}")
    return None

# === Helper Functions ===
def pad(text: bytes) -> bytes:
    padding_length = AES.block_size - (len(text) % AES.block_size)
    return text + bytes([padding_length] * padding_length)

def aes_cbc_encrypt(key: bytes, iv: bytes, plaintext: bytes) -> bytes:
    aes = AES.new(key, AES.MODE_CBC, iv)
    return aes.encrypt(pad(plaintext))

def decode_protobuf(encoded_data: bytes, message_type: message.Message) -> message.Message:
    instance = message_type()
    instance.ParseFromString(encoded_data)
    return instance

def json_to_proto(json_data: str, proto_message: Message) -> bytes:
    json_format.ParseDict(json.loads(json_data), proto_message)
    return proto_message.SerializeToString()

def clean_expired_cache():
    """Clean expired entries from pickle cache (5 hours)"""
    expired_keys = []
    current_time = time.time()
    
    for key, value in pickle_cache.items():
        if current_time - value.get('timestamp', 0) > 18000:  # 5 hours
            expired_keys.append(key)
    
    for key in expired_keys:
        del pickle_cache[key]
    
    if expired_keys:
        save_cache(pickle_cache)
        logging.info(f"Cleaned {len(expired_keys)} expired cache entries")

# GarenaMSDK/  DO NOT EDIT! 
def get_random_user_agent():
    versions = [
        '4.0.18P6', '4.0.19P7', '4.0.20P1', '4.1.0P3', '4.1.5P2', '4.2.1P8',
        '4.2.3P1', '5.0.1B2', '5.0.2P4', '5.1.0P1', '5.2.0B1', '5.2.5P3',
        '5.3.0B1', '5.3.2P2', '5.4.0P1', '5.4.3B2', '5.5.0P1', '5.5.2P3'
    ]
    models = [
        'SM-A125F', 'SM-A225F', 'SM-A325M', 'SM-A515F', 'SM-A725F', 'SM-M215F', 'SM-M325FV',
        'Redmi 9A', 'Redmi 9C', 'POCO M3', 'POCO M4 Pro', 'RMX2185', 'RMX3085',
        'moto g(9) play', 'CPH2239', 'V2027', 'OnePlus Nord', 'ASUS_Z01QD',
    ]
    android_versions = ['9', '10', '11', '12', '13', '14']
    languages = ['en-US', 'es-MX', 'pt-BR', 'id-ID', 'ru-RU', 'hi-IN']
    countries = ['USA', 'MEX', 'BRA', 'IDN', 'RUS', 'IND']
    version = random.choice(versions)
    model = random.choice(models)
    android = random.choice(android_versions)
    lang = random.choice(languages)
    country = random.choice(countries)
    return f"GarenaMSDK/{version}({model};Android {android};{lang};{country};)"

def get_token(password, uid):
    try:
        # Try first URL
        url = "https://100067.connect.garena.com/oauth/guest/token/grant"
        headers = {
            "Host": "100067.connect.garena.com",
            "User-Agent": get_random_user_agent(),
            "Content-Type": "application/x-www-form-urlencoded",
            "Accept-Encoding": "gzip, deflate, br",
            "Connection": "close"
        }
        data = {
            "uid": uid,
            "password": password,
            "response_type": "token",
            "client_type": "2",
            "client_secret": CLIENT_SECRET,
            "client_id": CLIENT_ID
        }
        response = SESSION.post(url, headers=headers, data=data, verify=False)
        
        # If first fails, try second URL
        if response.status_code != 200:
            url = "https://100067.connect.garena.com/api/v2/oauth/guest/token:grant"
            response = SESSION.post(url, headers=headers, data=data, verify=False)
        
        # If second fails, try third URL
        if response.status_code != 200:
            url = "https://ffmconnect.live.gop.garenanow.com/oauth/guest/token/grant"
            response = SESSION.post(url, headers=headers, data=data, verify=False)
            
        # If third fails, try fourth URL
        if response.status_code != 200:
            url = "https://ffmsdk.live.gop.garenanow.com/oauth/guest/token/grant"
            response = SESSION.post(url, headers=headers, data=data, verify=False)
        
        if response.status_code != 200:
            return None
            
        token_json = response.json()
        if "access_token" in token_json and "open_id" in token_json:
            return token_json
        else:
            return None
    except Exception as e:
        logging.error(f"Error getting token for {uid}: {str(e)}")
        return None

def generate_jwt_token(password, uid):
    # Check in pickle cache first
    cache_key = f"{uid}_{hashlib.md5(password.encode()).hexdigest()[:8]}"
    if cache_key in pickle_cache:
        cached_data = pickle_cache[cache_key]
        # Check if cache is still valid (5 hours = 18000 seconds)
        if time.time() - cached_data.get('timestamp', 0) < 18000:
            logging.info(f"Returning cached token for {uid}")
            return cached_data.get('token_data')
    
    # Get access_token and open_id
    token_data = get_token(password, uid)  
    if not token_data:
        return None
    
    access_token = token_data.get("access_token")
    open_id = token_data.get("open_id")
    
    body = json.dumps({
        "open_id": open_id,
        "open_id_type": "4",
        "login_token": access_token,
        "orign_platform_type": "4"
    })
    
    # Convert to protobuf and encrypt
    proto_bytes = json_to_proto(body, FreeFire_pb2.LoginReq())
    payload = aes_cbc_encrypt(MAIN_KEY, MAIN_IV, proto_bytes)
    edata = payload.hex()
    
    # Send MajorLogin request
    url = "https://loginbp.common.ggbluefox.com/MajorLogin"
    headers = {
        "Accept-Encoding": "gzip",
        "Connection": "Keep-Alive",
        "Content-Length": str(len(edata)),
        "Content-Type": "application/x-www-form-urlencoded",
        "Expect": "100-continue",
        "Host": "loginbp.common.ggbluefox.com",
        "ReleaseVersion": "OB53",
        "User-Agent": "Dalvik/2.1.0 (Linux; U; Android 9; ASUS_I005DA Build/PI)",
        "X-GA": "v1 1",
        "X-Unity-Version": "2018.4.11f1"
    }
    response = requests.post(url, data=bytes.fromhex(edata), headers=headers, verify=False)
        
    # If first fails, try second URL
    if response.status_code != 200:
        url = "https://loginbp.ggblueshark.com/MajorLogin"
        headers = {
           "Accept-Encoding": "gzip", 
           "Connection": "Keep-Alive",
           "Content-Length": str(len(edata)),
           "Content-Type": "application/x-www-form-urlencoded",
           "Expect": "100-continue",
           "Host": "loginbp.ggblueshark.com",
           "ReleaseVersion": "OB53",
           "User-Agent": "Dalvik/2.1.0 (Linux; U; Android 9; ASUS_I005DA Build/PI)",
           "X-GA": "v1 1",
           "X-Unity-Version": "2018.4.11f1"
        }
        response = requests.post(url, data=bytes.fromhex(edata), headers=headers, verify=False)
        
    # If second fails, try third URL
    if response.status_code != 200:
        url = "https://loginbp.ggpolarbear.com/MajorLogin"
        headers = {
            "Content-Type": "application/x-www-form-urlencoded",
            "Host": "loginbp.ggpolarbear.com",
            "ReleaseVersion": "OB53",
            "User-Agent": "Free%20Fire%20MAX/2019117050 CFNetwork/3860.200.71 Darwin/25.1.0",
            "X-GA": "v1 1",
            "X-Unity-Version": "2022.3.47f1",
            "Accept": "*/*",
            "Accept-Encoding": "gzip, deflate, br",
            "Accept-Language": "vi-VN,vi;q=0.9",
            "Connection": "keep-alive",
            "Content-Length": str(len(edata))
        }
        response = requests.post(url, data=bytes.fromhex(edata), headers=headers, verify=False)
        
    # If third fails, try fourth URL
    if response.status_code != 200:
        url = "https://loginbp.ggwhitehawk.com/MajorLogin"
        headers = {
            "Expect": "100-continue",
            "Host": "loginbp.ggwhitehawk.com",
            "ReleaseVersion": "OB53",
            "X-GA": "v1 1",
            "X-Unity-Version": "2022.3.47f1"
        }
        response = requests.post(url, data=bytes.fromhex(edata), headers=headers, verify=False)
    
    if response.status_code != 200:
        return None
    
    # Send payload with httpx (Without Content-Length) 
    headers_for_httpx = {
        "Accept-Encoding": "gzip",
        "Connection": "Keep-Alive",
        "Content-Type": "application/x-www-form-urlencoded",
        "Expect": "100-continue",
        "Host": url.replace("https://", "").split("/")[0],
        "ReleaseVersion": "OB53",
        "User-Agent": "Dalvik/2.1.0 (Linux; U; Android 9; ASUS_I005DA Build/PI)",
        "X-GA": "v1 1",
        "X-Unity-Version": "2018.4.11f1"
    }
    
    with httpx.Client(verify=False) as client:
        # Directly send payload (With bytes format)
        resp = client.post(url, content=payload, headers=headers_for_httpx)
        msg = json.loads(json_format.MessageToJson(
            decode_protobuf(resp.content, FreeFire_pb2.LoginRes)
        ))
        
        # Prepare response
        response_data = {
            "agoraEnvironment": msg.get("agoraEnvironment", "invalid"),
            "lockRegion": msg.get("lockRegion", ""),
            "token": msg.get('token', '')
        }
        
        # Save to pickle cache
        pickle_cache[cache_key] = {
            'token_data': response_data,
            'timestamp': time.time()
        }
        save_cache(pickle_cache)
        
        return response_data

# === Flask Routes (Only /token) ===
@app.route('/token', methods=['GET'])
@cache.cached(timeout=25200, query_string=True)
def get_jwt_token():
    global cache_hits, cache_misses
    
    # Generate unique Request ID
    request_id = str(uuid.uuid4())[:8]
    
    uid = request.args.get('uid')
    password = request.args.get('password')
    
    if not uid or not password:
        logging.warning(f"[{request_id}] Missing parameters")
        return jsonify({"error": "Both uid and password parameters are required"}), 400
    
    # Validate UID (only digits)
    if not uid.isdigit():
        logging.warning(f"[{request_id}] Invalid UID format: {uid}")
        return jsonify({"error": "Invalid UID format. UID must contain only numbers."}), 400
    
    # Rate limiting per UID
    if is_uid_rate_limited(uid):
        logging.warning(f"[{request_id}] Rate limit exceeded for UID: {uid}")
        return jsonify({"error": "Rate limit exceeded. Maximum 10 requests per minute per UID."}), 429
    
    logging.info(f"[{request_id}] Processing request for UID: {uid}")
    
    # Create cache_key for checking cache status
    cache_key = f"{uid}_{hashlib.md5(password.encode()).hexdigest()[:8]}"
    
    # Update request status
    request_status[uid] = {
        'status': 'processing',
        'timestamp': time.time(),
        'request_id': request_id
    }
    
    try:
        # Using retry mechanism
        token_data = generate_with_retry(password, uid)
        
        if token_data:
            request_status[uid] = {
                'status': 'success',
                'timestamp': time.time(),
                'request_id': request_id
            }
            
            # Create response with caching headers
            response = make_response(jsonify(token_data))
            response.headers['Cache-Control'] = 'private, max-age=25200'
            response.headers['X-Cache'] = 'HIT' if cache_key in pickle_cache else 'MISS'
            response.headers['X-Generated-At'] = str(int(time.time()))
            response.headers['X-Request-ID'] = request_id
            
            logging.info(f"[{request_id}] Token generated successfully for UID: {uid}")
            return response, 200
        else:
            request_status[uid] = {
                'status': 'failed',
                'timestamp': time.time(),
                'request_id': request_id
            }
            logging.error(f"[{request_id}] Failed to generate token for UID: {uid}")
            return jsonify({"error": "Failed to generate token. Check your credentials."}), 500
    except Exception as e:
        request_status[uid] = {
            'status': 'error',
            'error': str(e),
            'timestamp': time.time(),
            'request_id': request_id
        }
        logging.error(f"[{request_id}] Exception for UID {uid}: {str(e)}")
        return jsonify({"error": f"Failed to generate token: {str(e)}"}), 500

# Auto cleanup of expired cache every hour
def scheduled_cache_cleanup():
    while True:
        time.sleep(3600)  # Sleep for 1 hour
        clean_expired_cache()

# Graceful Shutdown Handler
def shutdown_handler(signum, frame):
    print(Fore.YELLOW + "\n" + "="*50)
    print(Fore.YELLOW + "Shutdown signal received. Saving cache...")
    print(Fore.YELLOW + "="*50)
    
    # Save pickle cache
    save_cache(pickle_cache)
    print(Fore.GREEN + "✓ Pickle cache saved successfully")
    
    # Save rate limit data (optional)
    print(Fore.GREEN + f"✓ Active rate limits: {len(rate_limit_uid)} UIDs")
    
    # Close session
    SESSION.close()
    print(Fore.GREEN + "✓ Connection pool closed")
    
    print(Fore.CYAN + "="*50)
    print(Fore.GREEN + "Goodbye! Server stopped gracefully.")
    print(Fore.CYAN + "="*50)
    sys.exit(0)

# Register signal handlers for graceful shutdown
signal.signal(signal.SIGINT, shutdown_handler)   # Ctrl+C
signal.signal(signal.SIGTERM, shutdown_handler)  # Termination signal

# Start cleanup thread
cleanup_thread = threading.Thread(target=scheduled_cache_cleanup, daemon=True)
cleanup_thread.start()

if __name__ == '__main__':
    print(Fore.CYAN + "="*60)
    print(Fore.GREEN + Style.BRIGHT + "     FREEFIRE JWT TOKEN GENERATOR")
    print(Fore.CYAN + "="*60)
    print(Fore.YELLOW + f"📍 Server: http://0.0.0.0:8000")
    print(Fore.YELLOW + f"🔑 Endpoint: /token?uid=UID&password=PASS")
    print(Fore.CYAN + "-"*60)
    print(Fore.MAGENTA + "✨ Features Enabled:")
    print(Fore.MAGENTA + "   ✅ Request ID Tracking")
    print(Fore.MAGENTA + "   ✅ Graceful Shutdown (Cache saves on exit)")
    print(Fore.MAGENTA + "   ✅ Rate Limiting per UID (10 req/min)")
    print(Fore.MAGENTA + "   ✅ Retry Mechanism (3 attempts)")
    print(Fore.MAGENTA + "   ✅ Connection Pooling (50 max)")
    print(Fore.MAGENTA + "   ✅ Environment Variables")
    print(Fore.MAGENTA + "   ✅ Response Caching Headers")
    print(Fore.MAGENTA + "   ✅ Pickle Cache (5 hours TTL)")
    print(Fore.CYAN + "-"*60)
    print(Fore.MAGENTA + f"📊 Rate Limit: 10 requests per minute per UID")
    print(Fore.MAGENTA + f"💾 Cache File: {CACHE_FILE}")
    print(Fore.CYAN + "-"*60)
    print(Fore.RED + "⚠️  Press CTRL+C to stop gracefully")
    print(Fore.CYAN + "="*60)
    
    app.run(host='0.0.0.0', port=8000, debug=True)