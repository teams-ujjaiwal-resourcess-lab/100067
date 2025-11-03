from flask import Flask, jsonify, request
from flask_caching import Cache
import requests
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import binascii
import MajorLoginReq_pb2
import MajorLoginRes_pb2
import jwt_generator_pb2
import login_pb2
import json
import time
import warnings
from colorama import init
from urllib3.exceptions import InsecureRequestWarning

# Disable SSL warnings
warnings.filterwarnings("ignore", category=InsecureRequestWarning)

# Constants
AES_KEY = b'Yg&tc%DEuh6%Zc^8'
AES_IV = b'6oyZDr22E3ychjM%'

# Init colorama
init(autoreset=True)

# Flask setup
app = Flask(__name__)
cache = Cache(app, config={'CACHE_TYPE': 'SimpleCache', 'CACHE_DEFAULT_TIMEOUT': 25200})


def get_token(password, uid):
    try:
        url = "https://100067.connect.garena.com/oauth/guest/token/grant"
        headers = {
            "Host": "100067.connect.garena.com",
            "User-Agent": "GarenaMSDK/4.0.19P4(G011A ;Android 9;en;US;)",
            "Content-Type": "application/x-www-form-urlencoded",
            "Accept-Encoding": "gzip, deflate, br",
            "Connection": "close"
        }
        data = {
            "uid": uid,
            "password": password,
            "response_type": "token",
            "client_type": "2",
            "client_secret": "2ee44819e9b4598845141067b281621874d0d5d7af9d8f7e00c1e54715b7d1e3",
            "client_id": "100067"
        }
        res = requests.post(url, headers=headers, data=data, timeout=10)
        if res.status_code != 200:
            return None
        token_json = res.json()
        if "access_token" in token_json and "open_id" in token_json:
            return token_json
        return None
    except Exception:
        return None


def encrypt_message(key, iv, plaintext):
    cipher = AES.new(key, AES.MODE_CBC, iv)
    padded = pad(plaintext, AES.block_size)
    return cipher.encrypt(padded)


def parse_response(content):
    response_dict = {}
    lines = content.split("\n")
    for line in lines:
        if ":" in line:
            key, value = line.split(":", 1)
            response_dict[key.strip()] = value.strip().strip('"')
    return response_dict


@app.route('/token', methods=['GET'])
@cache.cached(timeout=25200, query_string=True)
def get_single_response():
    uid = request.args.get('uid')
    password = request.args.get('password')

    if not uid or not password:
        return jsonify({"error": "Both uid and password parameters are required"}), 400

    token_data = get_token(password, uid)
    if not token_data:
        return jsonify({
            "uid": uid,
            "status": "invalid",
            "message": "Wrong UID or Password. Please check and try again."
        }), 400

    # Prepare MajorLogin object: 
    major_login = MajorLoginReq_pb2.MajorLogin()
    major_login.event_time = "2025-06-04 19:48:07"
    major_login.game_name = "free fire"
    major_login.platform_id = 1
    major_login.client_version = "2.112.2"
    major_login.system_software = "Android OS 9 / API-28 (PQ3B.190801.10101846/G9650ZHU2ARC6)"
    major_login.system_hardware = "Handheld"
    major_login.telecom_operator = "Verizon"
    major_login.network_type = "WIFI"
    major_login.screen_width = 1920
    major_login.screen_height = 1080
    major_login.screen_dpi = "280"
    major_login.processor_details = "ARM64 FP ASIMD AES VMH | 2865 | 4"
    major_login.memory = 3003
    major_login.gpu_renderer = "Adreno (TM) 640"
    major_login.gpu_version = "OpenGL ES 3.1 v1.46"
    major_login.unique_device_id = "Google|34a7dcdf-a7d5-4cb6-8d7e-3b0e448a0c57"
    major_login.client_ip = "223.191.51.89"
    major_login.language = "en"
    major_login.open_id = token_data['open_id']
    major_login.open_id_type = "4"
    major_login.device_type = "Handheld"
    memory_available = major_login.memory_available
    memory_available.version = 55
    memory_available.hidden_value = 81
    major_login.access_token = token_data['access_token']
    major_login.platform_sdk_id = 1
    major_login.network_operator_a = "Verizon"
    major_login.network_type_a = "WIFI"
    major_login.client_using_version = "7428b253defc164018c604a1ebbfebdf"
    major_login.external_storage_total = 36235
    major_login.external_storage_available = 31335
    major_login.internal_storage_total = 2519
    major_login.internal_storage_available = 703
    major_login.game_disk_storage_available = 25010
    major_login.game_disk_storage_total = 26628
    major_login.external_sdcard_avail_storage = 32992
    major_login.external_sdcard_total_storage = 36235
    major_login.login_by = 3
    major_login.library_path = "/data/app/com.dts.freefireth-YPKM8jHEwAJlhpmhDhv5MQ==/lib/arm64"
    major_login.reg_avatar = 1
    major_login.library_token = "5b892aaabd688e571f688053118a162b|/data/app/com.dts.freefireth-YPKM8jHEwAJlhpmhDhv5MQ==/base.apk"
    major_login.channel_type = 3
    major_login.cpu_type = 2
    major_login.cpu_architecture = "64"
    major_login.client_version_code = "2019117863"
    major_login.graphics_api = "OpenGLES2"
    major_login.supported_astc_bitset = 16383
    major_login.login_open_id_type = 4
    major_login.analytics_detail = b"FwQVTgUPX1UaUllDDwcWCRBpWAUOUgsvA1snWlBaO1kFYg=="
    major_login.loading_time = 13564
    major_login.release_channel = "android"
    major_login.extra_info = "KqsHTymw5/5GB23YGniUYN2/q47GATrq7eFeRatf0NkwLKEMQ0PK5BKEk72dPflAxUlEBir6Vtey83XqF593qsl8hwY="
    major_login.android_engine_init_flag = 110009
    major_login.if_push = 1
    major_login.is_vpn = 1
    major_login.origin_platform_type = "4"
    major_login.primary_platform_type = "4"

    try:
        # Encrypt and send MajorLogin
        serialized = major_login.SerializeToString()
        encrypted = encrypt_message(AES_KEY, AES_IV, serialized)
        edata = binascii.hexlify(encrypted).decode()

        headers = {
            'User-Agent': "Dalvik/2.1.0 (Linux; Android 9)",
            'Connection': "Keep-Alive",
            'Accept-Encoding': "gzip",
            'Content-Type': "application/octet-stream",
            'Expect': "100-continue",
            'X-Unity-Version': "2018.4.11f1",
            'X-GA': "v1 1",
            'ReleaseVersion': "OB51"
        }

        response = requests.post(
            "https://loginbp.common.ggbluefox.com/MajorLogin",
            data=bytes.fromhex(edata),
            headers=headers,
            verify=False
        )

        if response.status_code == 200:
            # Parse MajorLoginRes
            login_res = MajorLoginRes_pb2.MajorLoginRes()
            login_res.ParseFromString(response.content)

            # Debug: Print all available fields from MajorLoginRes
            print("Available fields in MajorLoginRes:")
            for field in login_res.DESCRIPTOR.fields:
                field_name = field.name
                field_value = getattr(login_res, field_name, None)
                print(f"  {field_name}: {field_value}")

            # Parse jwt response
            jwt_msg = jwt_generator_pb2.Garena_420()
            jwt_msg.ParseFromString(response.content)
            jwt_dict = parse_response(str(jwt_msg))
            token = jwt_dict.get("token", "")

            # FIXED: Try different possible field names for URL
            base_url = None
            
            # Try different possible field names
            possible_url_fields = ['url', 'server_url', 'base_url', 'game_url', 'login_url']
            
            for field_name in possible_url_fields:
                if hasattr(login_res, field_name):
                    url_value = getattr(login_res, field_name)
                    if url_value and url_value.strip():
                        base_url = url_value
                        print(f"Found URL in field '{field_name}': {base_url}")
                        break
            
            # If no URL found, use a default one
            if not base_url:
                print("No URL field found in response, using default URL")
                base_url = "https://loginbp.common.ggbluefox.com"

            # Prepare LoginReq for GetLoginData
            login_req = login_pb2.LoginReq()
            login_req.account_id = login_res.account_id
            serialized_login = login_req.SerializeToString()
            encrypted_login = encrypt_message(AES_KEY, AES_IV, serialized_login)
            login_hex = binascii.hexlify(encrypted_login).decode()

            get_headers = headers.copy()
            get_headers["Authorization"] = f"Bearer {token}"

            # Use the determined URL
            get_login_url = f"{base_url}/GetLoginData"
            print(f"Using GetLoginData URL: {get_login_url}")
            
            get_resp = requests.post(
                get_login_url,
                data=bytes.fromhex(login_hex),
                headers=get_headers,
                verify=False
            )

            if get_resp.status_code == 200:
                try:
                    # Decrypt the GetLoginData response
                    cipher = AES.new(AES_KEY, AES.MODE_CBC, AES_IV)
                    decrypted_data = cipher.decrypt(get_resp.content)
                    
                    # Remove padding
                    padding_length = decrypted_data[-1]
                    if padding_length <= AES.block_size:
                        decrypted_data = decrypted_data[:-padding_length]
                    
                    # Parse the decrypted data
                    login_info = login_pb2.LoginReq()
                    login_info.ParseFromString(decrypted_data)
                    
                    nickname = login_info.nickname
                    region = login_info.region
                    level = login_info.level
                    exp = login_info.exp
                    create_at = login_info.create_at
                    
                    print(f"Successfully parsed user data: {nickname}, {region}, Level {level}")
                    
                except Exception as e:
                    print("Parsing error:", e)
                    # If decryption fails, try parsing directly
                    try:
                        login_info = login_pb2.LoginReq()
                        login_info.ParseFromString(get_resp.content)
                        nickname = login_info.nickname
                        region = login_info.region
                        level = login_info.level
                        exp = login_info.exp
                        create_at = login_info.create_at
                        print(f"Direct parsing successful: {nickname}, {region}, Level {level}")
                    except Exception as e2:
                        print("Direct parsing also failed:", e2)
            else:
                print(f"GetLoginData failed with status: {get_resp.status_code}")

            # Final response
            response_data = {
                "accountId": login_res.account_id if login_res.account_id else "",
                "accountNickname": nickname, 
                "accountRegion": region, 
                "accountLevel": level, 
                "accountLevelExp": exp, 
                "accountCreateAt": create_at, 
                "lockRegion": login_res.lock_region if login_res.lock_region else "",
                "notiRegion": login_res.noti_region if login_res.noti_region else "",
                "ipRegion": login_res.ip_region if login_res.ip_region else "",
                "agoraEnvironment": login_res.agora_environment if login_res.agora_environment else "",
                "tokenStatus": jwt_dict.get("status", "invalid"),
                "token": jwt_dict.get("token", ""), 
                "ttl": login_res.ttl if login_res.ttl else 0,
                "serverUrl": login_res.server_url if login_res.server_url else "",
                "expireAt": int(time.time()) + (login_res.ttl if login_res.ttl else 0)
            }

            # Add optional fields if they exist
            optional_fields = ['lockRegion', 'notiRegion', 'ipRegion', 'agoraEnvironment', 'ttl', 'serverUrl']
            for field in optional_fields:
                if hasattr(login_res, field):
                    value = getattr(login_res, field)
                    if value is not None:
                        response_data[field] = value

            return jsonify(response_data)

        else:
            return jsonify({"error": f"Failed MajorLogin: {response.status_code}"}), 400

    except Exception as e:
        return jsonify({"error": str(e)}), 500


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)