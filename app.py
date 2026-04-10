from flask import Flask, request, jsonify
import sys
import jwt
import requests
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import RemoveFriend_Req_pb2
from byte import Encrypt_ID, encrypt_api
import binascii
import data_pb2
import uid_generator_pb2
import my_pb2
import output_pb2
from datetime import datetime
import json
import time
import urllib3
import warnings

# -----------------------------
# Security Warnings Disable
# -----------------------------
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
warnings.filterwarnings("ignore", category=UserWarning, message="Unverified HTTPS request")

app = Flask(__name__)

# -----------------------------
# AES Configuration
# -----------------------------
AES_KEY = bytes([89, 103, 38, 116, 99, 37, 68, 69, 117, 104, 54, 37, 90, 99, 94, 56])
AES_IV = bytes([54, 111, 121, 90, 68, 114, 50, 50, 69, 51, 121, 99, 104, 106, 77, 37])

def encrypt_message(data_bytes):
    cipher = AES.new(AES_KEY, AES.MODE_CBC, AES_IV)
    return cipher.encrypt(pad(data_bytes, AES.block_size))

def encrypt_message_hex(data_bytes):
    cipher = AES.new(AES_KEY, AES.MODE_CBC, AES_IV)
    encrypted = cipher.encrypt(pad(data_bytes, AES.block_size))
    return binascii.hexlify(encrypted).decode('utf-8')

# -----------------------------
# Region-based URL Configuration
# -----------------------------
def get_base_url(server_name):
    server_name = server_name.upper()
    if server_name == "IND":
        return "https://client.ind.freefiremobile.com/"
    elif server_name in {"BR", "US", "SAC", "NA"}:
        return "https://client.us.freefiremobile.com/"
    else:
        return "https://clientbp.ggblueshark.com/"

def get_server_from_token(token):
    """Extract server region from JWT token"""
    try:
        decoded = jwt.decode(token, options={"verify_signature": False})
        lock_region = decoded.get("lock_region", "IND")
        return lock_region.upper()
    except:
        return "IND"

# -----------------------------
# Retry Decorator
# -----------------------------
def retry_operation(max_retries=10, delay=1):
    def decorator(func):
        def wrapper(*args, **kwargs):
            last_exception = None
            for attempt in range(max_retries):
                try:
                    result = func(*args, **kwargs)
                    if result and result.get('status') in ['success', 'failed']:
                        return result
                    print(f"Attempt {attempt + 1}/{max_retries} failed, retrying...")
                except Exception as e:
                    last_exception = e
                    print(f"Attempt {attempt + 1}/{max_retries} failed with error: {str(e)}")
                
                if attempt < max_retries - 1:
                    time.sleep(delay)
            
            if last_exception:
                return {
                    "status": "error",
                    "message": f"All {max_retries} attempts failed",
                    "error": str(last_exception)
                }
            return {
                "status": "error", 
                "message": f"All {max_retries} attempts failed"
            }
        return wrapper
    return decorator

# -----------------------------
# TOKEN GENERATION METHODS
# -----------------------------

# Method 1: Guest Login (UID + Password) se JWT
def get_jwt_from_guest(uid, password):
    """Guest login: UID + Password -> JWT Token"""
    try:
        oauth_url = "https://100067.connect.garena.com/oauth/guest/token/grant"
        payload = {
            'uid': uid,
            'password': password,
            'response_type': "token",
            'client_type': "2",
            'client_secret': "2ee44819e9b4598845141067b281621874d0d5d7af9d8f7e00c1e54715b7d1e3",
            'client_id': "100067"
        }
        
        headers = {
            'User-Agent': "GarenaMSDK/4.0.19P9(SM-M526B ;Android 13;pt;BR;)",
            'Connection': "Keep-Alive",
            'Accept-Encoding': "gzip"
        }

        oauth_response = requests.post(oauth_url, data=payload, headers=headers, timeout=10, verify=False)
        oauth_response.raise_for_status()
        
        oauth_data = oauth_response.json()
        
        if 'access_token' not in oauth_data:
            return None, "OAuth response missing access_token"

        access_token = oauth_data['access_token']
        open_id = oauth_data.get('open_id', '')
        
        # Try platforms
        platforms = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12]
        
        for platform_type in platforms:
            result = platform_login(open_id, access_token, platform_type)
            if result and 'token' in result:
                return result['token'], None
        
        return None, "JWT generation failed on all platforms"

    except Exception as e:
        return None, str(e)

# Method 2: Access Token se JWT
def get_jwt_from_access_token(access_token):
    """Access Token -> JWT Token using external API"""
    try:
        api_url = f"http://217.160.125.125:14965/token?access_token={access_token}"
        
        response = requests.get(api_url, timeout=10, verify=False)
        response.raise_for_status()
        
        data = response.json()
        
        if data and 'token' in data:
            return data['token'], None
        else:
            return None, "JWT not found in response"
            
    except Exception as e:
        return None, str(e)

# Method 3: External API se JWT (UID + Password)
def get_jwt_from_external_api(uid, password):
    """External API: UID + Password -> JWT Token"""
    try:
        external_url = f"https://star-jwt-gen.vercel.app/token?uid={uid}&password={password}"
        
        response = requests.get(external_url, timeout=10, verify=False)
        response.raise_for_status()
        
        data = response.json()
        
        if data and 'token' in data:
            return data['token'], None
        else:
            return None, "Token not found in response"
            
    except Exception as e:
        return None, str(e)

def platform_login(open_id, access_token, platform_type):
    """Platform login to get JWT"""
    try:
        game_data = my_pb2.GameData()
        game_data.timestamp = "2024-12-05 18:15:32"
        game_data.game_name = "free fire"
        game_data.game_version = 1
        game_data.version_code = "1.108.3"
        game_data.os_info = "Android OS 9 / API-28 (PI/rel.cjw.20220518.114133)"
        game_data.device_type = "Handheld"
        game_data.network_provider = "Verizon Wireless"
        game_data.connection_type = "WIFI"
        game_data.screen_width = 1280
        game_data.screen_height = 960
        game_data.dpi = "240"
        game_data.cpu_info = "ARMv7 VFPv3 NEON VMH | 2400 | 4"
        game_data.total_ram = 5951
        game_data.gpu_name = "Adreno (TM) 640"
        game_data.gpu_version = "OpenGL ES 3.0"
        game_data.user_id = "Google|74b585a9-0268-4ad3-8f36-ef41d2e53610"
        game_data.ip_address = "172.190.111.97"
        game_data.language = "en"
        game_data.open_id = open_id
        game_data.access_token = access_token
        game_data.platform_type = platform_type
        game_data.field_99 = str(platform_type)
        game_data.field_100 = str(platform_type)

        serialized_data = game_data.SerializeToString()
        encrypted_data = encrypt_message(serialized_data)
        hex_encrypted_data = binascii.hexlify(encrypted_data).decode('utf-8')

        url = "https://loginbp.ggblueshark.com/MajorLogin"
        headers = {
            "User-Agent": "Dalvik/2.1.0 (Linux; U; Android 9; ASUS_Z01QD Build/PI)",
            "Connection": "Keep-Alive",
            "Accept-Encoding": "gzip",
            "Content-Type": "application/octet-stream",
            "Expect": "100-continue",
            "X-Unity-Version": "2018.4.11f1",
            "X-GA": "v1 1",
            "ReleaseVersion": "OB53"
        }
        
        edata = bytes.fromhex(hex_encrypted_data)

        response = requests.post(url, data=edata, headers=headers, timeout=10, verify=False)
        response.raise_for_status()

        if response.status_code == 200:
            data_dict = None
            try:
                example_msg = output_pb2.Garena_420()
                example_msg.ParseFromString(response.content)
                data_dict = {field.name: getattr(example_msg, field.name)
                             for field in example_msg.DESCRIPTOR.fields
                             if field.name not in ["binary", "binary_data", "Garena420"]}
            except:
                try:
                    data_dict = response.json()
                except:
                    return None

            if data_dict and "token" in data_dict:
                return {"token": data_dict["token"]}
        
        return None

    except Exception:
        return None

# -----------------------------
# Player Info Functions
# -----------------------------
def create_info_protobuf(uid):
    message = uid_generator_pb2.uid_generator()
    message.saturn_ = int(uid)
    message.garena = 1
    return message.SerializeToString()

def get_player_info(target_uid, token, server_name=None):
    """Get detailed player information"""
    try:
        if not server_name:
            server_name = get_server_from_token(token)
            
        protobuf_data = create_info_protobuf(target_uid)
        encrypted_data = encrypt_message_hex(protobuf_data)
        endpoint = get_base_url(server_name) + "GetPlayerPersonalShow"

        headers = {
            'User-Agent': "Dalvik/2.1.0 (Linux; U; Android 9; ASUS_Z01QD Build/PI)",
            'Connection': "Keep-Alive",
            'Accept-Encoding': "gzip",
            'Authorization': f"Bearer {token}",
            'Content-Type': "application/x-www-form-urlencoded",
            'Expect': "100-continue",
            'X-Unity-Version': "2018.4.11f1",
            'X-GA': "v1 1",
            'ReleaseVersion': "OB53"
        }

        response = requests.post(endpoint, data=bytes.fromhex(encrypted_data), headers=headers, verify=False)
        
        if response.status_code != 200:
            return None

        hex_response = response.content.hex()
        binary = bytes.fromhex(hex_response)
        
        info = data_pb2.AccountPersonalShowInfo()
        info.ParseFromString(binary)
        
        return info
    except Exception as e:
        print(f"Error getting player info: {e}")
        return None

def extract_player_info(info_data):
    """Extract player information from protobuf response"""
    if not info_data:
        return None

    basic_info = info_data.basic_info
    return {
        'uid': basic_info.account_id,
        'nickname': basic_info.nickname,
        'level': basic_info.level,
        'region': basic_info.region,
        'likes': basic_info.liked,
        'release_version': basic_info.release_version
    }

def decode_author_uid(token):
    try:
        decoded = jwt.decode(token, options={"verify_signature": False})
        return decoded.get("account_id") or decoded.get("sub")
    except:
        return None

# -----------------------------
# Friend Operations
# -----------------------------
@retry_operation(max_retries=10, delay=1)
def remove_friend_operation(author_uid, target_uid, token, server_name=None):
    """Remove friend operation"""
    try:
        if not server_name:
            server_name = get_server_from_token(token)
            
        player_info = get_player_info(target_uid, token, server_name)
        
        msg = RemoveFriend_Req_pb2.RemoveFriend()
        msg.AuthorUid = int(author_uid)
        msg.TargetUid = int(target_uid)
        encrypted_bytes = encrypt_message(msg.SerializeToString())

        url = get_base_url(server_name) + "RemoveFriend"
        headers = {
            'Authorization': f"Bearer {token}",
            'User-Agent': "Dalvik/2.1.0 (Linux; Android 9)",
            'Content-Type': "application/x-www-form-urlencoded",
            'X-Unity-Version': "2018.4.11f1",
            'X-GA': "v1 1",
            'ReleaseVersion': "OB53"
        }

        res = requests.post(url, data=encrypted_bytes, headers=headers, verify=False)
        
        player_data = None
        if player_info:
            player_data = extract_player_info(player_info)
        
        if res.status_code == 200:
            status = "success"
        else:
            status = "failed"
            raise Exception(f"HTTP {res.status_code}")
        
        return {
            "author_uid": author_uid,
            "nickname": player_data.get('nickname') if player_data else "Unknown",
            "uid": target_uid,
            "level": player_data.get('level') if player_data else 0,
            "likes": player_data.get('likes') if player_data else 0,
            "region": player_data.get('region') if player_data else "Unknown",
            "release_version": player_data.get('release_version') if player_data else "Unknown",
            "status": status,
            "time": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        }

    except Exception as e:
        print(f"Remove friend error: {e}")
        raise e

@retry_operation(max_retries=10, delay=1)
def add_friend_operation(author_uid, target_uid, token, server_name=None):
    """Add friend operation"""
    try:
        if not server_name:
            server_name = get_server_from_token(token)
            
        player_info = get_player_info(target_uid, token, server_name)
        
        encrypted_id = Encrypt_ID(target_uid)
        payload = f"08a7c4839f1e10{encrypted_id}1801"
        encrypted_payload = encrypt_api(payload)

        url = get_base_url(server_name) + "RequestAddingFriend"
        headers = {
            "Authorization": f"Bearer {token}",
            "X-Unity-Version": "2018.4.11f1",
            "X-GA": "v1 1",
            "ReleaseVersion": "OB53",
            "Content-Type": "application/x-www-form-urlencoded",
            "User-Agent": "Dalvik/2.1.0 (Linux; Android 9)"
        }

        r = requests.post(url, headers=headers, data=bytes.fromhex(encrypted_payload), verify=False)
        
        player_data = None
        if player_info:
            player_data = extract_player_info(player_info)
        
        if r.status_code == 200:
            status = "success"
        else:
            status = "failed"
            raise Exception(f"HTTP {r.status_code}")
        
        return {
            "author_uid": author_uid,
            "nickname": player_data.get('nickname') if player_data else "Unknown",
            "uid": target_uid,
            "level": player_data.get('level') if player_data else 0,
            "likes": player_data.get('likes') if player_data else 0,
            "region": player_data.get('region') if player_data else "Unknown",
            "release_version": player_data.get('release_version') if player_data else "Unknown",
            "status": status,
            "time": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        }
        
    except Exception as e:
        print(f"Add friend error: {e}")
        raise e

# ============================================
# API ENDPOINTS - 3 DIFFERENT AUTH METHODS
# ============================================

# -----------------------------
# METHOD 1: GUEST LOGIN (UID + PASSWORD)
# -----------------------------

@app.route('/guest/add_friend', methods=['GET'])
def guest_add_friend():
    """Guest login se friend add - UID + Password"""
    uid = request.args.get('uid')
    password = request.args.get('password')
    friend_uid = request.args.get('friend_uid')
    server_name = request.args.get('server_name', 'IND')

    if not uid or not password or not friend_uid:
        return jsonify({"status": "failed", "message": "Missing uid, password, or friend_uid"}), 400

    # Guest login se JWT generate
    token, error = get_jwt_from_guest(uid, password)
    if error:
        return jsonify({"status": "failed", "message": f"Guest login failed: {error}"}), 400
    
    author_uid = decode_author_uid(token)
    if not author_uid:
        return jsonify({"status": "failed", "message": "Failed to decode token"}), 400
        
    result = add_friend_operation(author_uid, friend_uid, token, server_name)
    result['auth_method'] = 'guest_login'
    return jsonify(result)

@app.route('/guest/remove_friend', methods=['GET'])
def guest_remove_friend():
    """Guest login se friend remove - UID + Password"""
    uid = request.args.get('uid')
    password = request.args.get('password')
    friend_uid = request.args.get('friend_uid')
    server_name = request.args.get('server_name', 'IND')

    if not uid or not password or not friend_uid:
        return jsonify({"status": "failed", "message": "Missing uid, password, or friend_uid"}), 400

    token, error = get_jwt_from_guest(uid, password)
    if error:
        return jsonify({"status": "failed", "message": f"Guest login failed: {error}"}), 400
    
    author_uid = decode_author_uid(token)
    if not author_uid:
        return jsonify({"status": "failed", "message": "Failed to decode token"}), 400
        
    result = remove_friend_operation(author_uid, friend_uid, token, server_name)
    result['auth_method'] = 'guest_login'
    return jsonify(result)

@app.route('/guest/player_info', methods=['GET'])
def guest_player_info():
    """Guest login se player info - UID + Password"""
    uid = request.args.get('uid')
    password = request.args.get('password')
    friend_uid = request.args.get('friend_uid')
    server_name = request.args.get('server_name', 'IND')

    if not uid or not password or not friend_uid:
        return jsonify({"status": "failed", "message": "Missing uid, password, or friend_uid"}), 400

    token, error = get_jwt_from_guest(uid, password)
    if error:
        return jsonify({"status": "failed", "message": f"Guest login failed: {error}"}), 400

    player_info = get_player_info(friend_uid, token, server_name)
    if not player_info:
        return jsonify({"status": "failed", "message": "Info not found"}), 400

    player_data = extract_player_info(player_info)
    player_data.update({
        "status": "success", 
        "time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "auth_method": "guest_login"
    })
    return jsonify(player_data)

# -----------------------------
# METHOD 2: ACCESS TOKEN SE DIRECT
# -----------------------------

@app.route('/access/add_friend', methods=['GET'])
def access_add_friend():
    """Access Token se friend add"""
    access_token = request.args.get('access_token')
    friend_uid = request.args.get('friend_uid')
    server_name = request.args.get('server_name', 'IND')

    if not access_token or not friend_uid:
        return jsonify({"status": "failed", "message": "Missing access_token or friend_uid"}), 400

    # Access token se JWT generate
    jwt_token, error = get_jwt_from_access_token(access_token)
    if error:
        return jsonify({"status": "failed", "message": f"Access token conversion failed: {error}"}), 400
    
    author_uid = decode_author_uid(jwt_token)
    if not author_uid:
        return jsonify({"status": "failed", "message": "Failed to decode token"}), 400
        
    result = add_friend_operation(author_uid, friend_uid, jwt_token, server_name)
    result['auth_method'] = 'access_token'
    return jsonify(result)

@app.route('/access/remove_friend', methods=['GET'])
def access_remove_friend():
    """Access Token se friend remove"""
    access_token = request.args.get('access_token')
    friend_uid = request.args.get('friend_uid')
    server_name = request.args.get('server_name', 'IND')

    if not access_token or not friend_uid:
        return jsonify({"status": "failed", "message": "Missing access_token or friend_uid"}), 400

    jwt_token, error = get_jwt_from_access_token(access_token)
    if error:
        return jsonify({"status": "failed", "message": f"Access token conversion failed: {error}"}), 400
    
    author_uid = decode_author_uid(jwt_token)
    if not author_uid:
        return jsonify({"status": "failed", "message": "Failed to decode token"}), 400
        
    result = remove_friend_operation(author_uid, friend_uid, jwt_token, server_name)
    result['auth_method'] = 'access_token'
    return jsonify(result)

@app.route('/access/player_info', methods=['GET'])
def access_player_info():
    """Access Token se player info"""
    access_token = request.args.get('access_token')
    friend_uid = request.args.get('friend_uid')
    server_name = request.args.get('server_name', 'IND')

    if not access_token or not friend_uid:
        return jsonify({"status": "failed", "message": "Missing access_token or friend_uid"}), 400

    jwt_token, error = get_jwt_from_access_token(access_token)
    if error:
        return jsonify({"status": "failed", "message": f"Access token conversion failed: {error}"}), 400

    player_info = get_player_info(friend_uid, jwt_token, server_name)
    if not player_info:
        return jsonify({"status": "failed", "message": "Info not found"}), 400

    player_data = extract_player_info(player_info)
    player_data.update({
        "status": "success", 
        "time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "auth_method": "access_token"
    })
    return jsonify(player_data)

# -----------------------------
# METHOD 3: DIRECT JWT TOKEN USE
# -----------------------------

@app.route('/jwt/add_friend', methods=['GET', 'POST'])
def jwt_add_friend():
    """Direct JWT Token se friend add"""
    if request.method == 'GET':
        jwt_token = request.args.get('jwt_token')
        friend_uid = request.args.get('friend_uid')
        server_name = request.args.get('server_name', 'IND')
    else:
        data = request.get_json()
        jwt_token = data.get('jwt_token')
        friend_uid = data.get('friend_uid')
        server_name = data.get('server_name', 'IND')

    if not jwt_token or not friend_uid:
        return jsonify({"status": "failed", "message": "Missing jwt_token or friend_uid"}), 400
    
    author_uid = decode_author_uid(jwt_token)
    if not author_uid:
        return jsonify({"status": "failed", "message": "Invalid JWT token"}), 400
        
    result = add_friend_operation(author_uid, friend_uid, jwt_token, server_name)
    result['auth_method'] = 'jwt_token'
    return jsonify(result)

@app.route('/jwt/remove_friend', methods=['GET', 'POST'])
def jwt_remove_friend():
    """Direct JWT Token se friend remove"""
    if request.method == 'GET':
        jwt_token = request.args.get('jwt_token')
        friend_uid = request.args.get('friend_uid')
        server_name = request.args.get('server_name', 'IND')
    else:
        data = request.get_json()
        jwt_token = data.get('jwt_token')
        friend_uid = data.get('friend_uid')
        server_name = data.get('server_name', 'IND')

    if not jwt_token or not friend_uid:
        return jsonify({"status": "failed", "message": "Missing jwt_token or friend_uid"}), 400
    
    author_uid = decode_author_uid(jwt_token)
    if not author_uid:
        return jsonify({"status": "failed", "message": "Invalid JWT token"}), 400
        
    result = remove_friend_operation(author_uid, friend_uid, jwt_token, server_name)
    result['auth_method'] = 'jwt_token'
    return jsonify(result)

@app.route('/jwt/player_info', methods=['GET', 'POST'])
def jwt_player_info():
    """Direct JWT Token se player info"""
    if request.method == 'GET':
        jwt_token = request.args.get('jwt_token')
        friend_uid = request.args.get('friend_uid')
        server_name = request.args.get('server_name', 'IND')
    else:
        data = request.get_json()
        jwt_token = data.get('jwt_token')
        friend_uid = data.get('friend_uid')
        server_name = data.get('server_name', 'IND')

    if not jwt_token or not friend_uid:
        return jsonify({"status": "failed", "message": "Missing jwt_token or friend_uid"}), 400

    player_info = get_player_info(friend_uid, jwt_token, server_name)
    if not player_info:
        return jsonify({"status": "failed", "message": "Info not found"}), 400

    player_data = extract_player_info(player_info)
    player_data.update({
        "status": "success", 
        "time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "auth_method": "jwt_token"
    })
    return jsonify(player_data)

# -----------------------------
# TOKEN GENERATION ENDPOINTS
# -----------------------------

@app.route('/generate/guest', methods=['GET'])
def generate_guest_token():
    """Generate JWT from Guest Login (UID + Password)"""
    uid = request.args.get('uid')
    password = request.args.get('password')
    
    if not uid or not password:
        return jsonify({"status": "failed", "message": "Missing uid or password"}), 400
    
    token, error = get_jwt_from_guest(uid, password)
    if error:
        return jsonify({"status": "failed", "message": error}), 400
    
    author_uid = decode_author_uid(token)
    return jsonify({
        "status": "success",
        "token": token,
        "author_uid": author_uid,
        "method": "guest_login"
    })

@app.route('/generate/access', methods=['GET'])
def generate_access_token_jwt():
    """Generate JWT from Access Token"""
    access_token = request.args.get('access_token')
    
    if not access_token:
        return jsonify({"status": "failed", "message": "Missing access_token"}), 400
    
    token, error = get_jwt_from_access_token(access_token)
    if error:
        return jsonify({"status": "failed", "message": error}), 400
    
    author_uid = decode_author_uid(token)
    return jsonify({
        "status": "success",
        "token": token,
        "author_uid": author_uid,
        "method": "access_token_conversion"
    })

@app.route('/generate/external', methods=['GET'])
def generate_external_token():
    """Generate JWT from External API (UID + Password)"""
    uid = request.args.get('uid')
    password = request.args.get('password')
    
    if not uid or not password:
        return jsonify({"status": "failed", "message": "Missing uid or password"}), 400
    
    token, error = get_jwt_from_external_api(uid, password)
    if error:
        return jsonify({"status": "failed", "message": error}), 400
    
    author_uid = decode_author_uid(token)
    return jsonify({
        "status": "success",
        "token": token,
        "author_uid": author_uid,
        "method": "external_api"
    })

# -----------------------------
# HEALTH CHECK
# -----------------------------

@app.route('/health', methods=['GET'])
def health_check():
    return jsonify({
        "status": "healthy", 
        "service": "FreeFire-API",
        "auth_methods": {
            "guest_login": {
                "endpoints": [
                    "/guest/add_friend?uid=xxx&password=xxx&friend_uid=xxx",
                    "/guest/remove_friend?uid=xxx&password=xxx&friend_uid=xxx",
                    "/guest/player_info?uid=xxx&password=xxx&friend_uid=xxx"
                ]
            },
            "access_token": {
                "endpoints": [
                    "/access/add_friend?access_token=xxx&friend_uid=xxx",
                    "/access/remove_friend?access_token=xxx&friend_uid=xxx",
                    "/access/player_info?access_token=xxx&friend_uid=xxx"
                ]
            },
            "jwt_token": {
                "endpoints": [
                    "/jwt/add_friend?jwt_token=xxx&friend_uid=xxx",
                    "/jwt/remove_friend?jwt_token=xxx&friend_uid=xxx",
                    "/jwt/player_info?jwt_token=xxx&friend_uid=xxx"
                ]
            },
            "token_generation": {
                "endpoints": [
                    "/generate/guest?uid=xxx&password=xxx",
                    "/generate/access?access_token=xxx",
                    "/generate/external?uid=xxx&password=xxx"
                ]
            }
        }
    }), 200

# -----------------------------
# Run Server
# ----------------------------

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
    
# MADEBYSTAR