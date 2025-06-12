from flask import Flask, render_template, request, jsonify
import base64
import hmac
import hashlib
import time
import struct

app = Flask(__name__)

def generate_totp(secret_key):
    try:
        secret_key = secret_key.replace(" ", "").upper()
        secret_bytes = base64.b32decode(secret_key)
    except Exception as e:
        return f"Error: โค้ด 2FA ไม่ถูกต้อง {str(e)}"

    counter = int(time.time() // 30)
    counter_bytes = struct.pack(">Q", counter)
    hmac_obj = hmac.new(secret_bytes, counter_bytes, hashlib.sha1)
    hmac_result = hmac_obj.digest()
    
    offset = hmac_result[-1] & 0xF
    code = struct.unpack(">I", hmac_result[offset:offset+4])[0]
    code = code & 0x7FFFFFFF
    code = code % 1000000
    
    return f"{code:06d}"

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/generate', methods=['POST'])
def generate():
    secret = request.json.get('secret', '')
    if secret:
        code = generate_totp(secret)
        time_left = 30 - (int(time.time()) % 30)
        return jsonify({
            'code': code,
            'time_left': time_left
        })
    return jsonify({'error': 'No secret provided'}), 400

if __name__ == '__main__':
    app.run(debug=True) 