from flask import Flask, render_template, request, jsonify, flash, redirect, url_for
import os
import requests
import json
import base64

try:
    from crypto_utils import CryptoManager
    print("✅ CryptoManager imported successfully")
except Exception as e:
    print(f"❌ Error importing CryptoManager: {e}")
    CryptoManager = None

try:
    from socket_client import SecureMessageClient
    print("✅ SecureMessageClient imported successfully")
except Exception as e:
    print(f"❌ Error importing SecureMessageClient: {e}")
    SecureMessageClient = None

app = Flask(__name__)
app.secret_key = 'secure_message_client_secret_key_2024'

SERVER_URL = 'http://localhost:5001'
crypto_manager = CryptoManager() if CryptoManager else None

@app.route('/')
def index():
    return render_template('client_index.html')

@app.route('/send')
def send():
    return render_template('client_send.html')

@app.route('/receive')
def receive():
    return render_template('client_receive.html')

@app.route('/security')
def security():
    return render_template('client_security.html')

@app.route('/api/server-status')
def server_status():
    try:
        response = requests.get(f'{SERVER_URL}/api/server-status', timeout=5)
        return jsonify(response.json())
    except requests.exceptions.RequestException:
        return jsonify({'running': False, 'error': 'Không thể kết nối đến server'})

@app.route('/api/send-message', methods=['POST'])
def api_send_message():
    try:
        server_status_response = requests.get(f'{SERVER_URL}/api/server-status', timeout=5)
        if not server_status_response.json().get('running', False):
            return jsonify({'success': False, 'message': 'Server chưa được khởi động.'})
        
        data = request.get_json()
        message = data.get('message', '').strip()
        recipient_id = data.get('recipient_id', 'Server')
        
        if not message:
            return jsonify({'success': False, 'message': 'Tin nhắn không được để trống'})
        
        if not SecureMessageClient:
            return jsonify({'success': False, 'message': 'SecureMessageClient không khả dụng'})
        
        client = SecureMessageClient()
        if client.connect():
            result = client.send_message(message, recipient_id)
            client.disconnect()
            
            if result['status'] == 'ACK':
                return jsonify({
                    'success': True,
                    'message': 'Gửi tin nhắn thành công',
                    'security_info': {
                        'encryption': 'AES-256-GCM',
                        'signature': 'RSA-PSS',
                        'anti_replay': 'Đã gắn UUID'
                    }
                })
            else:
                return jsonify({
                    'success': False,
                    'message': result.get('message', 'Gửi tin nhắn thất bại'),
                    'security_error': result.get('error', 'unknown')
                })
        else:
            return jsonify({'success': False, 'message': 'Không thể kết nối đến server socket'})
            
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)})

@app.route('/api/receive-message', methods=['POST'])
def api_receive_message():
    try:
        server_status_response = requests.get(f'{SERVER_URL}/api/server-status', timeout=5)
        if not server_status_response.json().get('running', False):
            return jsonify({'success': False, 'message': 'Server chưa được khởi động.'})
            
        response = requests.get(f'{SERVER_URL}/api/last-message', timeout=5)
        data = response.json()
        if data.get('success'):
            return jsonify({
                'success': True,
                'message': 'Nhận tin nhắn thành công',
                'decrypted_text': data.get('decrypted_text', ''),
                'sender_id': data.get('sender_id', 'Unknown'),
                'timestamp': data.get('timestamp', '')
            })
        else:
            return jsonify({'success': False, 'message': data.get('message', 'Không có tin nhắn nào')})
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)})

# NÂNG CẤP: Đổi hàm test từ DES sang AES-GCM
@app.route('/api/test-aes', methods=['POST'])
def test_aes():
    try:
        if not crypto_manager:
            return jsonify({'success': False, 'message': 'CryptoManager không khả dụng'})
        data = request.get_json()
        test_text = data.get('text', 'Hello World!')
        
        crypto_manager.generate_aes_key()
        encrypted_data = crypto_manager.encrypt_text_aes_gcm(test_text)
        decrypted_text = crypto_manager.decrypt_text_aes_gcm(encrypted_data['nonce'], encrypted_data['cipher'])
        
        return jsonify({
            'success': True,
            'original_text': test_text,
            'encrypted_data': encrypted_data,
            'decrypted_text': decrypted_text,
            'message': 'Test AES-GCM thành công'
        })
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)})

@app.route('/api/test-rsa', methods=['POST'])
def test_rsa():
    try:
        if not crypto_manager:
            return jsonify({'success': False, 'message': 'CryptoManager không khả dụng'})
        data = request.get_json()
        test_message = data.get('message', 'Test RSA signature')
        
        signature = crypto_manager.sign_message(test_message)
        is_valid = crypto_manager.verify_signature(test_message, signature)
        is_invalid = crypto_manager.verify_signature(test_message + "tampered", signature)
        
        return jsonify({
            'success': True,
            'original_message': test_message,
            'signature': signature,
            'verification_result': is_valid,
            'tampered_verification': is_invalid,
            'message': 'Test RSA-PSS thành công'
        })
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)})

if __name__ == '__main__':
    print("🚀 Starting Secure Message Client (Upgraded Edition)...")
    app.run(host='0.0.0.0', port=5000, debug=True)