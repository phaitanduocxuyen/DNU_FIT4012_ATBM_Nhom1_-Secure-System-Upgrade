import socket
import json
import time
import uuid
import base64
from crypto_utils import CryptoManager

class SecurityTester:
    def __init__(self, host='localhost', port=8888):
        self.host = host
        self.port = port
        self.crypto = CryptoManager()
        self.server_public_key = None
        self.client_id = "Hacker_Test_Bot"
        self.socket = None
        self.session_key = None
        self.test_results = []
        
    def connect_and_auth(self):
        """Mô phỏng Handshake và Xác thực hợp lệ ban đầu"""
        try:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.connect((self.host, self.port))
            
            # Handshake
            self.socket.send("Hello!".encode())
            if self.socket.recv(1024).decode() != "Ready!":
                return False
            self.server_public_key = self.socket.recv(2048).decode()
            
            # Tạo khóa AES-GCM qua HKDF
            self.session_key = self.crypto.generate_aes_key()
            encrypted_session_key = self.crypto.encrypt_session_key(self.server_public_key)
            signed_info = self.crypto.sign_message(self.client_id)
            
            # Auth
            auth_packet = {
                'type': 'auth',
                'signed_info': signed_info,
                'encrypted_aes_key': encrypted_session_key,
                'client_id': self.client_id,
                'client_public_key': self.crypto.get_public_key_pem()
            }
            
            self._send_packet(auth_packet)
            response = self._recv_response()
            return response.get('status') == 'ACK'
        except Exception as e:
            print(f"Lỗi kết nối/xác thực: {e}")
            return False

    def _send_packet(self, packet):
        data = json.dumps(packet).encode()
        size = str(len(data)).zfill(8)
        self.socket.send(size.encode())
        self.socket.send(data)

    def _recv_response(self):
        size_data = self.socket.recv(8)
        if not size_data: return None
        response_size = int(size_data.decode())
        response_bytes = b''
        while len(response_bytes) < response_size:
            chunk = self.socket.recv(response_size - len(response_bytes))
            if not chunk: break
            response_bytes += chunk
        return json.loads(response_bytes.decode())

    # =========================================================================
    # CÁC KỊCH BẢN TẤN CÔNG (TEST CASES)
    # =========================================================================

    def test_1_valid_message(self):
        """TEST 1: Gửi tin nhắn hợp lệ (Kiểm tra Base case)"""
        print("\n[TEST 1] Đang gửi tin nhắn hợp lệ (Happy Path)...")
        msg_id = str(uuid.uuid4())
        encrypted = self.crypto.encrypt_text_aes_gcm("Đây là tin nhắn hoàn toàn hợp lệ.")
        signature_payload = encrypted['cipher'] + msg_id
        
        packet = {
            'type': 'message',
            'cipher': encrypted['cipher'],
            'nonce': encrypted['nonce'],
            'msg_id': msg_id,
            'sig': self.crypto.sign_message(signature_payload),
            'recipient_id': 'Server',
            'timestamp': int(time.time())
        }
        
        # Lưu lại packet này để xài cho bài test Replay Attack
        self.last_valid_packet = packet 
        
        self._send_packet(packet)
        response = self._recv_response()
        passed = response.get('status') == 'ACK'
        self._print_result("Test Hợp lệ", passed, response)

    def test_2_replay_attack(self):
        """TEST 2: Tấn công phát lại (Gửi lại y hệt gói tin cũ)"""
        print("\n[TEST 2] Đang mô phỏng Replay Attack (Gửi lại gói tin của Test 1)...")
        
        # Cố tình gửi lại y hệt packet cũ
        self._send_packet(self.last_valid_packet)
        response = self._recv_response()
        
        # Đạt yêu cầu nếu Server từ chối (NACK) với lỗi replay
        passed = response.get('status') == 'NACK' and response.get('error') == 'replay'
        self._print_result("Test Chống Replay Attack", passed, response)

    def test_3_tampering_attack(self):
        """TEST 3: Tấn công thay đổi dữ liệu (Sửa đổi Ciphertext)"""
        print("\n[TEST 3] Đang mô phỏng Tampering Attack (Sửa đổi 1 ký tự trong Ciphertext)...")
        
        msg_id = str(uuid.uuid4())
        encrypted = self.crypto.encrypt_text_aes_gcm("Tin nhắn này sẽ bị sửa đổi.")
        
        # Mô phỏng Hacker chặn bắt và sửa Data (Ciphertext)
        original_cipher = encrypted['cipher']
        # Đổi ký tự đầu tiên
        tampered_cipher = 'A' + original_cipher[1:] 
        
        # Vẫn dùng chữ ký cũ
        signature_payload = original_cipher + msg_id 
        
        packet = {
            'type': 'message',
            'cipher': tampered_cipher, # Dữ liệu đã bị hỏng
            'nonce': encrypted['nonce'],
            'msg_id': msg_id,
            'sig': self.crypto.sign_message(signature_payload),
            'recipient_id': 'Server',
            'timestamp': int(time.time())
        }
        
        self._send_packet(packet)
        response = self._recv_response()
        
        # Đạt yêu cầu nếu Server từ chối (NACK) vì lỗi auth hoặc integrity
        passed = response.get('status') == 'NACK' and response.get('error') in ['auth', 'integrity']
        self._print_result("Test Phát hiện Dữ liệu bị sửa (AES Auth Tag)", passed, response)

    def run_benchmark(self):
        """TEST 4: Đo hiệu năng mã hóa AES-256-GCM (1000 vòng lặp)"""
        print("\n[BENCHMARK] Bắt đầu đo hiệu năng AES-256-GCM...")
        start_time = time.time()
        for _ in range(1000):
            self.crypto.encrypt_text_aes_gcm("Tin nhắn mẫu để test hiệu năng " * 10)
        end_time = time.time()
        duration = end_time - start_time
        print(f"👉 Mã hóa 1000 tin nhắn AES-GCM mất: {duration:.4f} giây")

    def _print_result(self, test_name, passed, response):
        if passed:
            print(f"✅ {test_name}: PASSED")
            print(f"   Server phản hồi đúng mong đợi: {response.get('message')}")
        else:
            print(f"❌ {test_name}: FAILED")
            print(f"   Server phản hồi sai: {response}")

if __name__ == "__main__":
    print("=" * 60)
    print("🔐 CÔNG CỤ KIỂM THỬ BẢO MẬT TỰ ĐỘNG (SECURITY TESTER)")
    print("=" * 60)
    
    tester = SecurityTester()
    if tester.connect_and_auth():
        print("Đã xác thực thành công vào Server. Bắt đầu tấn công...\n")
        
        # Chạy liên tiếp các kịch bản
        tester.test_1_valid_message()
        time.sleep(1) # Nghỉ 1s
        
        # Test 2 phải chạy trên một kết nối mới vì Server ngắt kết nối sau mỗi NACK
        tester.socket.close()
        tester.connect_and_auth()
        tester.test_2_replay_attack()
        
        tester.socket.close()
        tester.connect_and_auth()
        tester.test_3_tampering_attack()
        
        tester.run_benchmark()
    else:
        print("❌ Không thể kết nối tới Server. Hãy bật Server trước!")