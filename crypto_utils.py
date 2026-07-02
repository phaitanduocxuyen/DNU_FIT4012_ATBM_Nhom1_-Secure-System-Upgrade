import os
import base64
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.backends import default_backend

class CryptoManager:
    def __init__(self):
        self.aes_key = None
        self.private_key = None
        self.public_key = None
        self.generate_rsa_keys()
        
    def generate_rsa_keys(self):
        """Tạo cặp khóa RSA 2048-bit"""
        self.private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        self.public_key = self.private_key.public_key()
        
    def generate_aes_key(self):
        """
        NÂNG CẤP: Dùng HKDF để dẫn xuất khóa AES-256 (32 bytes) an toàn.
        Không dùng trực tiếp os.urandom làm khóa phiên như hệ thống cũ.
        """
        raw_key_material = os.urandom(32)
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b'secure_messaging_handshake',
            backend=default_backend()
        )
        self.aes_key = hkdf.derive(raw_key_material)
        return self.aes_key
        
    def encrypt_session_key(self, public_key_pem=None):
        """Mã hóa khóa AES bằng RSA với OAEP + SHA-256"""
        if public_key_pem:
            public_key = serialization.load_pem_public_key(
                public_key_pem.encode()
            )
        else:
            public_key = self.public_key
            
        encrypted_key = public_key.encrypt(
            self.aes_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return base64.b64encode(encrypted_key).decode()
        
    def decrypt_session_key(self, encrypted_key_b64):
        """Giải mã khóa AES bằng RSA với OAEP + SHA-256"""
        encrypted_key = base64.b64decode(encrypted_key_b64)
        self.aes_key = self.private_key.decrypt(
            encrypted_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return self.aes_key
        
    def encrypt_text_aes_gcm(self, text, additional_data=None):
        """
        NÂNG CẤP: Mã hóa bằng AES-256-GCM.
        Thuật toán này tích hợp mã hóa và xác thực toàn vẹn (tạo Auth Tag),
        nên không cần dùng hàm hash SHA-256 riêng lẻ nữa.
        """
        if not self.aes_key:
            self.generate_aes_key()
            
        aesgcm = AESGCM(self.aes_key)
        # GCM khuyến nghị kích thước nonce là 12 bytes
        nonce = os.urandom(12) 
        text_bytes = text.encode('utf-8')
        
        # Ciphertext sinh ra từ AES-GCM đã bao gồm cả Authentication Tag ở cuối
        ciphertext = aesgcm.encrypt(nonce, text_bytes, additional_data)
        
        return {
            'nonce': base64.b64encode(nonce).decode(),
            'cipher': base64.b64encode(ciphertext).decode()
        }
        
    def decrypt_text_aes_gcm(self, nonce_b64, cipher_b64, additional_data=None):
        """
        Giải mã văn bản bằng AES-256-GCM.
        Sẽ tự động throw lỗi nếu dữ liệu (cipher) bị can thiệp trên đường truyền.
        """
        if not self.aes_key:
            raise ValueError("Chưa thiết lập khóa AES (AES key not available)")
            
        nonce = base64.b64decode(nonce_b64)
        ciphertext = base64.b64decode(cipher_b64)
        
        aesgcm = AESGCM(self.aes_key)
        try:
            plaintext = aesgcm.decrypt(nonce, ciphertext, additional_data)
            return plaintext.decode('utf-8')
        except Exception:
            # Bắt lỗi InvalidTag exception từ thư viện cryptography
            raise ValueError("Dữ liệu đã bị thay đổi hoặc khóa không hợp lệ (Lỗi toàn vẹn/Authentication Tag)")
            
    def sign_message(self, message):
        """
        NÂNG CẤP: Ký tin nhắn bằng RSA-PSS thay vì PKCS1v15 cũ.
        PSS cung cấp mức độ bảo mật cao hơn chống lại các tấn công trên chữ ký.
        """
        message_bytes = message.encode('utf-8')
        signature = self.private_key.sign(
            message_bytes,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return base64.b64encode(signature).decode()
        
    def verify_signature(self, message, signature_b64, public_key_pem=None):
        """Xác thực chữ ký RSA-PSS"""
        if public_key_pem:
            public_key = serialization.load_pem_public_key(
                public_key_pem.encode()
            )
        else:
            public_key = self.public_key
            
        message_bytes = message.encode('utf-8')
        signature = base64.b64decode(signature_b64)
        
        try:
            public_key.verify(
                signature,
                message_bytes,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            return True
        except:
            return False
            
    def get_public_key_pem(self):
        """Lấy public key dưới dạng PEM"""
        return self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode()