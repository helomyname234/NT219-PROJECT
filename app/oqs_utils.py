import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding as sym_padding # Đổi tên để tránh nhầm lẫn với các padding khác
from cryptography.hazmat.primitives import hashes # Nếu cần cho KDF sau này
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC # Nếu cần KDF

# Các hàm OQS (Kyber, Dilithium) sẽ được thêm đầy đủ ở bước sau
# ... (giữ lại các import oqs và các hàm OQS bạn đã viết thử nếu có)

# --- Các hằng số và cấu hình (có thể dùng chung) ---
KEY_DIR = "system_keys" # Thư mục lưu khóa của hệ thống (ví dụ khóa master Kyber)
AES_KEY_LENGTH_BYTES = 32  # AES-256, là 32 bytes
AES_IV_LENGTH_BYTES = 16   # AES CBC IV là 16 bytes (128 bits)

# --- Hàm hỗ trợ AES (mã hóa dữ liệu thực tế) ---
def generate_aes_key(key_length_bytes: int = AES_KEY_LENGTH_BYTES) -> bytes:
    """Tạo một khóa AES ngẫu nhiên an toàn."""
    return os.urandom(key_length_bytes)

def aes_encrypt(key: bytes, plaintext_bytes: bytes) -> bytes:
    """
    Mã hóa plaintext bằng AES-CBC với key và IV được tạo ngẫu nhiên.
    Trả về: iv + ciphertext.
    """
    if len(key) not in [16, 24, 32]: # 128, 192, or 256-bit key
        raise ValueError("Khóa AES phải dài 16, 24, hoặc 32 bytes.")

    iv = os.urandom(AES_IV_LENGTH_BYTES)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()

    # Sử dụng PKCS7 padding cho AES
    padder = sym_padding.PKCS7(algorithms.AES.block_size).padder() # algorithms.AES.block_size là 128 bits = 16 bytes
    padded_data = padder.update(plaintext_bytes) + padder.finalize()

    ciphertext = encryptor.update(padded_data) + encryptor.finalize()
    return iv + ciphertext  # Gắn IV vào đầu ciphertext

def aes_decrypt(key: bytes, iv_ciphertext_blob: bytes) -> bytes:
    """
    Giải mã iv_ciphertext_blob (nơi IV được gắn ở đầu) bằng AES-CBC với key.
    Trả về: plaintext_bytes gốc.
    """
    if len(key) not in [16, 24, 32]:
        raise ValueError("Khóa AES phải dài 16, 24, hoặc 32 bytes.")
    if len(iv_ciphertext_blob) < AES_IV_LENGTH_BYTES:
        raise ValueError("Dữ liệu mã hóa quá ngắn để chứa IV.")

    iv = iv_ciphertext_blob[:AES_IV_LENGTH_BYTES]
    actual_ciphertext = iv_ciphertext_blob[AES_IV_LENGTH_BYTES:]

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()

    try:
        padded_plaintext = decryptor.update(actual_ciphertext) + decryptor.finalize()

        # Gỡ bỏ PKCS7 padding
        unpadder = sym_padding.PKCS7(algorithms.AES.block_size).unpadder()
        plaintext_bytes = unpadder.update(padded_plaintext) + unpadder.finalize()
        return plaintext_bytes
    except ValueError as e:
        # Lỗi có thể xảy ra nếu padding không đúng (ví dụ: khóa sai, dữ liệu bị hỏng)
        print(f"Lỗi giải mã AES (có thể do khóa sai hoặc padding không đúng): {e}")
        raise ValueError("Giải mã AES thất bại. Dữ liệu có thể bị hỏng hoặc khóa không đúng.") from e

# --- (Các hàm OQS sẽ ở đây ở bước sau) ---
# def generate_kyber_keypair(...)
# def kyber_encapsulate(...)
# def kyber_decapsulate(...)
# def initialize_system_keys(...)

# --- Hàm tiện ích lưu/tải khóa (sẽ dùng cho khóa master Kyber) ---
# def save_key(filename, key_bytes): ...
# def load_key(filename): ...


if __name__ == '__main__':
    print("Chạy self-test cho oqs_utils.py (phần AES)...")

    # Test AES
    original_plaintext = "Đây là một thông điệp bí mật cần được mã hóa bằng AES!"
    original_plaintext_bytes = original_plaintext.encode('utf-8')

    aes_key = generate_aes_key()
    print(f"Khóa AES (hex): {aes_key.hex()}")
    print(f"Độ dài khóa AES: {len(aes_key)} bytes")

    encrypted_blob = aes_encrypt(aes_key, original_plaintext_bytes)
    print(f"Dữ liệu đã mã hóa AES (IV+Ciphertext) (hex): {encrypted_blob.hex()}")
    print(f"Độ dài blob mã hóa: {len(encrypted_blob)} bytes")

    decrypted_bytes = aes_decrypt(aes_key, encrypted_blob)
    decrypted_plaintext = decrypted_bytes.decode('utf-8')
    print(f"Dữ liệu đã giải mã: {decrypted_plaintext}")

    assert original_plaintext == decrypted_plaintext
    print("Test mã hóa và giải mã AES THÀNH CÔNG!")

    # Test với khóa sai
    wrong_aes_key = generate_aes_key()
    print(f"Thử giải mã với khóa AES sai (khóa sai hex: {wrong_aes_key.hex()})...")
    try:
        aes_decrypt(wrong_aes_key, encrypted_blob)
        print("LỖI LOGIC: Giải mã thành công với khóa sai!") # Không nên đến được đây
    except ValueError as e:
        print(f"Giải mã với khóa sai thất bại như mong đợi: {e}")
        assert "Giải mã AES thất bại" in str(e) # Hoặc kiểm tra lỗi padding cụ thể nếu có
    print("Test giải mã với khóa sai THÀNH CÔNG (đã báo lỗi)!")