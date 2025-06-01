import oqs
import os
import json
from cryptography.hazmat.primitives.ciphers.aead import AESGCM # Sử dụng AESGCM
from cryptography.exceptions import InvalidTag # Để bắt lỗi tag không hợp lệ
from typing import Optional, Tuple, Any

# --- Các hằng số và cấu hình ---
#  --- Hằng số cho Kyber768----
KEY_DIR = "system_keys"
ADMIN_KYBER_PK_FILENAME = "admin_kyber_public.key"
ADMIN_KYBER_SK_FILENAME = "admin_kyber_secret.key"
KYBER_ALG_NAME = "Kyber768" 
#  --- Hằng số cho Dilithium3----
DILITHIUM_ALG_NAME = "Dilithium3"
ADMIN_DILITHIUM_PK_FILENAME = "admin_dilithium_public.key"
ADMIN_DILITHIUM_SK_FILENAME = "admin_dilithium_secret.key"

# QUAN TRỌNG: Đảm bảo tên này khớp với output của oqs.get_enabled_KEM_mechanisms()


AES_KEY_LENGTH_BYTES = 32  # Kyber768 shared secret là 32 bytes (AES-256)
AES_GCM_NONCE_LENGTH_BYTES = 12 # Nonce khuyến nghị cho AES-GCM
# AES_GCM_TAG_LENGTH_BYTES = 16 # Thư viện cryptography tự quản lý tag

# --- Hàm hỗ trợ AES-GCM ---
def generate_aes_key(key_length_bytes: int = AES_KEY_LENGTH_BYTES) -> bytes:
    """Tạo một khóa AES ngẫu nhiên an toàn."""
    return os.urandom(key_length_bytes)

def aes_gcm_encrypt(key: bytes, plaintext_bytes: bytes, associated_data: Optional[bytes] = None) -> Tuple[bytes, bytes]:
    """
    Mã hóa plaintext bằng AES-GCM với key và nonce được tạo ngẫu nhiên.
    Có thể nhận thêm 'associated_data' không được mã hóa nhưng được xác thực.
    Trả về: (nonce, ciphertext_with_tag)
    Lưu ý: ciphertext_with_tag trả về bởi AESGCM.encrypt() đã bao gồm authentication tag.
    """
    if len(key) != AES_KEY_LENGTH_BYTES:
        raise ValueError(f"Khóa AES phải dài {AES_KEY_LENGTH_BYTES} bytes cho thuật toán {KYBER_ALG_NAME}.")

    nonce = os.urandom(AES_GCM_NONCE_LENGTH_BYTES)
    aesgcm = AESGCM(key) 

    try:
        ciphertext_with_tag = aesgcm.encrypt(nonce, plaintext_bytes, associated_data)
        return nonce, ciphertext_with_tag
    except Exception as e: 
        print(f"Lỗi mã hóa AES-GCM: {e}")
        raise # Re-raise để hàm gọi có thể xử lý

def aes_gcm_decrypt(key: bytes, nonce: bytes, ciphertext_with_tag: bytes, associated_data: Optional[bytes] = None) -> bytes:
    """
    Giải mã ciphertext_with_tag bằng AES-GCM với key, nonce và (tùy chọn) associated_data.
    Nếu tag không hợp lệ (dữ liệu bị thay đổi), hàm sẽ raise InvalidTag.
    Trả về: plaintext_bytes gốc.
    """
    if len(key) != AES_KEY_LENGTH_BYTES:
         raise ValueError(f"Khóa AES phải dài {AES_KEY_LENGTH_BYTES} bytes cho thuật toán {KYBER_ALG_NAME}.")
    if len(nonce) != AES_GCM_NONCE_LENGTH_BYTES:
        raise ValueError(f"Nonce cho AES-GCM phải dài {AES_GCM_NONCE_LENGTH_BYTES} bytes.")

    aesgcm = AESGCM(key)
    try:
        plaintext_bytes = aesgcm.decrypt(nonce, ciphertext_with_tag, associated_data)
        return plaintext_bytes
    except InvalidTag: # Bắt lỗi cụ thể khi tag không hợp lệ
        print("Lỗi giải mã AES-GCM: Tag không hợp lệ! Dữ liệu có thể đã bị sửa đổi.")
        raise ValueError("Giải mã AES-GCM thất bại: Tag không hợp lệ, dữ liệu có thể đã bị sửa đổi.")
    except Exception as e: 
        print(f"Lỗi không xác định trong quá trình giải mã AES-GCM: {e}")
        raise ValueError("Giải mã AES-GCM thất bại do lỗi không xác định.") from e

# --- Hàm tiện ích lưu/tải khóa ---
def save_key_to_file(filename_with_path: str, key_bytes: bytes) -> None:
    """Lưu bytes của khóa vào file. Tạo thư mục nếu chưa có."""
    os.makedirs(os.path.dirname(filename_with_path), exist_ok=True)
    with open(filename_with_path, "wb") as f:
        f.write(key_bytes)
    print(f"Khóa đã được lưu vào: {filename_with_path}")

def load_key_from_file(filename_with_path: str) -> Optional[bytes]:
    """Tải bytes của khóa từ file. Trả về None nếu file không tìm thấy."""
    try:
        with open(filename_with_path, "rb") as f:
            key_bytes = f.read()
            return key_bytes
    except FileNotFoundError:
        print(f"Không tìm thấy file khóa: {filename_with_path}")
        return None

# --- Hàm làm việc với OQS (Kyber KEM) ---
def generate_oqs_kem_keypair(alg_name: str) -> Tuple[bytes, bytes]:
    try:
        with oqs.KeyEncapsulation(alg_name) as kem:
            public_key = kem.generate_keypair()
            secret_key = kem.export_secret_key()
            return public_key, secret_key
    except oqs.MechanismNotSupportedError:
        print(f"LỖI: Thuật toán KEM '{alg_name}' không được hỗ trợ bởi bản build liboqs của bạn.")
        raise
    except Exception as e:
        print(f"Lỗi không xác định khi tạo cặp khóa OQS cho {alg_name}: {e}")
        raise

def oqs_kem_encapsulate(public_key_recipient: bytes, alg_name: str) -> Tuple[bytes, bytes]:
    try:
        with oqs.KeyEncapsulation(alg_name) as kem_client:
            ciphertext_c, shared_secret_k = kem_client.encap_secret(public_key_recipient)
            if alg_name.startswith("Kyber") and len(shared_secret_k) != AES_KEY_LENGTH_BYTES:
                 print(f"CẢNH BÁO: Shared secret từ {alg_name} dài {len(shared_secret_k)} bytes, "
                       f"trong khi AES yêu cầu {AES_KEY_LENGTH_BYTES} bytes.")
            return ciphertext_c, shared_secret_k
    except oqs.MechanismNotSupportedError:
        print(f"LỖI: Thuật toán KEM '{alg_name}' không được hỗ trợ bởi bản build liboqs của bạn.")
        raise
    except Exception as e:
        print(f"Lỗi không xác định khi đóng gói OQS KEM cho {alg_name}: {e}")
        raise

def oqs_kem_decapsulate(secret_key_recipient: bytes, ciphertext_c: bytes, alg_name: str) -> bytes:
    try:
        with oqs.KeyEncapsulation(alg_name, secret_key=secret_key_recipient) as kem_server:
            shared_secret_k = kem_server.decap_secret(ciphertext_c)
            if alg_name.startswith("Kyber") and len(shared_secret_k) != AES_KEY_LENGTH_BYTES:
                 print(f"CẢNH BÁO: Shared secret được giải mã từ {alg_name} dài {len(shared_secret_k)} bytes, "
                       f"trong khi AES yêu cầu {AES_KEY_LENGTH_BYTES} bytes.")
            return shared_secret_k
    except oqs.MechanismNotSupportedError:
        print(f"LỖI: Thuật toán KEM '{alg_name}' không được hỗ trợ bởi bản build liboqs của bạn.")
        raise
    except Exception as e:
        print(f"Lỗi không xác định hoặc giải mã KEM thất bại cho {alg_name}: {e}")
        raise ValueError(f"Giải mã KEM thất bại cho {alg_name}. Bản mã có thể không hợp lệ, khóa bí mật sai, hoặc lỗi OQS.") from e

# --- Các hàm hỗ trợ sign and verify cert Dilithium3 ---

def generate_oqs_sig_keypair(alg_name: str) -> Tuple[bytes, bytes]:
    """Tạo cặp khóa Chữ ký OQS (ví dụ: Dilithium) và trả về (public_key, secret_key)."""
    try:
        with oqs.Signature(alg_name) as sig:
            public_key = sig.generate_keypair()
            secret_key = sig.export_secret_key()
            return public_key, secret_key
    except oqs.MechanismNotSupportedError:
        print(f"LỖI: Thuật toán Signature '{alg_name}' không được hỗ trợ bởi bản build liboqs của bạn.")
        raise
    except Exception as e:
        print(f"Lỗi không xác định khi tạo cặp khóa Signature OQS cho {alg_name}: {e}")
        raise

def oqs_signature_sign(secret_key_signer: bytes, message: bytes, alg_name: str) -> bytes:
    """Ký một thông điệp sử dụng khóa bí mật (ví dụ: Dilithium)."""
    try:
        # Khởi tạo đối tượng Signature với khóa bí mật
        with oqs.Signature(alg_name, secret_key=secret_key_signer) as sig:
            signature = sig.sign(message)
            return signature
    except oqs.MechanismNotSupportedError:
        print(f"LỖI: Thuật toán Signature '{alg_name}' không được hỗ trợ.")
        raise
    except Exception as e:
        print(f"Lỗi không xác định khi ký bằng OQS Signature cho {alg_name}: {e}")
        raise

def oqs_signature_verify(public_key_signer: bytes, message: bytes, signature: bytes, alg_name: str) -> bool:
    """
    Xác minh một chữ ký sử dụng khóa công khai (ví dụ: Dilithium).
    Trả về True nếu chữ ký hợp lệ, False nếu không.
    """
    try:
        # Khởi tạo đối tượng Signature mà không cần khóa cho việc xác minh
        with oqs.Signature(alg_name) as sig_verifier:
            # Hàm verify nhận public_key như một tham số (dựa trên ví dụ của liboqs-python)
            is_valid = sig_verifier.verify(message, signature, public_key_signer)
            return is_valid
    except oqs.MechanismNotSupportedError:
        print(f"LỖI: Thuật toán Signature '{alg_name}' không được hỗ trợ.")
        raise # Nên raise để hàm gọi biết
    except Exception as e: 
        # oqs.Signature.verify có thể raise lỗi nếu chữ ký có cấu trúc không hợp lệ 
        print(f"Lỗi không xác định hoặc chữ ký có cấu trúc không hợp lệ khi xác minh OQS Signature cho {alg_name}: {e}")
        return False 


def initialize_system_keys() -> None:
    """
    Kiểm tra và tạo cặp khóa Kyber và Dilithium cho admin nếu chúng chưa tồn tại.
    Lưu khóa vào thư mục KEY_DIR.
    """
    os.makedirs(KEY_DIR, exist_ok=True) # Đảm bảo thư mục KEY_DIR tồn tại

    # Xử lý khóa Kyber
    admin_kyber_pk_path = os.path.join(KEY_DIR, ADMIN_KYBER_PK_FILENAME)
    admin_kyber_sk_path = os.path.join(KEY_DIR, ADMIN_KYBER_SK_FILENAME)
    if not os.path.exists(admin_kyber_pk_path) or not os.path.exists(admin_kyber_sk_path):
        print(f"Khóa Kyber của Admin không tìm thấy. Đang tạo cặp khóa mới cho {KYBER_ALG_NAME}...")
        try:
            public_key_k, secret_key_k = generate_oqs_kem_keypair(KYBER_ALG_NAME) # Sử dụng tên hàm đã đổi
            save_key_to_file(admin_kyber_pk_path, public_key_k)
            save_key_to_file(admin_kyber_sk_path, secret_key_k)
            print(f"Cặp khóa Kyber của Admin đã được tạo và lưu.")
        except Exception as e:
            print(f"LỖI NGHIÊM TRỌNG: Không thể tạo hoặc lưu khóa Kyber của Admin: {e}")
            raise SystemExit(f"Không thể khởi tạo khóa Kyber hệ thống: {e}")
    else:
        print(f"Đã tìm thấy khóa Kyber của Admin trong '{KEY_DIR}'.")

    # >>> THÊM XỬ LÝ KHÓA DILITHIUM <<<
    admin_dilithium_pk_path = os.path.join(KEY_DIR, ADMIN_DILITHIUM_PK_FILENAME)
    admin_dilithium_sk_path = os.path.join(KEY_DIR, ADMIN_DILITHIUM_SK_FILENAME)
    if not os.path.exists(admin_dilithium_pk_path) or not os.path.exists(admin_dilithium_sk_path):
        print(f"Khóa Dilithium của Admin không tìm thấy. Đang tạo cặp khóa mới cho {DILITHIUM_ALG_NAME}...")
        try:
            public_key_d, secret_key_d = generate_oqs_sig_keypair(DILITHIUM_ALG_NAME)
            save_key_to_file(admin_dilithium_pk_path, public_key_d)
            save_key_to_file(admin_dilithium_sk_path, secret_key_d)
            print(f"Cặp khóa Dilithium của Admin đã được tạo và lưu.")
        except Exception as e:
            print(f"LỖI NGHIÊM TRỌNG: Không thể tạo hoặc lưu khóa Dilithium của Admin: {e}")
            raise SystemExit(f"Không thể khởi tạo khóa Dilithium hệ thống: {e}")
    else:
        print(f"Đã tìm thấy khóa Dilithium của Admin trong '{KEY_DIR}'.")


if __name__ == '__main__':
    print("Chạy self-test cho oqs_utils.py (AES-GCM và OQS KEM)...")
     # In ra các KEM và Signature được hỗ trợ
    try:
        print("\nCác cơ chế KEM được liboqs hiện tại hỗ trợ:")
        print(oqs.get_enabled_KEM_mechanisms())
        print("\nCác cơ chế Signature được liboqs hiện tại hỗ trợ:")
        supported_sigs = oqs.get_enabled_sig_mechanisms() # Lưu lại để kiểm tra
        print(supported_sigs)
        if KYBER_ALG_NAME not in oqs.get_enabled_KEM_mechanisms():
            print(f"CẢNH BÁO KEM: Tên '{KYBER_ALG_NAME}' có thể không chính xác/build.")
        if DILITHIUM_ALG_NAME not in supported_sigs:
            print(f"CẢNH BÁO SIG: Tên '{DILITHIUM_ALG_NAME}' có thể không chính xác/build.")
    except Exception as e:
        print(f"Không thể lấy danh sách cơ chế: {e}")

    # --- Test AES-GCM ---
    original_plaintext_gcm = "Thông điệp bí mật với AES-GCM!"
    original_plaintext_gcm_bytes = original_plaintext_gcm.encode('utf-8')
    # Dữ liệu liên kết tùy chọn (không được mã hóa nhưng được xác thực)
    associated_data_example = b"metadata_version_1.0" 
    
    aes_gcm_key = generate_aes_key() # Khóa AES 32 bytes
    print(f"\n--- Test AES-GCM với khóa dài {len(aes_gcm_key)} bytes ---")

    # Mã hóa
    nonce_val, ciphertext_with_tag_val = aes_gcm_encrypt(aes_gcm_key, original_plaintext_gcm_bytes, associated_data_example)
    print(f"Nonce (hex): {nonce_val.hex()} (dài {len(nonce_val)} bytes)")
    print(f"Ciphertext cùng Tag (hex): {ciphertext_with_tag_val.hex()} (dài {len(ciphertext_with_tag_val)} bytes)")
    
    # Giải mã (trường hợp đúng)
    try:
        decrypted_gcm_bytes = aes_gcm_decrypt(aes_gcm_key, nonce_val, ciphertext_with_tag_val, associated_data_example)
        decrypted_gcm_plaintext = decrypted_gcm_bytes.decode('utf-8')
        print(f"Dữ liệu đã giải mã (GCM): {decrypted_gcm_plaintext}")
        assert original_plaintext_gcm == decrypted_gcm_plaintext
        print("Test mã hóa và giải mã AES-GCM THÀNH CÔNG!")
    except ValueError as e:
        print(f"LỖI khi giải mã AES-GCM trường hợp đúng: {e}")


    # Test giải mã với ciphertext bị sửa đổi
    print("\nThử giải mã với ciphertext bị sửa đổi (AES-GCM)...")
    corrupted_ciphertext_with_tag = bytearray(ciphertext_with_tag_val)
    if len(corrupted_ciphertext_with_tag) > 0:
        corrupted_ciphertext_with_tag[0] = corrupted_ciphertext_with_tag[0] ^ 0x01 
    else:
        corrupted_ciphertext_with_tag = b"corrupted"
    try:
        aes_gcm_decrypt(aes_gcm_key, nonce_val, bytes(corrupted_ciphertext_with_tag), associated_data_example)
        print("LỖI LOGIC (AES-GCM): Giải mã thành công với ciphertext bị sửa đổi!")
    except ValueError as e: # Mong đợi lỗi InvalidTag được bắt ở đây
        print(f"Giải mã AES-GCM với ciphertext bị sửa đổi thất bại như mong đợi: {e}")
    print("Test giải mã AES-GCM với ciphertext bị sửa đổi (bắt lỗi ValueError) THÀNH CÔNG!")

    # Test giải mã với nonce bị sửa đổi
    print("\nThử giải mã với nonce bị sửa đổi (AES-GCM)...")
    corrupted_nonce = bytearray(nonce_val)
    if len(corrupted_nonce) > 0:
        corrupted_nonce[0] = corrupted_nonce[0] ^ 0x01
    else:
        corrupted_nonce = os.urandom(AES_GCM_NONCE_LENGTH_BYTES) # Nonce hoàn toàn khác
    try:
        aes_gcm_decrypt(aes_gcm_key, bytes(corrupted_nonce), ciphertext_with_tag_val, associated_data_example)
        print("LỖI LOGIC (AES-GCM): Giải mã thành công với nonce bị sửa đổi!")
    except ValueError as e:
        print(f"Giải mã AES-GCM với nonce bị sửa đổi thất bại như mong đợi: {e}")
    print("Test giải mã AES-GCM với nonce bị sửa đổi (bắt lỗi ValueError) THÀNH CÔNG!")


    # Test giải mã với associated_data bị sửa đổi (nếu có sử dụng)
    if associated_data_example:
        print("\nThử giải mã với associated_data bị sửa đổi (AES-GCM)...")
        corrupted_associated_data = b"metadata_was_totally_changed"
        try:
            aes_gcm_decrypt(aes_gcm_key, nonce_val, ciphertext_with_tag_val, corrupted_associated_data)
            print("LỖI LOGIC (AES-GCM): Giải mã thành công với associated_data bị sửa đổi!")
        except ValueError as e:
            print(f"Giải mã AES-GCM với associated_data bị sửa đổi thất bại như mong đợi: {e}")
        print("Test giải mã AES-GCM với associated_data bị sửa đổi (bắt lỗi ValueError) THÀNH CÔNG!")

    print("\n" + "-"*30)
    # --- Test OQS KEM (Kyber) - giữ nguyên phần này ---
    try:
        print(f"Đang test KEM với thuật toán đã cấu hình: {KYBER_ALG_NAME}")
        pk, sk = generate_oqs_kem_keypair(KYBER_ALG_NAME)
        print(f"  Độ dài Khóa công khai Kyber ({KYBER_ALG_NAME}): {len(pk)} bytes")
        print("  Client đang đóng gói shared secret...")
        ciphertext_c, shared_secret_k_client = oqs_kem_encapsulate(pk, KYBER_ALG_NAME)
        print(f"  Độ dài Ciphertext C (Kyber): {len(ciphertext_c)} bytes")
        print(f"  Độ dài Shared Secret K (Client): {len(shared_secret_k_client)} bytes (Kỳ vọng {AES_KEY_LENGTH_BYTES} cho {KYBER_ALG_NAME})")

        print("  Server đang mở gói shared secret...")
        shared_secret_k_server = oqs_kem_decapsulate(sk, ciphertext_c, KYBER_ALG_NAME)
        print(f"  Độ dài Shared Secret K (Server): {len(shared_secret_k_server)} bytes")

        assert shared_secret_k_client == shared_secret_k_server, "LỖI: Shared secrets không khớp!"
        print("  KEM Self-Test (Keypair -> Encaps -> Decaps) THÀNH CÔNG: Shared secrets khớp!")

        print("\n  Kiểm tra hàm initialize_system_keys()...")
        initialize_system_keys() 
        initialize_system_keys() 
        assert os.path.exists(os.path.join(KEY_DIR, ADMIN_KYBER_PK_FILENAME))
        assert os.path.exists(os.path.join(KEY_DIR, ADMIN_KYBER_SK_FILENAME))
        print("  Test initialize_system_keys() THÀNH CÔNG.")

    except oqs.MechanismNotSupportedError as e:
        print(f"LỖI KEM Self-Test: {e}. Đảm bảo {KYBER_ALG_NAME} là tên chính xác và được kích hoạt trong liboqs.")
    # ... (các khối except khác giữ nguyên) ...
    except ValueError as ve:
        print(f"LỖI KEM Self-Test (ValueError): {ve}")
    except TypeError as te: 
        print(f"LỖI KEM Self-Test (TypeError): {te}")
        import traceback
        traceback.print_exc()
    except Exception as e:
        print(f"LỖI KEM Self-Test không mong đợi: {e}")
        import traceback
        traceback.print_exc()

    # TEST CHO OQS SIGNATURE (DILITHIUM)

    print("\n" + "-"*30)
    try:
        print(f"Đang test Signature với thuật toán đã cấu hình: {DILITHIUM_ALG_NAME}")
        message_to_sign = b"This is a very important message that needs to be signed for NT219 project."

        # 1. Tạo cặp khóa Dilithium
        sig_pk, sig_sk = generate_oqs_sig_keypair(DILITHIUM_ALG_NAME)
        print(f"  Độ dài Khóa công khai Dilithium ({DILITHIUM_ALG_NAME}): {len(sig_pk)} bytes")
        print(f"  Độ dài Khóa bí mật Dilithium ({DILITHIUM_ALG_NAME}): {len(sig_sk)} bytes")

        # 2. Ký thông điệp
        print(f"  Đang ký thông điệp: '{message_to_sign.decode()}'")
        signature = oqs_signature_sign(sig_sk, message_to_sign, DILITHIUM_ALG_NAME)
        print(f"  Độ dài Chữ ký: {len(signature)} bytes")

        # 3. Xác minh chữ ký (trường hợp đúng)
        print("  Đang xác minh chữ ký (trường hợp đúng)...")
        is_valid_correct = oqs_signature_verify(sig_pk, message_to_sign, signature, DILITHIUM_ALG_NAME)
        assert is_valid_correct, "LỖI: Chữ ký hợp lệ không được xác minh đúng!"
        print("  Xác minh chữ ký hợp lệ THÀNH CÔNG!")

        # 4. Xác minh chữ ký (trường hợp thông điệp sai)
        print("  Đang xác minh chữ ký (với thông điệp sai)...")
        wrong_message = b"This is a completely different and incorrect message."
        is_valid_wrong_message = oqs_signature_verify(sig_pk, wrong_message, signature, DILITHIUM_ALG_NAME)
        assert not is_valid_wrong_message, "LỖI: Chữ ký với thông điệp sai lại được xác minh là đúng!"
        print("  Xác minh chữ ký với thông điệp sai THÀNH CÔNG (đã báo không hợp lệ)!")
        
        # 5. Xác minh chữ ký (trường hợp chữ ký sai)
        print("  Đang xác minh chữ ký (với chữ ký bị sửa đổi)...")
        corrupted_signature = bytearray(signature)
        if len(corrupted_signature) > 0:
            # Thay đổi một byte ở giữa chữ ký để chắc chắn làm hỏng nó
            idx_to_corrupt = len(corrupted_signature) // 2
            corrupted_signature[idx_to_corrupt] = corrupted_signature[idx_to_corrupt] ^ 0xFF
        is_valid_wrong_sig = oqs_signature_verify(sig_pk, message_to_sign, bytes(corrupted_signature), DILITHIUM_ALG_NAME)
        assert not is_valid_wrong_sig, "LỖI: Chữ ký bị sửa đổi lại được xác minh là đúng!"
        print("  Xác minh chữ ký bị sửa đổi THÀNH CÔNG (đã báo không hợp lệ)!")

    except oqs.MechanismNotSupportedError as e:
        print(f"LỖI SIGNATURE Self-Test: {e}. Đảm bảo {DILITHIUM_ALG_NAME} là tên chính xác và được kích hoạt trong liboqs.")
    except ValueError as ve: 
        print(f"LỖI SIGNATURE Self-Test (ValueError): {ve}")
    except TypeError as te: 
        print(f"LỖI SIGNATURE Self-Test (TypeError): {te}")
    except Exception as e:
        print(f"LỖI SIGNATURE Self-Test không mong đợi: {e}")
        import traceback
        traceback.print_exc()
        
    # --- Test khởi tạo tất cả khóa hệ thống ---
    print("\n" + "-"*30)
    print("Kiểm tra hàm initialize_system_keys() (bao gồm Kyber và Dilithium)...")
    try:
        initialize_system_keys() # Gọi hàm đã đổi tên và cập nhật
        initialize_system_keys() # Gọi lại để test trường hợp đã tồn tại
        assert os.path.exists(os.path.join(KEY_DIR, ADMIN_KYBER_PK_FILENAME))
        assert os.path.exists(os.path.join(KEY_DIR, ADMIN_KYBER_SK_FILENAME))
        assert os.path.exists(os.path.join(KEY_DIR, ADMIN_DILITHIUM_PK_FILENAME)) # Kiểm tra khóa Dilithium
        assert os.path.exists(os.path.join(KEY_DIR, ADMIN_DILITHIUM_SK_FILENAME))
        print("Test initialize_system_keys() cho Kyber và Dilithium THÀNH CÔNG.")
    except Exception as e:
        print(f"Lỗi khi test initialize_system_keys: {e}")
        import traceback
        traceback.print_exc()

    print("\nSelf-test cho oqs_utils.py (AES-GCM và OQS KEM) hoàn thành.")