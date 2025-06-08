# app/main.py
from fastapi import FastAPI, HTTPException, status
import json
import os 
from typing import Optional, List 

from .model import CitizenCreate, CitizenDisplay, MessageResponse 
from .db_utils import init_db, add_citizen_record_db, get_citizen_record_db
# from .db_utils import get_all_citizens_db

from .oqs_utils import (
    initialize_system_keys, load_key_from_file, 
    oqs_kem_encapsulate, oqs_kem_decapsulate,
    aes_gcm_encrypt, aes_gcm_decrypt,
    oqs_signature_sign, oqs_signature_verify,
    hash_data_sha256, 
    KYBER_ALG_NAME, DILITHIUM_ALG_NAME, 
    KEY_DIR, 
    ADMIN_KYBER_PK_FILENAME, ADMIN_KYBER_SK_FILENAME,
    ADMIN_DILITHIUM_PK_FILENAME, ADMIN_DILITHIUM_SK_FILENAME
)
import oqs

app = FastAPI(
    title="Citizen Info API (Hashed ID, Signed Records)",
    description="API mô phỏng hệ thống tra cứu thông tin công dân sử dụng băm ID, Kyber KEM, AES-GCM, và Dilithium Signature.",
    version="0.5.0", 
)

ADMIN_KYBER_PUBLIC_KEY: Optional[bytes] = None
ADMIN_KYBER_SECRET_KEY: Optional[bytes] = None
ADMIN_DILITHIUM_PUBLIC_KEY: Optional[bytes] = None 
ADMIN_DILITHIUM_SECRET_KEY: Optional[bytes] = None 

@app.on_event("startup")
async def startup_event():
    global ADMIN_KYBER_PUBLIC_KEY, ADMIN_KYBER_SECRET_KEY, ADMIN_DILITHIUM_PUBLIC_KEY, ADMIN_DILITHIUM_SECRET_KEY
    print("Application startup: Initializing database and loading/creating ALL system keys...")
    init_db() 
    initialize_system_keys() 

    ADMIN_KYBER_PUBLIC_KEY = load_key_from_file(os.path.join(KEY_DIR, ADMIN_KYBER_PK_FILENAME))
    ADMIN_KYBER_SECRET_KEY = load_key_from_file(os.path.join(KEY_DIR, ADMIN_KYBER_SK_FILENAME))


    ADMIN_DILITHIUM_PUBLIC_KEY = load_key_from_file(os.path.join(KEY_DIR, ADMIN_DILITHIUM_PK_FILENAME))
    ADMIN_DILITHIUM_SECRET_KEY  = load_key_from_file(os.path.join(KEY_DIR, ADMIN_DILITHIUM_SK_FILENAME))

    if not all([ADMIN_KYBER_PUBLIC_KEY, ADMIN_KYBER_SECRET_KEY, 
                ADMIN_DILITHIUM_PUBLIC_KEY, ADMIN_DILITHIUM_SECRET_KEY]):
        print("LỖI NGHIÊM TRỌNG: Không thể tải tất cả các khóa hệ thống cần thiết khi khởi động ứng dụng.")
        raise SystemExit("Không thể tải tất cả các khóa hệ thống cần thiết. Ứng dụng dừng lại.")
    print("Database and ALL System keys initialization complete. Admin keys loaded.")

@app.get("/", response_model=MessageResponse, tags=["General"])
async def read_root():
    return {"message": "API Hệ thống Thông tin Công dân (Hashed ID, Kyber, AES-GCM, Dilithium)"}

@app.post("/register", response_model=CitizenDisplay, status_code=status.HTTP_201_CREATED, tags=["Citizens"])
async def register_new_citizen(citizen_input: CitizenCreate): 
    if not (ADMIN_KYBER_PUBLIC_KEY and ADMIN_DILITHIUM_SECRET_KEY):
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail="Hệ thống chưa sẵn sàng (thiếu khóa đăng ký).")

    original_citizen_id = citizen_input.citizen_id
    print(f"Registering original_citizen_id: {original_citizen_id}")
    # Khai báo biến ở phạm vi hàm để có thể dùng trong except nếu cần
    hashed_id_for_db: Optional[str] = None 
    try:
        hashed_id_for_db = hash_data_sha256(original_citizen_id)
        print(f"  Hashed ID for DB: {hashed_id_for_db}")

        citizen_data_to_encrypt_dict = citizen_input.model_dump()
        citizen_data_plaintext_bytes = json.dumps(citizen_data_to_encrypt_dict).encode('utf-8')

        kyber_ct_for_aes_key, record_specific_aes_key = oqs_kem_encapsulate(
            ADMIN_KYBER_PUBLIC_KEY, KYBER_ALG_NAME
        )

        aad_bytes_for_encrypt = hashed_id_for_db.encode('utf-8')
        nonce, ciphertext_with_tag = aes_gcm_encrypt(
            record_specific_aes_key,
            citizen_data_plaintext_bytes,
            associated_data=aad_bytes_for_encrypt
        )

        nonce_hex = nonce.hex()
        ct_tag_hex = ciphertext_with_tag.hex() 
        kyber_ct_hex = kyber_ct_for_aes_key.hex() 
        
        message_to_sign_str = f"{hashed_id_for_db}|{nonce_hex}|{ct_tag_hex}|{kyber_ct_hex}"
        message_to_sign_bytes = message_to_sign_str.encode('utf-8')
        print(f"  Message for Dilithium signing (first 100 chars): {message_to_sign_str[:100]}...")

        record_signature = oqs_signature_sign(
            ADMIN_DILITHIUM_SECRET_KEY,
            message_to_sign_bytes,
            DILITHIUM_ALG_NAME
        )
        record_signature_hex = record_signature.hex()
        print(f"  Record signature (Dilithium) hex (first 30 chars): {record_signature_hex[:30]}...")

        add_citizen_record_db(
            hashed_citizen_id=hashed_id_for_db,
            aes_gcm_nonce_hex=nonce_hex,
            encrypted_data_with_tag_hex=ct_tag_hex,
            kyber_ciphertext_c_hex=kyber_ct_hex,
            record_signature_hex=record_signature_hex
        )
        
        return CitizenDisplay(**citizen_data_to_encrypt_dict) 
    
    except ValueError as ve: 
        if "already exists" in str(ve): 
            error_hashed_id = hashed_id_for_db if hashed_id_for_db else "N/A"
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=f"Citizen ID (sau khi xử lý thành '{error_hashed_id}') có thể đã tồn tại.")
        else: 
            raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"Lỗi xử lý dữ liệu trong quá trình đăng ký: {ve}")
    except oqs.MechanismNotSupportedError as oqs_err:
        print(f"OQS Error during registration: {oqs_err}")
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Lỗi OQS: Thuật toán không được hỗ trợ.")
    except Exception as e:
        print(f"Unexpected error during registration: {e}")
        import traceback
        traceback.print_exc()
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Lỗi không xác định trong quá trình đăng ký.")

@app.get("/lookup/{citizen_id_original}", response_model=CitizenDisplay, tags=["Citizens"])
async def lookup_citizen_info(citizen_id_original: str): 
    if not (ADMIN_KYBER_SECRET_KEY and ADMIN_DILITHIUM_PUBLIC_KEY):
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail="Hệ thống chưa sẵn sàng (thiếu khóa tra cứu).")

    print(f"Looking up original_citizen_id: {citizen_id_original}")
    hashed_id_to_lookup: Optional[str] = None
    try:
        hashed_id_to_lookup = hash_data_sha256(citizen_id_original)
        print(f"  Hashed ID for DB lookup: {hashed_id_to_lookup}")
        
        db_record = get_citizen_record_db(hashed_id_to_lookup)
        
        if not db_record:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Không tìm thấy công dân với ID: {citizen_id_original}")
        
        nonce_h = db_record["aes_gcm_nonce_hex"]
        ct_tag_h = db_record["encrypted_data_with_tag_hex"]
        kyber_ct_h = db_record["kyber_ciphertext_c_hex"]
        sig_h = db_record["record_signature_hex"]

        msg_to_verify_str = f"{hashed_id_to_lookup}|{nonce_h}|{ct_tag_h}|{kyber_ct_h}"
        msg_to_verify_bytes = msg_to_verify_str.encode('utf-8')
        sig_bytes = bytes.fromhex(sig_h)
        print(f"  Verifying signature for stored record (hashed_id: {hashed_id_to_lookup})")

        is_signature_valid = oqs_signature_verify(
            ADMIN_DILITHIUM_PUBLIC_KEY,
            msg_to_verify_bytes,
            sig_bytes,
            DILITHIUM_ALG_NAME
        )

        if not is_signature_valid:
            print(f"  SIGNATURE VERIFICATION FAILED for record with hashed_id {hashed_id_to_lookup}!")
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Xác minh tính toàn vẹn dữ liệu của bản ghi thất bại. Không thể truy cập an toàn.")
        
        print(f"  Signature for record with hashed_id {hashed_id_to_lookup} is VALID.")

        kyber_ct_bytes = bytes.fromhex(kyber_ct_h)
        aes_key = oqs_kem_decapsulate(ADMIN_KYBER_SECRET_KEY, kyber_ct_bytes, KYBER_ALG_NAME)

        nonce_bytes = bytes.fromhex(nonce_h)
        ct_tag_bytes = bytes.fromhex(ct_tag_h)
        aad_bytes_verify = hashed_id_to_lookup.encode('utf-8') 

        decrypted_data_bytes = aes_gcm_decrypt(aes_key, nonce_bytes, ct_tag_bytes, associated_data=aad_bytes_verify)
        decrypted_data_dict = json.loads(decrypted_data_bytes.decode('utf-8'))
        
        return CitizenDisplay(**decrypted_data_dict)

    except ValueError as ve: 
        error_id_display = hashed_id_to_lookup if hashed_id_to_lookup else f"(original: {citizen_id_original})"
        print(f"ValueError during processing for {error_id_display}: {ve}")
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"Lỗi xử lý hoặc xác minh dữ liệu.")
    except oqs.MechanismNotSupportedError as oqs_err:
        print(f"OQS Error during lookup: {oqs_err}")
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Lỗi OQS: Thuật toán không được hỗ trợ.")
    except HTTPException: 
        raise
    except Exception as e:
        error_id_display_exc = hashed_id_to_lookup if hashed_id_to_lookup else f"(original: {citizen_id_original})"
        print(f"Unexpected error during lookup for {error_id_display_exc}: {e}")
        import traceback
        traceback.print_exc()
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Lỗi không xác định trong quá trình tra cứu.")

# --- (Tùy chọn) Endpoint để xem tất cả công dân (cập nhật cho AES-GCM và Dilithium) ---
# @app.get("/citizens", response_model=List[CitizenDisplay], tags=["Internal Tools"])
# async def list_all_citizens_debug():
#     """
#     (CHỈ DÙNG CHO DEBUG) Lấy danh sách tất cả công dân đã giải mã.
#     Yêu cầu hàm get_all_citizens_db() trong db_utils.py.
#     CẢNH BÁO: Endpoint này không an toàn và tốn hiệu năng nếu DB lớn.
#     """
#     if not (ADMIN_KYBER_SECRET_KEY and ADMIN_DILITHIUM_PUBLIC_KEY):
#         raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail="Hệ thống chưa sẵn sàng (thiếu khóa).")

#     # Giả sử bạn có hàm get_all_citizens_db() trong db_utils.py trả về List[Dict[str, Any]]
#     try:
#         # Bạn cần tạo hàm này trong db_utils.py nếu muốn dùng endpoint này
#         # from .db_utils import get_all_citizens_db
#         all_db_records = get_all_citizens_db() 
#     except NameError: 
#         raise HTTPException(status_code=501, detail="Chức năng list_all_citizens chưa được triển khai đầy đủ trong db_utils.")
#     except AttributeError: # Nếu get_all_citizens_db không được import
#          raise HTTPException(status_code=501, detail="Chức năng list_all_citizens chưa được import từ db_utils.")
    
#     citizens_display_list = []
#     for record in all_db_records:
#         try:
#             hashed_id = record["hashed_citizen_id"]
#             nonce_h = record["aes_gcm_nonce_hex"]
#             ct_tag_h = record["encrypted_data_with_tag_hex"]
#             kyber_ct_h = record["kyber_ciphertext_c_hex"]
#             sig_h = record["record_signature_hex"]

#             msg_to_verify_str = f"{hashed_id}|{nonce_h}|{ct_tag_h}|{kyber_ct_h}"
#             msg_to_verify_bytes = msg_to_verify_str.encode('utf-8')
#             sig_bytes = bytes.fromhex(sig_h)
            
#             if not oqs_signature_verify(ADMIN_DILITHIUM_PUBLIC_KEY, msg_to_verify_bytes, sig_bytes, DILITHIUM_ALG_NAME):
#                 print(f"DEBUG list_all: Signature FAILED for hashed_id {hashed_id}")
#                 continue 

#             kyber_ct_bytes = bytes.fromhex(kyber_ct_h)
#             aes_key = oqs_kem_decapsulate(ADMIN_KYBER_SECRET_KEY, kyber_ct_bytes, KYBER_ALG_NAME)

#             nonce_bytes = bytes.fromhex(nonce_h)
#             ct_tag_bytes = bytes.fromhex(ct_tag_h)
#             aad_bytes_verify = hashed_id.encode('utf-8') 

#             decrypted_bytes = aes_gcm_decrypt(aes_key, nonce_bytes, ct_tag_bytes, associated_data=aad_bytes_verify)
#             citizen_info_dict = json.loads(decrypted_bytes.decode('utf-8'))
#             citizens_display_list.append(CitizenDisplay(**citizen_info_dict))
#         except Exception as e:
#             print(f"Lỗi khi giải mã bản ghi (hashed_id: {record.get('hashed_citizen_id')}) trong list_all_citizens: {e}")
#             continue 
#     return citizens_display_list