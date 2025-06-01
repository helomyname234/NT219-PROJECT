from fastapi import FastAPI, HTTPException, status
import json
import os 
from typing import Optional, List # Import List nếu bạn dùng endpoint /citizens

# Import các Pydantic models từ app.model
from .model import CitizenBase, CitizenCreate, CitizenDisplay, MessageResponse 

# Import các hàm tiện ích database từ app.db_utils
from .db_utils import init_db, add_citizen_record_db, get_citizen_record_db
# from .db_utils import get_all_citizens_db # Bỏ comment nếu bạn viết và dùng hàm này

# Import các hàm mã hóa từ app.oqs_utils
from .oqs_utils import (
    initialize_system_keys,
    load_key_from_file, 
    oqs_kem_encapsulate, oqs_kem_decapsulate,
    aes_gcm_encrypt, aes_gcm_decrypt, # Đã cập nhật sang AES-GCM
    KYBER_ALG_NAME, KEY_DIR, ADMIN_KYBER_PK_FILENAME, ADMIN_KYBER_SK_FILENAME
)
import oqs # Import oqs để bắt MechanismNotSupportedError nếu cần

# Khởi tạo ứng dụng FastAPI
app = FastAPI(
    title="Citizen Information API (LBC Demo)",
    description="API mô phỏng hệ thống tra cứu thông tin công dân sử dụng Kyber KEM để bảo vệ khóa AES (sử dụng AES-GCM).",
    version="0.3.0", # Tăng phiên bản để phản ánh việc dùng AES-GCM
)

# --- Biến toàn cục cho khóa admin (tải một lần khi khởi động) ---
ADMIN_KYBER_PUBLIC_KEY: Optional[bytes] = None
ADMIN_KYBER_SECRET_KEY: Optional[bytes] = None

# --- Sự kiện Startup ---
@app.on_event("startup")
async def startup_event():
    global ADMIN_KYBER_PUBLIC_KEY, ADMIN_KYBER_SECRET_KEY
    print("Application startup: Initializing database and loading/creating system keys...")
    init_db() # Đảm bảo DB và bảng đã sẵn sàng với cấu trúc mới
    initialize_system_keys() 

    pk_path = os.path.join(KEY_DIR, ADMIN_KYBER_PK_FILENAME)
    sk_path = os.path.join(KEY_DIR, ADMIN_KYBER_SK_FILENAME)
    
    ADMIN_KYBER_PUBLIC_KEY = load_key_from_file(pk_path)
    ADMIN_KYBER_SECRET_KEY = load_key_from_file(sk_path)

    if not ADMIN_KYBER_PUBLIC_KEY or not ADMIN_KYBER_SECRET_KEY:
        print("LỖI NGHIÊM TRỌNG: Không thể tải khóa Kyber của Admin khi khởi động ứng dụng.")
        raise SystemExit("Không thể tải khóa hệ thống cần thiết. Ứng dụng dừng lại.")
    
    print("Database and System keys initialization complete. Admin keys loaded.")

# --- API Endpoints ---
@app.get("/", response_model=MessageResponse, tags=["General"])
async def read_root():
    return {"message": "Chào mừng đến với API Hệ thống Thông tin Công dân (Kyber KEM + AES-GCM)"}

@app.post("/register", response_model=CitizenDisplay, status_code=status.HTTP_201_CREATED, tags=["Citizens"])
async def register_new_citizen(citizen_data: CitizenCreate):
    global ADMIN_KYBER_PUBLIC_KEY
    if not ADMIN_KYBER_PUBLIC_KEY:
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail="Hệ thống chưa sẵn sàng, không tìm thấy khóa công khai admin.")

    print(f"Attempting to register citizen_id: {citizen_data.citizen_id} with Kyber KEM + AES-GCM.")
    try:
        citizen_dict = citizen_data.model_dump()
        citizen_data_plaintext_str = json.dumps(citizen_dict)
        citizen_data_plaintext_bytes = citizen_data_plaintext_str.encode('utf-8')

        # 1. Đóng gói (KEM) để tạo khóa AES (shared_secret_k) và bản mã Kyber của nó (kyber_ciphertext_c)
        #    sử dụng khóa công khai Kyber của Admin.
        kyber_ciphertext_c_for_aes_key, record_specific_aes_key = oqs_kem_encapsulate(
            ADMIN_KYBER_PUBLIC_KEY, KYBER_ALG_NAME
        )
        # record_specific_aes_key là khóa AES sẽ dùng, được tạo an toàn từ KEM.

        # 2. Mã hóa dữ liệu công dân bằng khóa AES (record_specific_aes_key) vừa được tạo bằng AES-GCM
        # aes_gcm_encrypt sẽ trả về (nonce, ciphertext_bao_gom_tag)
        # (Tùy chọn: có thể thêm associated_data, ví dụ citizen_id dạng bytes)
        # associated_auth_data = citizen_data.citizen_id.encode('utf-8')
        nonce, ciphertext_with_tag = aes_gcm_encrypt(
            record_specific_aes_key, 
            citizen_data_plaintext_bytes
            # associated_data=associated_auth_data # Bỏ comment nếu bạn dùng
        )

        # 3. Lưu vào DB:
        add_citizen_record_db(
            citizen_id=citizen_data.citizen_id,
            aes_gcm_nonce_hex=nonce.hex(),                         # Lưu nonce dạng hex
            encrypted_data_with_tag_hex=ciphertext_with_tag.hex(), # Lưu ciphertext+tag dạng hex
            kyber_ciphertext_c_hex=kyber_ciphertext_c_for_aes_key.hex()
        )
        
        # Trả về thông tin công dân gốc (trước khi mã hóa)
        return CitizenDisplay(**citizen_dict)
    
    except ValueError as ve: # Có thể là lỗi từ add_citizen_record_db (trùng ID) hoặc từ aes_gcm_encrypt
        print(f"ValueError during registration: {ve}")
        # Phân biệt lỗi nếu cần (ví dụ: lỗi từ AES khác với lỗi trùng ID)
        if "already exists" in str(ve):
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(ve))
        else: # Lỗi khác, có thể là từ mã hóa
            raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"Lỗi xử lý dữ liệu: {ve}")
    except oqs.MechanismNotSupportedError as oqs_err:
        print(f"OQS Error during registration: {oqs_err}")
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Lỗi OQS: Thuật toán không được hỗ trợ.")
    except Exception as e:
        print(f"Unexpected error during registration: {e}")
        import traceback
        traceback.print_exc() # In chi tiết lỗi cho debug
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Lỗi không xác định trong quá trình đăng ký.")


@app.get("/lookup/{citizen_id}", response_model=CitizenDisplay, tags=["Citizens"])
async def lookup_citizen_info(citizen_id: str):
    global ADMIN_KYBER_SECRET_KEY
    if not ADMIN_KYBER_SECRET_KEY:
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail="Hệ thống chưa sẵn sàng, không tìm thấy khóa bí mật admin.")

    print(f"Attempting to lookup citizen_id: {citizen_id} with Kyber KEM + AES-GCM decryption.")
    record_from_db = get_citizen_record_db(citizen_id)
    
    if record_from_db is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Citizen with ID '{citizen_id}' not found.")
    
    try:
        # Lấy các giá trị từ DB
        aes_gcm_nonce_hex = record_from_db["aes_gcm_nonce_hex"]
        encrypted_data_with_tag_hex = record_from_db["encrypted_data_with_tag_hex"]
        kyber_ciphertext_c_hex = record_from_db["kyber_ciphertext_c_hex"] # Bản mã Kyber của khóa AES

        # Chuyển từ hex về bytes
        aes_gcm_nonce = bytes.fromhex(aes_gcm_nonce_hex)
        encrypted_data_with_tag = bytes.fromhex(encrypted_data_with_tag_hex)
        kyber_ciphertext_c = bytes.fromhex(kyber_ciphertext_c_hex)

        # 1. Mở gói bản mã Kyber (kyber_ciphertext_c) để lấy lại khóa AES
        #    sử dụng khóa bí mật Kyber của Admin.
        retrieved_aes_key = oqs_kem_decapsulate(
            ADMIN_KYBER_SECRET_KEY, kyber_ciphertext_c, KYBER_ALG_NAME
        )

        # 2. Giải mã dữ liệu công dân bằng khóa AES và nonce, ciphertext_with_tag (AES-GCM)
        # (Tùy chọn: nếu có associated_data khi mã hóa, phải dùng lại ở đây)
        # associated_auth_data_verify = citizen_id.encode('utf-8')
        decrypted_citizen_data_bytes = aes_gcm_decrypt(
            retrieved_aes_key, 
            aes_gcm_nonce, 
            encrypted_data_with_tag
            # associated_data=associated_auth_data_verify # Bỏ comment nếu bạn dùng
        )
        decrypted_citizen_data_str = decrypted_citizen_data_bytes.decode('utf-8')
        citizen_info_dict = json.loads(decrypted_citizen_data_str)
        
        return CitizenDisplay(**citizen_info_dict)

    except ValueError as ve: # Sẽ bắt cả lỗi từ oqs_kem_decapsulate (nếu raise ValueError) và aes_gcm_decrypt (ví dụ InvalidTag)
        print(f"ValueError during decryption process for {citizen_id}: {ve}")
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"Không thể giải mã dữ liệu cho công dân {citizen_id}. Dữ liệu, tag, nonce hoặc bản mã khóa có thể bị hỏng/sửa đổi, hoặc khóa admin sai.")
    except oqs.MechanismNotSupportedError as oqs_err:
        print(f"OQS Error during lookup: {oqs_err}")
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Lỗi OQS: Thuật toán không được hỗ trợ.")
    except Exception as e:
        print(f"Unexpected error during lookup for {citizen_id}: {e}")
        import traceback
        traceback.print_exc()
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Lỗi không xác định trong quá trình tra cứu.")

# --- (Tùy chọn) Endpoint để xem tất cả công dân (cập nhật cho AES-GCM) ---
# @app.get("/citizens", response_model=List[CitizenDisplay], tags=["Citizens"])
# async def list_all_citizens_debug():
#     """
#     Lấy danh sách tất cả công dân (CHỈ DÙNG CHO DEBUG - cần giải mã từng cái).
#     CẢNH BÁO: Endpoint này không an toàn và tốn hiệu năng nếu DB lớn.
#     """
#     global ADMIN_KYBER_SECRET_KEY
#     if not ADMIN_KYBER_SECRET_KEY:
#         raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail="Hệ thống chưa sẵn sàng (thiếu SK).")

#     all_db_records = get_all_citizens_db() # Bạn cần viết/sửa hàm này trong db_utils.py
#     citizens_display_list = []
#     for record in all_db_records:
#         try:
#             aes_gcm_nonce = bytes.fromhex(record["aes_gcm_nonce_hex"])
#             encrypted_data_with_tag = bytes.fromhex(record["encrypted_data_with_tag_hex"])
#             kyber_ciphertext_c = bytes.fromhex(record["kyber_ciphertext_c_hex"])
#             citizen_id_for_aad = record["citizen_id"] # Để dùng cho AAD nếu có

#             retrieved_aes_key = oqs_kem_decapsulate(
#                 ADMIN_KYBER_SECRET_KEY, kyber_ciphertext_c, KYBER_ALG_NAME
#             )
#             # associated_auth_data_verify_all = citizen_id_for_aad.encode('utf-8')
#             decrypted_bytes = aes_gcm_decrypt(
#                 retrieved_aes_key, 
#                 aes_gcm_nonce, 
#                 encrypted_data_with_tag
#                 # associated_data=associated_auth_data_verify_all
#             )
#             citizen_info_dict = json.loads(decrypted_bytes.decode('utf-8'))
#             citizens_display_list.append(CitizenDisplay(**citizen_info_dict))
#         except Exception as e:
#             print(f"Lỗi khi giải mã bản ghi {record.get('citizen_id')} trong list_all_citizens: {e}")
#             # Bỏ qua bản ghi không giải mã được khi debug
#             continue 
#     return citizens_display_list