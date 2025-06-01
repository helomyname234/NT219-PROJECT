from fastapi import FastAPI, HTTPException, status
import json # Để chuyển đổi dict thành chuỗi JSON trước khi mã hóa AES
# Import các Pydantic models từ app.model
from .model import CitizenBase, CitizenCreate, CitizenDisplay, MessageResponse 

# Import các hàm tiện ích database từ app.db_utils
from .db_utils import init_db, add_citizen_record_db, get_citizen_record_db

# Import các hàm mã hóa từ app.oqs_utils
from .oqs_utils import generate_aes_key, aes_encrypt, aes_decrypt # Chỉ import phần AES cho bước này

# Khởi tạo ứng dụng FastAPI
app = FastAPI(
    title="Citizen Information API (LBC Demo)",
    description="API mô phỏng hệ thống tra cứu thông tin công dân sử dụng LBC (giai đoạn 2, tích hợp AES).",
    version="0.1.1", # Tăng phiên bản
)

# --- Sự kiện Startup ---
@app.on_event("startup")
async def startup_event():
    print("Application startup: Initializing database...")
    init_db()
    # Khi tích hợp OQS, sẽ gọi initialize_system_keys() ở đây
    print("Database initialization complete.")

# --- API Endpoints ---

@app.get("/", response_model=MessageResponse, tags=["General"])
async def read_root():
    return {"message": "Chào mừng đến với API Hệ thống Thông tin Công dân (LBC Demo - AES Integrated)"}

@app.post("/register", response_model=CitizenDisplay, status_code=status.HTTP_201_CREATED, tags=["Citizens"])
async def register_new_citizen(citizen_data: CitizenCreate):
    print(f"Attempting to register citizen_id: {citizen_data.citizen_id} with AES encryption.")
    try:
        citizen_dict = citizen_data.model_dump() # Pydantic V2+
        # citizen_dict = citizen_data.dict() # Pydantic V1
        
        # 1. Chuyển dữ liệu công dân (dictionary) thành chuỗi JSON, rồi thành bytes để mã hóa
        citizen_data_plaintext_str = json.dumps(citizen_dict)
        citizen_data_plaintext_bytes = citizen_data_plaintext_str.encode('utf-8')

        # 2. Tạo khóa AES ngẫu nhiên cho bản ghi này
        record_aes_key = generate_aes_key()

        # 3. Mã hóa dữ liệu công dân (dạng bytes) bằng khóa AES này
        encrypted_citizen_data_blob = aes_encrypt(record_aes_key, citizen_data_plaintext_bytes)

        # 4. Lưu vào DB:
        #    - encrypted_data_hex: dữ liệu đã mã hóa AES (dạng hex)
        #    - kyber_ciphertext_c_hex: TẠM THỜI lưu record_aes_key (dạng hex) ở đây
        add_citizen_record_db(
            citizen_id=citizen_data.citizen_id,
            encrypted_data_hex=encrypted_citizen_data_blob.hex(), # Lưu blob (IV + ciphertext)
            kyber_ciphertext_c_hex=record_aes_key.hex() # LƯU Ý AN NINH: CHỈ LÀM CHO BƯỚC NÀY
        )
        
        # Trả về thông tin công dân vừa tạo (dữ liệu gốc trước khi mã hóa)
        return CitizenDisplay(**citizen_dict)
    
    except ValueError as ve: 
        print(f"ValueError during registration: {ve}")
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(ve))
    except Exception as e:
        print(f"Unexpected error during registration: {e}")
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="An internal server error occurred during registration.")

@app.get("/lookup/{citizen_id}", response_model=CitizenDisplay, tags=["Citizens"])
async def lookup_citizen_info(citizen_id: str):
    print(f"Attempting to lookup citizen_id: {citizen_id} with AES decryption.")
    record_from_db = get_citizen_record_db(citizen_id)
    
    if record_from_db is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Citizen with ID '{citizen_id}' not found.")
    
    try:
        # Lấy dữ liệu mã hóa và khóa AES (đang được lưu tạm trong 'kyber_ciphertext_c_hex')
        encrypted_data_blob_hex = record_from_db["encrypted_data_hex"]
        stored_aes_key_hex = record_from_db["kyber_ciphertext_c_hex"] # Khóa AES lưu tạm

        encrypted_data_blob = bytes.fromhex(encrypted_data_blob_hex)
        retrieved_aes_key = bytes.fromhex(stored_aes_key_hex)

        # Giải mã dữ liệu công dân bằng khóa AES vừa lấy được
        decrypted_citizen_data_bytes = aes_decrypt(retrieved_aes_key, encrypted_data_blob)
        decrypted_citizen_data_str = decrypted_citizen_data_bytes.decode('utf-8')
        
        # Chuyển chuỗi JSON đã giải mã thành dictionary Python
        citizen_info_dict = json.loads(decrypted_citizen_data_str)
        
        return CitizenDisplay(**citizen_info_dict)

    except ValueError as ve: # Có thể là lỗi giải mã AES (khóa sai, data hỏng)
        print(f"ValueError during AES decryption for {citizen_id}: {ve}")
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"Could not decrypt data for citizen {citizen_id}. Data might be corrupted or key is incorrect.")
    except Exception as e:
        print(f"Unexpected error during lookup for {citizen_id}: {e}")
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="An internal server error occurred during lookup.")

# Bạn có thể giữ lại endpoint /citizens (nếu có) để debug, nhưng nhớ cập nhật logic giải mã tương tự.