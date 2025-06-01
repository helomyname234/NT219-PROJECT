import sqlite3
import os
from typing import Optional, Dict, Any, List # Thêm List nếu bạn viết hàm get_all_citizens_db

# Tên file database
DB_FILE_PATH = "citizens.db"

def get_db_connection() -> sqlite3.Connection:
    """
    Tạo và trả về một đối tượng kết nối đến database SQLite.
    Kết nối này sẽ cho phép truy cập các cột bằng tên.
    """
    conn = sqlite3.connect(DB_FILE_PATH)
    conn.row_factory = sqlite3.Row # Giúp truy cập kết quả như dictionary (row['column_name'])
    return conn

def init_db() -> None:
    """
    Khởi tạo database: Tạo bảng 'citizens' với các cột cho AES-GCM nếu nó chưa tồn tại.
    """
    db_existed_before_init = os.path.exists(DB_FILE_PATH)
    
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        # Xóa bảng cũ nếu tồn tại và cấu trúc không khớp? 
        # Hoặc chỉ tạo nếu chưa có. Để đơn giản, chúng ta sẽ chỉ tạo nếu chưa có.
        # Nếu bạn muốn đảm bảo cấu trúc mới, bạn có thể DROP TABLE IF EXISTS citizens rồi CREATE lại,
        # nhưng điều đó sẽ xóa hết dữ liệu cũ. Cân nhắc cẩn thận.
        # Vì đây là đồ án và bạn đang phát triển, việc xóa DB cũ (`rm citizens.db`) 
        # trước khi chạy với cấu trúc mới là chấp nhận được.

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS citizens (
                citizen_id TEXT PRIMARY KEY,
                aes_gcm_nonce_hex TEXT NOT NULL,         -- Nonce cho AES-GCM
                encrypted_data_with_tag_hex TEXT NOT NULL, -- Ciphertext + Tag từ AES-GCM
                kyber_ciphertext_c_hex TEXT NOT NULL     -- Bản mã Kyber của khóa AES
            );
        """)
        conn.commit()
        if not db_existed_before_init:
            print(f"Database file '{DB_FILE_PATH}' created.")
        print("Table 'citizens' (with AES-GCM fields) is ready.")
    except sqlite3.Error as e:
        print(f"SQLite error during table creation: {e}")
    finally:
        conn.close()

def add_citizen_record_db(citizen_id: str, aes_gcm_nonce_hex: str, encrypted_data_with_tag_hex: str, kyber_ciphertext_c_hex: str) -> None:
    """
    Thêm một bản ghi công dân mới vào database (đã cập nhật cho AES-GCM).
    Raise ValueError nếu citizen_id đã tồn tại.
    """
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        cursor.execute("""
            INSERT INTO citizens (citizen_id, aes_gcm_nonce_hex, encrypted_data_with_tag_hex, kyber_ciphertext_c_hex)
            VALUES (?, ?, ?, ?)
        """, (citizen_id, aes_gcm_nonce_hex, encrypted_data_with_tag_hex, kyber_ciphertext_c_hex))
        conn.commit()
        print(f"Record for citizen_id '{citizen_id}' (AES-GCM) added to the database.")
    except sqlite3.IntegrityError: 
        print(f"Error: Citizen ID '{citizen_id}' already exists in the database.")
        raise ValueError(f"Citizen ID {citizen_id} already exists.")
    except sqlite3.Error as e:
        print(f"SQLite error during record insertion: {e}")
        raise
    finally:
        conn.close()

def get_citizen_record_db(citizen_id: str) -> Optional[Dict[str, Any]]:
    """
    Lấy thông tin bản ghi của một công dân dựa trên citizen_id (đã cập nhật cho AES-GCM).
    Trả về một dictionary nếu tìm thấy, ngược lại trả về None.
    """
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        cursor.execute("""
            SELECT citizen_id, aes_gcm_nonce_hex, encrypted_data_with_tag_hex, kyber_ciphertext_c_hex 
            FROM citizens 
            WHERE citizen_id = ?
        """, (citizen_id,))
        row = cursor.fetchone()
        
        if row:
            # print(f"Record found for citizen_id '{citizen_id}'.") # Bỏ print để đỡ rối log app
            return dict(row) 
        else:
            # print(f"No record found for citizen_id '{citizen_id}'.")
            return None
    except sqlite3.Error as e:
        print(f"SQLite error during record retrieval: {e}")
        return None 
    finally:
        conn.close()

# --- (Tùy chọn) Hàm lấy tất cả công dân để debug ---
# def get_all_citizens_db() -> List[Dict[str, Any]]:
#     """Lấy tất cả các bản ghi công dân từ database."""
#     conn = get_db_connection()
#     cursor = conn.cursor()
#     try:
#         cursor.execute("""
#             SELECT citizen_id, aes_gcm_nonce_hex, encrypted_data_with_tag_hex, kyber_ciphertext_c_hex 
#             FROM citizens
#         """)
#         rows = cursor.fetchall()
#         return [dict(row) for row in rows]
#     except sqlite3.Error as e:
#         print(f"SQLite error during retrieval of all records: {e}")
#         return []
#     finally:
#         conn.close()


if __name__ == '__main__':
    print("Running DB Utils self-test (AES-GCM version)...")
    
    # Xóa DB cũ để test từ đầu (chỉ khi chạy trực tiếp file này)
    if os.path.exists(DB_FILE_PATH):
        print(f"Removing existing database file '{DB_FILE_PATH}' for fresh test.")
        os.remove(DB_FILE_PATH)
        
    init_db()

    # Test thêm dữ liệu
    try:
        add_citizen_record_db("TESTGCM001", "nonce_hex_1", "encrypted_tag_hex_1", "kyber_cipher_hex_1")
        add_citizen_record_db("TESTGCM002", "nonce_hex_2", "encrypted_tag_hex_2", "kyber_cipher_hex_2")
        print("Self-test: Added initial records.")
    except ValueError as e:
        print(f"Self-test add error (should not happen on fresh DB): {e}")

    # Test lấy dữ liệu
    record1 = get_citizen_record_db("TESTGCM001")
    if record1:
        print("Retrieved TESTGCM001:", record1)
        assert record1["aes_gcm_nonce_hex"] == "nonce_hex_1"
        assert record1["encrypted_data_with_tag_hex"] == "encrypted_tag_hex_1"
    else:
        print("TESTGCM001 not found during self-test retrieve. ERROR.")

    record_non_existent = get_citizen_record_db("NONEXISTENTGCM")
    assert record_non_existent is None
    print("Self-test: Retrieval of non-existent record OK.")

    # Test thêm trùng lặp
    try:
        add_citizen_record_db("TESTGCM001", "nonce_hex_3", "encrypted_tag_hex_3", "kyber_cipher_hex_3")
        print("Self-test: Added duplicate record - FAILED (should have raised error).")
    except ValueError as e:
        print(f"Self-test: Attempt to add duplicate record raised ValueError as expected: {e}")
    
    print("DB Utils self-test (AES-GCM version) finished.")