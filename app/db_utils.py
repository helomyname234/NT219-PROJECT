import sqlite3
import os
from typing import Optional, Dict, Any, List
import hashlib # Cần thiết nếu bạn muốn chạy self-test với hàm hash

# Tên file database
DB_FILE_PATH = "citizens.db"

def get_db_connection() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_FILE_PATH, timeout=10.0) # Thêm timeout
    conn.row_factory = sqlite3.Row
    return conn

def init_db() -> None:
    db_existed_before_init = os.path.exists(DB_FILE_PATH)
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS citizens (
                hashed_citizen_id TEXT PRIMARY KEY,      -- SẼ LƯU HASH CỦA CITIZEN_ID
                aes_gcm_nonce_hex TEXT NOT NULL,
                encrypted_data_with_tag_hex TEXT NOT NULL, 
                kyber_ciphertext_c_hex TEXT NOT NULL,
                record_signature_hex TEXT NOT NULL     -- CHỮ KÝ DILITHIUM CỦA TOÀN BỘ BẢN GHI
            );
        """)
        conn.commit()
        
        # Kích hoạt WAL mode
        try:
            cursor.execute("PRAGMA journal_mode=WAL;")
            current_journal_mode = cursor.fetchone()
            if current_journal_mode and current_journal_mode[0].lower() == 'wal':
                print("WAL mode enabled for the database.")
            else: # Thử lại nếu lần đầu không thành công ngay
                conn.close() 
                conn = sqlite3.connect(DB_FILE_PATH, timeout=10.0)
                conn.row_factory = sqlite3.Row
                cursor = conn.cursor()
                cursor.execute("PRAGMA journal_mode=WAL;")
                conn.commit()
                cursor.execute("PRAGMA journal_mode;")
                current_journal_mode = cursor.fetchone()
                if current_journal_mode and current_journal_mode[0].lower() == 'wal':
                    print("WAL mode enabled successfully after re-connect.")
                else:
                    print(f"Failed to enable WAL mode. Current mode: {current_journal_mode[0] if current_journal_mode else 'Unknown'}")
            conn.commit()
        except sqlite3.Error as e_wal:
            print(f"SQLite error while trying to enable WAL mode: {e_wal}")

        if not db_existed_before_init:
            print(f"Database file '{DB_FILE_PATH}' created.")
        print("Table 'citizens' (with hashed_id and Dilithium signature field) is ready.")
    except sqlite3.Error as e:
        print(f"SQLite error during table creation: {e}")
    finally:
        if conn:
            conn.close()

def add_citizen_record_db(
    hashed_citizen_id: str, 
    aes_gcm_nonce_hex: str, 
    encrypted_data_with_tag_hex: str, 
    kyber_ciphertext_c_hex: str,
    record_signature_hex: str  # << THÊM THAM SỐ MỚI CHO CHỮ KÝ
) -> None:
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        cursor.execute("""
            INSERT INTO citizens (
                hashed_citizen_id, aes_gcm_nonce_hex, encrypted_data_with_tag_hex, 
                kyber_ciphertext_c_hex, record_signature_hex  -- << THÊM CỘT MỚI
            )
            VALUES (?, ?, ?, ?, ?) -- << 5 placeholders
        """, (
            hashed_citizen_id, aes_gcm_nonce_hex, encrypted_data_with_tag_hex, 
            kyber_ciphertext_c_hex, record_signature_hex # << THÊM GIÁ TRỊ MỚI
            ))
        conn.commit()
        print(f"Record for hashed_citizen_id '{hashed_citizen_id}' (Signed) added.")
    except sqlite3.IntegrityError: 
        print(f"Error: Hashed Citizen ID '{hashed_citizen_id}' already exists.")
        raise ValueError(f"Hashed Citizen ID {hashed_citizen_id} already exists.")
    except sqlite3.Error as e:
        print(f"SQLite error during record insertion: {e}")
        raise
    finally:
        conn.close()

def get_citizen_record_db(hashed_citizen_id: str) -> Optional[Dict[str, Any]]:
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        cursor.execute("""
            SELECT hashed_citizen_id, aes_gcm_nonce_hex, encrypted_data_with_tag_hex, 
                   kyber_ciphertext_c_hex, record_signature_hex -- << LẤY THÊM CỘT CHỮ KÝ
            FROM citizens 
            WHERE hashed_citizen_id = ? 
        """, (hashed_citizen_id,))
        row = cursor.fetchone()
        if row:
            return dict(row) 
        return None
    except sqlite3.Error as e:
        print(f"SQLite error during record retrieval: {e}")
        return None 
    finally:
        conn.close()

if __name__ == '__main__':
    print("Running DB Utils self-test (Hashed ID & Signature version)...")
    
    # Hàm hash tạm thời để test, trong thực tế sẽ import từ oqs_utils
    def local_test_hash(data_str: str) -> str:
        return hashlib.sha256(data_str.encode('utf-8')).hexdigest()

    if os.path.exists(DB_FILE_PATH):
        print(f"Removing existing database '{DB_FILE_PATH}' for fresh test.")
        os.remove(DB_FILE_PATH)
    init_db()
    
    hashed_id1 = local_test_hash("CITIZEN_DB_TEST_001")
    hashed_id2 = local_test_hash("CITIZEN_DB_TEST_002")

    try:
        add_citizen_record_db(hashed_id1, "nonce_h1", "enc_data_h1", "kyber_ct_h1", "sig_h1")
        add_citizen_record_db(hashed_id2, "nonce_h2", "enc_data_h2", "kyber_ct_h2", "sig_h2")
        print("Self-test: Added initial records.")
    except ValueError as e:
        print(f"Self-test add error: {e}")

    record1 = get_citizen_record_db(hashed_id1)
    if record1:
        print("Retrieved by hashed_id1:", record1)
        assert record1["aes_gcm_nonce_hex"] == "nonce_h1"
        assert record1["record_signature_hex"] == "sig_h1"
    else:
        print(f"{hashed_id1} not found during self-test retrieve. ERROR.")

    record_non_existent = get_citizen_record_db(local_test_hash("NONEXISTENT"))
    assert record_non_existent is None
    print("Self-test: Retrieval of non-existent record OK.")

    try:
        add_citizen_record_db(hashed_id1, "nonce_h3", "enc_data_h3", "kyber_ct_h3", "sig_h3")
        print("Self-test: Added duplicate record - FAILED (should have raised error).")
    except ValueError as e:
        print(f"Self-test: Attempt to add duplicate Hashed ID raised ValueError as expected: {e}")
    
    print("DB Utils self-test (Hashed ID & Signature version) finished.")