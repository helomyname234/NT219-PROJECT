import sqlite3
import os
from typing import Optional, Dict, Any # Để type hinting rõ ràng hơn

# Tên file database, bạn có thể đặt ở một file config riêng nếu muốn
DB_FILE_PATH = "citizens.db" # File này sẽ được tạo ở thư mục gốc của dự án

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
    Khởi tạo database: Tạo bảng 'citizens' nếu nó chưa tồn tại.
    """
    if os.path.exists(DB_FILE_PATH):
        print(f"Database file '{DB_FILE_PATH}' already exists. Skipping table creation.")
        # Tuy nhiên, bạn có thể muốn kiểm tra xem bảng đã tồn tại chưa, 
        # thay vì chỉ kiểm tra file. Nhưng cho đồ án này, kiểm tra file là đủ.
        # conn_check = get_db_connection()
        # cursor_check = conn_check.cursor()
        # cursor_check.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='citizens';")
        # table_exists = cursor_check.fetchone()
        # conn_check.close()
        # if table_exists:
        #     print("Table 'citizens' already exists.")
        #     return
    else:
        print(f"Database file '{DB_FILE_PATH}' not found. Creating new database and table.")

    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS citizens (
                citizen_id TEXT PRIMARY KEY,
                encrypted_data_hex TEXT NOT NULL,
                kyber_ciphertext_c_hex TEXT NOT NULL 
                -- kyber_ciphertext_c_hex: bản mã Kyber của khóa AES dùng để mã hóa encrypted_data_hex
            );
        """)
        conn.commit()
        print("Table 'citizens' created or already exists.")
    except sqlite3.Error as e:
        print(f"SQLite error during table creation: {e}")
    finally:
        conn.close()

def add_citizen_record_db(citizen_id: str, encrypted_data_hex: str, kyber_ciphertext_c_hex: str) -> None:
    """
    Thêm một bản ghi công dân mới vào database.
    Raise ValueError nếu citizen_id đã tồn tại.
    """
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        cursor.execute("""
            INSERT INTO citizens (citizen_id, encrypted_data_hex, kyber_ciphertext_c_hex)
            VALUES (?, ?, ?)
        """, (citizen_id, encrypted_data_hex, kyber_ciphertext_c_hex))
        conn.commit()
        print(f"Record for citizen_id '{citizen_id}' added to the database.")
    except sqlite3.IntegrityError: # Xảy ra khi PRIMARY KEY (citizen_id) bị trùng
        print(f"Error: Citizen ID '{citizen_id}' already exists in the database.")
        raise ValueError(f"Citizen ID {citizen_id} already exists.")
    except sqlite3.Error as e:
        print(f"SQLite error during record insertion: {e}")
        # Bạn có thể muốn raise một exception khác ở đây tùy theo cách xử lý lỗi
        raise
    finally:
        conn.close()

def get_citizen_record_db(citizen_id: str) -> Optional[Dict[str, Any]]:
    """
    Lấy thông tin bản ghi của một công dân dựa trên citizen_id.
    Trả về một dictionary nếu tìm thấy, ngược lại trả về None.
    """
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        cursor.execute("""
            SELECT citizen_id, encrypted_data_hex, kyber_ciphertext_c_hex 
            FROM citizens 
            WHERE citizen_id = ?
        """, (citizen_id,))
        row = cursor.fetchone() # Lấy một dòng kết quả
        
        if row:
            print(f"Record found for citizen_id '{citizen_id}'.")
            return dict(row) # Chuyển sqlite3.Row thành một dictionary Python tiêu chuẩn
        else:
            print(f"No record found for citizen_id '{citizen_id}'.")
            return None
    except sqlite3.Error as e:
        print(f"SQLite error during record retrieval: {e}")
        return None # Hoặc raise exception
    finally:
        conn.close()

# --- (Tùy chọn) Các hàm khác bạn có thể cần sau này ---
# def update_citizen_record_db(citizen_id: str, new_encrypted_data_hex: str, new_kyber_ciphertext_c_hex: str) -> bool:
#     """Cập nhật bản ghi. Trả về True nếu thành công, False nếu không tìm thấy citizen_id."""
#     conn = get_db_connection()
#     cursor = conn.cursor()
#     try:
#         cursor.execute("""
#             UPDATE citizens
#             SET encrypted_data_hex = ?, kyber_ciphertext_c_hex = ?
#             WHERE citizen_id = ?
#         """, (new_encrypted_data_hex, new_kyber_ciphertext_c_hex, citizen_id))
#         conn.commit()
#         if cursor.rowcount > 0: # Kiểm tra xem có dòng nào được cập nhật không
#             print(f"Record for citizen_id '{citizen_id}' updated.")
#             return True
#         else:
#             print(f"No record found for citizen_id '{citizen_id}' to update.")
#             return False
#     except sqlite3.Error as e:
#         print(f"SQLite error during record update: {e}")
#         return False
#     finally:
#         conn.close()

# def delete_citizen_record_db(citizen_id: str) -> bool:
#     """Xóa bản ghi. Trả về True nếu thành công, False nếu không tìm thấy citizen_id."""
#     conn = get_db_connection()
#     cursor = conn.cursor()
#     try:
#         cursor.execute("DELETE FROM citizens WHERE citizen_id = ?", (citizen_id,))
#         conn.commit()
#         if cursor.rowcount > 0:
#             print(f"Record for citizen_id '{citizen_id}' deleted.")
#             return True
#         else:
#             print(f"No record found for citizen_id '{citizen_id}' to delete.")
#             return False
#     except sqlite3.Error as e:
#         print(f"SQLite error during record deletion: {e}")
#         return False
#     finally:
#         conn.close()

if __name__ == '__main__':
    # Phần này để bạn chạy test nhanh các hàm DB (không phải unit test đầy đủ)
    # Sẽ tạo file citizens.db ở thư mục hiện tại nếu bạn chạy file này trực tiếp
    print("Running DB Utils self-test...")
    init_db()

    # Test thêm dữ liệu
    try:
        add_citizen_record_db("TEST001", "encrypted_data_example_hex_1", "kyber_ciphertext_example_hex_1")
        add_citizen_record_db("TEST002", "encrypted_data_example_hex_2", "kyber_ciphertext_example_hex_2")
    except ValueError as e:
        print(f"Self-test add error (expected if run multiple times): {e}")


    # Test lấy dữ liệu
    record1 = get_citizen_record_db("TEST001")
    if record1:
        print("Retrieved TEST001:", record1)
        assert record1["encrypted_data_hex"] == "encrypted_data_example_hex_1"
    else:
        print("TEST001 not found during self-test retrieve.")

    record_non_existent = get_citizen_record_db("NONEXISTENT")
    assert record_non_existent is None

    # (Tùy chọn) Test update và delete nếu bạn đã implement
    # success_update = update_citizen_record_db("TEST001", "new_encrypted_hex", "new_kyber_hex")
    # if success_update:
    #     updated_record1 = get_citizen_record_db("TEST001")
    #     print("Updated TEST001:", updated_record1)
    #     assert updated_record1["encrypted_data_hex"] == "new_encrypted_hex"

    # success_delete = delete_citizen_record_db("TEST002")
    # assert success_delete
    # deleted_record2 = get_citizen_record_db("TEST002")
    # assert deleted_record2 is None
    # print("Record TEST002 successfully deleted.")

    print("DB Utils self-test finished.")
    # Khi test xong, bạn có thể muốn xóa file citizens.db để lần sau test lại từ đầu
    # if os.path.exists(DB_FILE_PATH):
    #     os.remove(DB_FILE_PATH)
    #     print(f"'{DB_FILE_PATH}' removed for next test run.")
