# NT219-PROJECT: Hệ thống Tra cứu Thông tin Công dân Mô phỏng với Mật mã Hậu Lượng tử

Đây là dự án mô phỏng một hệ thống tra cứu thông tin công dân đơn giản, được bảo vệ bằng các thuật toán mật mã hậu lượng tử từ thư viện Open Quantum Safe (OQS), cụ thể là CRYSTALS-Kyber (cho mã hóa/đóng gói khóa) và có thể là CRYSTALS-Dilithium (cho chữ ký số).

## Mục tiêu

Dự án này nhằm mục đích:
*   Minh họa việc tích hợp các thuật toán Mật mã dựa trên Lưới (LBC) vào một ứng dụng web đơn giản với backend API.
*   Tạo một môi trường cụ thể để thực hiện các thử nghiệm tấn công cổ điển (ví dụ: tấn công giảm cơ sở) nhắm vào các thành phần LBC.
*   Cung cấp cơ sở để thảo luận và đánh giá sơ bộ về các khía cạnh an toàn và hiệu suất của các thuật toán LBC trong một kịch bản ứng dụng giả định.

## Công nghệ sử dụng

*   **Backend:** Python với FastAPI
*   **Mật mã:**
    *   `liboqs` (Thư viện C cho thuật toán PQC)
    *   `liboqs-python` (Python wrapper cho `liboqs` - được cài đặt như một phần phụ thuộc, không commit mã nguồn vào repo này)
    *   `cryptography` (Thư viện Python cho mã hóa đối xứng AES)
*   **Database:** SQLite
*   **Frontend (Minh họa đơn giản):** HTML, CSS, JavaScript (giao tiếp với API backend)

## Chuẩn bị Môi trường (Ubuntu)

Trước khi bắt đầu, hãy đảm bảo bạn đã cài đặt các gói điều kiện tiên quyết trên hệ thống Ubuntu của mình:

```bash
sudo apt update
sudo apt install git cmake build-essential python3 python3-venv python3-pip
```
### Hướng dẫn Cài đặt và Chạy dự án từ nhánh develop
1. Clone Dự án từ Nhánh develop

```bash      
git clone -b develop https://github.com/helomyname234/NT219-PROJECT.git
cd NT219-PROJECT
```
(Thay helomyname234/NT219-PROJECT.git bằng URL repository của bạn nếu khác).
2. Cài đặt liboqs (Thư viện C)
Hệ thống này yêu cầu thư viện liboqs gốc được biên dịch và cài đặt với các thuật toán Kyber và Dilithium (nếu sử dụng) đã được kích hoạt.
# Tạo một thư mục riêng để build liboqs (bên ngoài thư mục dự án này)
mkdir -p ~/build_libs && cd ~/build_libs

# Clone và build liboqs
```bash
git clone --depth=1 https://github.com/open-quantum-safe/liboqs
cd liboqs
mkdir build && cd build

# Cấu hình cmake, đảm bảo KEM_KYBER và SIG_DILITHIUM được bật
cmake .. -DBUILD_SHARED_LIBS=ON \
         -DOQS_ENABLE_KEM_KYBER=ON \
         -DOQS_ENABLE_SIG_DILITHIUM=ON # Bật Dilithium nếu bạn dự định sử dụng
# Biên dịch (thay $(nproc) bằng số core CPU của bạn nếu hệ thống không hiểu)
make -j$(nproc)
# Cài đặt vào hệ thống
sudo make install

# Cập nhật linker cache và LD_LIBRARY_PATH
sudo ldconfig
echo 'export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:/usr/local/lib' >> ~/.bashrc # Hoặc ~/.zshrc
source ~/.bashrc # Hoặc source ~/.zshrc

# Quay lại thư mục dự án NT219-PROJECT
cd /path/to/your/NT219-PROJECT # Thay bằng đường dẫn thực tế


```
Lưu ý: Nếu bạn gặp lỗi MechanismNotSupportedError khi chạy ứng dụng sau này, có thể là do các thuật toán cần thiết chưa được bật đúng cách khi biên dịch liboqs. Hãy kiểm tra lại cờ CMake.
3. Thiết lập Môi trường ảo Python và Cài đặt các Phụ thuộc

Từ thư mục gốc của dự án NT219-PROJECT:

      
# Tạo môi trường ảo
python3 -m venv venv_oqs
# Kích hoạt môi trường ảo
source venv_oqs/bin/activate

# Cài đặt liboqs-python wrapper (sẽ sử dụng liboqs đã cài ở bước 2)
pip install oqs 

# Cài đặt các gói Python phụ thuộc khác
pip install fastapi "uvicorn[standard]" cryptography
# Nếu bạn có file requirements.txt, bạn có thể dùng:
# pip install -r requirements.txt


(Lưu ý: liboqs-python khi được cài đặt qua pip install oqs sẽ cố gắng tìm liboqs.so đã được cài đặt trên hệ thống của bạn. Nếu không tìm thấy, nó có thể cố gắng tự build một bản liboqs (điều này cũng được đề cập trong README của liboqs-python như một tùy chọn). Tuy nhiên, việc cài đặt thủ công liboqs như ở Bước 2 cho phép bạn kiểm soát các thuật toán được bật tốt hơn).
4. Khởi tạo Database và Khóa Hệ thống

Ứng dụng sẽ tự động tạo file database SQLite (citizens.db) và các khóa hệ thống cần thiết (trong thư mục system_keys/, thư mục này đã được thêm vào .gitignore) khi chạy lần đầu nếu chúng chưa tồn tại.
5. Chạy Ứng dụng Backend (API Server)
# (Với môi trường ảo venv_oqs đã được kích hoạt)
uvicorn app.main:app --reload

(Giả sử file chính của bạn là app/main.py và instance FastAPI tên là app. Điều chỉnh nếu cần).

Server sẽ thường chạy trên http://127.0.0.1:8000. Bạn có thể truy cập http://127.0.0.1:8000/docs để xem giao diện Swagger UI (tài liệu API tự động) do FastAPI cung cấp.
6. (Tùy chọn) Chạy Frontend Đơn giản

Nếu bạn có một frontend HTML/JS đơn giản để tương tác với API:

    Mở file HTML chính (ví dụ frontend/index.html) trực tiếp bằng trình duyệt.

    Đảm bảo JavaScript trong frontend của bạn gọi đúng các địa chỉ API (ví dụ: http://127.0.0.1:8000/register, http://127.0.0.1:8000/lookup/{id}).

Cấu trúc Thư mục (Đề xuất)

      
NT219-PROJECT/
├── app/                    # Thư mục chứa mã nguồn backend
│   ├── main.py             # File chính của FastAPI, định nghĩa API endpoints
│   ├── oqs_utils.py        # Các hàm tiện ích cho OQS và AES
│   ├── db_utils.py         # Các hàm tiện ích cho SQLite
│   ├── models.py           # (Nếu dùng) Pydantic models cho request/response
│   └── __init__.py
├── frontend/               # (Tùy chọn) Mã nguồn frontend đơn giản
│   ├── index.html
│   ├── script.js
│   └── style.css
├── system_keys/            # (Được .gitignore) Chứa khóa của hệ thống (ví dụ: admin_kyber_*.key)
├── citizens.db             # (Được .gitignore) File database SQLite
├── venv_oqs/               # (Được .gitignore) Môi trường ảo Python
├── .gitignore              # Chỉ định các file/thư mục bị Git bỏ qua
└── README.md               # File hướng dẫn này

    

IGNORE_WHEN_COPYING_START
Use code with caution.
IGNORE_WHEN_COPYING_END
Hướng dẫn Thực hiện Tấn công (Mục đích Nghiên cứu)

Phần này phục vụ cho việc thực hiện các thử nghiệm phân tích an toàn theo mục tiêu của đồ án.

    Thu thập Thông tin:

        Khóa công khai của hệ thống (ví dụ: system_keys/admin_kyber_public.key).

        Dữ liệu đã mã hóa từ database (ví dụ: nội dung file citizens.db, cụ thể là các cột chứa kyber_ciphertext_c_hex và encrypted_data_hex).

    Chuẩn bị Công cụ:

        SageMath hoặc một môi trường Python có các thư viện cần thiết cho đại số tuyến tính và lý thuyết số.

    Thực hiện Tấn công Giảm Cơ sở (Ví dụ: nhắm vào Kyber):

        Viết script (trong SageMath hoặc Python) để:

            Đọc khóa công khai Kyber.

            Chuyển đổi khóa công khai thành dạng ma trận (ví dụ: ma trận A và vector t cho Module-LWE). Đây là bước đòi hỏi hiểu biết về cấu trúc khóa của Kyber.

            Xây dựng lưới (lattice) phù hợp từ các ma trận này.

            Áp dụng các thuật toán giảm cơ sở (LLL, BKZ) để cố gắng tìm khóa bí mật.

    Đánh giá Kết quả:

        Nếu khóa bí mật được khôi phục (khả năng rất thấp với tham số chuẩn), sử dụng nó để thử giải mã dữ liệu trong citizens.db.

        Ghi nhận thời gian, tài nguyên, và các quan sát trong quá trình tấn công.

LƯU Ý QUAN TRỌNG VỀ AN NINH:

    Dự án này được thực hiện với mục đích học tập và nghiên cứu về mật mã hậu lượng tử và các kỹ thuật phân tích cơ bản.

    Không sử dụng các kỹ thuật mã hóa hoặc phương pháp quản lý khóa được trình bày trong dự án này cho các ứng dụng thực tế có yêu cầu bảo mật cao mà không có sự tư vấn và đánh giá chuyên sâu từ các chuyên gia an ninh.

    TUYỆT ĐỐI KHÔNG COMMIT KHÓA BÍ MẬT LÊN REPOSITORY GIT. Sử dụng file .gitignore để loại trừ các file và thư mục nhạy cảm.

Đóng góp

(Điền tên thành viên nếu làm theo nhóm, hoặc để trống).
License

(Ví dụ: MIT License. Bạn có thể chọn một giấy phép phù hợp hoặc để trống nếu là đồ án nội bộ).
