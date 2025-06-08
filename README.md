

# Hướng dẫn Cài đặt Toàn diện Dự án NT219-PROJECT trên Ubuntu cho Người Mới

Chào bạn, đây là các bước để thiết lập môi trường và chạy dự án NT219-PROJECT trên máy Ubuntu của bạn.

## A. Cài đặt các Gói Hệ thống Cơ bản:

Trước tiên, chúng ta cần cài đặt một số công cụ và thư viện cần thiết từ trình quản lý gói apt. Mở Terminal và chạy các lệnh sau:

### Cập nhật danh sách gói:
```bash
sudo apt update
```

### Cài đặt các công cụ build, Git, và Python:
```bash
sudo apt install git cmake build-essential python3 python3-venv python3-pip
```

## B. Biên dịch và Cài đặt liboqs (Thư viện C):

liboqs là thư viện C cốt lõi cung cấp các thuật toán mật mã hậu lượng tử.

### Tạo một thư mục để chứa mã nguồn và build liboqs (ví dụ: ~/build_oqs_libs):
```bash
mkdir -p ~/build_oqs_libs
cd ~/build_oqs_libs
```


### Clone mã nguồn liboqs từ GitHub:
```bash
git clone --depth=1 https://github.com/open-quantum-safe/liboqs
```

### Chuẩn bị thư mục build:
```bash
cd liboqs
mkdir build
cd build
```bash

### Cấu hình bản build bằng cmake:
Kích hoạt các thuật toán Kyber và Dilithium.
```bash
cmake .. -DBUILD_SHARED_LIBS=ON \
         -DOQS_ENABLE_KEM_KYBER=ON \
         -DOQS_ENABLE_SIG_DILITHIUM=ON
```bash

Kiểm tra output của cmake để đảm bảo các thuật toán này được "Enabled".

### Biên dịch liboqs:
```bash
make -j$(nproc)
```

### Cài đặt liboqs vào hệ thống:
```bash
sudo make install
```

Cập nhật cache của dynamic linker và cấu hình LD_LIBRARY_PATH:
```bash
sudo ldconfig
echo 'export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:/usr/local/lib' >> ~/.bashrc
source ~/.bashrc
```

(Nếu bạn của bạn dùng shell khác Zsh, họ cần sửa ~/.bashrc thành ~/.zshrc tương ứng).

## C. Clone Dự án NT219-PROJECT và Cài đặt Phụ thuộc Python:

Di chuyển đến thư mục bạn muốn lưu trữ dự án (ví dụ: thư mục nhà):
```bash
cd ~
bash

### Clone Repository NT219-PROJECT (Bao gồm Submodule liboqs-python):
Thay thế URL_REPOSITORY_CUA_BAN bằng URL Git của dự án và TEN_THU_MUC_DU_AN bằng tên thư mục bạn muốn tạo.
```bash
git clone -b develop --recurse-submodules URL_REPOSITORY_CUA_BAN TEN_THU_MUC_DU_AN
cd TEN_THU_MUC_DU_AN
```

### Tạo và Kích hoạt Môi trường ảo Python:
```bash
python3 -m venv venv_app
source venv_app/bin/activate
```

Bạn sẽ thấy (venv_app) ở đầu dòng lệnh.

### Cài đặt liboqs-python Wrapper từ Submodule:
```bash
cd liboqs-python  # Di chuyển vào thư mục submodule
pip install .       # Cài đặt wrapper vào môi trường ảo đang hoạt động
cd ..               # Quay lại thư mục dự án chính
```


### Cài đặt các Gói Python Phụ thuộc Khác (Tường minh):
Với môi trường ảo (venv_app) đã được kích hoạt, chạy các lệnh sau để cài đặt từng gói cần thiết:
```bash
pip install fastapi
pip install "uvicorn[standard]"
pip install cryptography
pip install pydantic
# Thêm các gói khác nếu ứng dụng của bạn có sử dụng (ví dụ: requests, python-jose, passlib)
# Ví dụ:
# pip install requests 
# pip install "python-jose[cryptography]"
# pip install "passlib[bcrypt]"
```
hoac chi can chay 
### pip install -r requirements.txt

Bạn cần liệt kê tất cả các thư viện Python mà dự án của bạn thực sự import và sử dụng ở đây.

# D. Chạy Ứng dụng:

Khởi chạy Server Backend (API):
(Đảm bảo môi trường ảo venv_app vẫn đang được kích hoạt và bạn đang ở thư mục gốc của dự án TEN_THU_MUC_DU_AN)
```bash
uvicorn app.main:app --reload
```
Ứng dụng FastAPI sẽ khởi động. Nó sẽ tự động tạo file database citizens.db và các file khóa trong system_keys/ nếu chúng chưa tồn tại.

Truy cập và Kiểm tra:

Mở trình duyệt web và truy cập http://127.0.0.1:8000/docs.

Thử các chức năng của API.

(Nếu có) Mở file frontend/index.html.

Quan trọng cho bạn:
Bạn nên kiểm tra lại toàn bộ mã nguồn Python của mình (trong thư mục app/ và các file script khác) để xem bạn đã import những thư viện nào. Sau đó, hãy đảm bảo rằng tất cả các thư viện đó (trừ các thư viện chuẩn của Python như os, json, sqlite3, typing) đều được liệt kê trong danh sách các lệnh pip install ở Bước C.5 của hướng dẫn này.

Ví dụ, nếu bạn có import requests ở đâu đó, bạn cần thêm pip install requests vào danh sách.

Cách tốt nhất vẫn là bạn tự tạo file requirements.txt cho chính mình bằng cách:

Kích hoạt môi trường ảo venv_oqs của bạn.

Chạy pip freeze > requirements.txt trong thư mục gốc dự án.

Commit file requirements.txt đó lên GitHub.
Thì người bạn của bạn sẽ chỉ cần chạy pip install -r requirements.txt là đủ.
