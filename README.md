# NT219-PROJECT
Cryptanalysis on Lattice-based Algorithms
# THỰC NGHIỆM
-	Lựa chọn cặp thuật toán: Ví dụ, so sánh Kyber-512 (PQC KEM) với ECDH secp256r1 (Classical KEM) HOẶC so sánh Dilithium-2 (PQC Signature) với ECDSA secp256r1 (Classical Signature).
-	Sử dụng thư viện: Tận dụng thư viện liboqs (thông qua wrapper như oqs-python) cho PQC và thư viện cryptography (Python) hoặc tương đương cho thuật toán cổ điển.
-	Đo lường các chỉ số: Kích thước khóa công khai (bytes), kích thước khóa bí mật (bytes), kích thước bản mã đóng gói/chữ ký (bytes), thời gian trung bình (ms hoặc μs) cho các thao tác: tạo khóa (keygen), đóng gói khóa (encapsulate), mở gói khóa (decapsulate) (đối với KEM); hoặc ký (sign), xác thực (verify) (đối với chữ ký). Thực hiện đo lường nhiều lần để lấy giá trị trung bình.

