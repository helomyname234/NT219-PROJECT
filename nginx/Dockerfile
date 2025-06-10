# Sử dụng image nền có sẵn OpenSSL 3 PQC
FROM openquantumsafe/openssl3

# Sử dụng trình quản lý gói 'apk' của Alpine Linux
# 'add' là lệnh cài đặt, '--no-cache' tương đương với việc dọn dẹp sau khi cài
RUN apk update && apk add --no-cache nginx

# Xóa file cấu hình mặc định để tránh xung đột
# Đường dẫn file mặc định của Nginx trên Alpine hơi khác
RUN rm /etc/nginx/http.d/default.conf

# Sao chép file cấu hình tùy chỉnh của chúng ta vào
COPY nginx.conf /etc/nginx/nginx.conf
COPY openssl.conf /etc/ssl/openssl.cnf

# Chạy Nginx ở foreground
CMD ["nginx", "-g", "daemon off;"]
