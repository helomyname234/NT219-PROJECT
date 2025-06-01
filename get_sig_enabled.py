import oqs
import os
import json
from cryptography.hazmat.primitives.ciphers.aead import AESGCM # Sử dụng AESGCM
from cryptography.exceptions import InvalidTag # Để bắt lỗi tag không hợp lệ
from typing import Optional, Tuple, Any



e = oqs.get_enabled_sig_mechanisms()
print(e)