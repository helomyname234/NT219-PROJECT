import oqs # Thử import thư viện

print("Successfully imported 'oqs' library!")
print("-" * 30)

# Liệt kê các cơ chế KEM được kích hoạt
try:
    enabled_kems = oqs.get_enabled_KEM_mechanisms()
    print("Enabled KEM Mechanisms:")
    for kem_name in enabled_kems:
        print(f"  - {kem_name}")
    # Kiểm tra một KEM cụ thể bạn dự định dùng (ví dụ: Kyber768)
    TARGET_KEM = "Kyber768" # Thay đổi nếu bạn dùng tên KEM khác
    if TARGET_KEM in enabled_kems:
        print(f"\nTest: Attempting to use {TARGET_KEM}...")
        with oqs.KeyEncapsulation(TARGET_KEM) as kem:
            print(f"  Successfully created KEM object for {TARGET_KEM}.")
            public_key = kem.generate_keypair()
            secret_key = kem.export_secret_key()
            print(f"  {TARGET_KEM} public key length: {len(public_key)} bytes")
            print(f"  {TARGET_KEM} secret key length: {len(secret_key)} bytes")
            print(f"  KEM Keypair generation test for {TARGET_KEM} successful!")
    else:
        print(f"\nWarning: {TARGET_KEM} is NOT in the list of enabled KEMs.")
except oqs.MechanismNotSupportedError as e:
    print(f"\nError during KEM test: {e}")
    print("This usually means the KEM algorithm was not enabled during liboqs compilation.")
except Exception as e:
    print(f"\nAn unexpected error occurred during KEM tests: {e}")

print("-" * 30)
# Liệt kê các cơ chế Chữ ký được kích hoạt
try:
    enabled_sigs = oqs.get_enabled_sig_mechanisms()
    print("\nEnabled Signature Mechanisms:")
    for sig_name in enabled_sigs:
        print(f"  - {sig_name}")
    # Kiểm tra một thuật toán chữ ký cụ thể bạn dự định dùng (ví dụ: Dilithium3)
    TARGET_SIG = "Dilithium3" # Thay đổi nếu bạn dùng tên SIG khác
    if TARGET_SIG in enabled_sigs:
        print(f"\nTest: Attempting to use {TARGET_SIG}...")
        with oqs.Signature(TARGET_SIG) as sig:
            print(f"  Successfully created Signature object for {TARGET_SIG}.")
            public_key_sig = sig.generate_keypair()
            secret_key_sig = sig.export_secret_key()
            print(f"  {TARGET_SIG} public key length: {len(public_key_sig)} bytes")
            print(f"  {TARGET_SIG} secret key length: {len(secret_key_sig)} bytes")
            print(f"  Signature Keypair generation test for {TARGET_SIG} successful!")
    else:
        print(f"\nWarning: {TARGET_SIG} is NOT in the list of enabled Signatures.")
except oqs.MechanismNotSupportedError as e:
    print(f"\nError during Signature test: {e}")
    print("This usually means the Signature algorithm was not enabled during liboqs compilation.")
except Exception as e:
    print(f"\nAn unexpected error occurred during Signature tests: {e}")