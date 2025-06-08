import numpy as np
from itertools import product

N = 6
M = 12
Q = 97
ETA = 1

def generate_lwe_instance():
    A = np.random.randint(0, Q, size=(M, N))
    s = np.random.randint(-ETA, ETA + 1, size=(N, 1))
    e = np.random.randint(-ETA, ETA + 1, size=(M, 1))
    t = (A @ s + e) % Q
    return A, t, s

def enumeration_attack(A, t):
    # Tập các giá trị có thể cho mỗi phần tử của s
    possible_values = [-ETA, 0, ETA]

    candidates = product(possible_values, repeat=N)

    for idx, s_candidate in enumerate(candidates):
        s_candidate_vec = np.array(s_candidate).reshape((N,1))
        # Tính t' = A @ s_candidate mod Q
        t_candidate = (A @ s_candidate_vec) % Q

        # Sai số = t - t_candidate mod Q
        diff = (t - t_candidate) % Q
        # Vì modulo, ta cân nhắc sai số nhỏ theo vòng tròn:
        diff = np.minimum(diff, Q - diff)

        # Nếu tất cả sai số <= ETA thì đây là ứng viên phù hợp
        if np.all(diff <= ETA):
            print(f"Tìm được s_candidate sau {idx+1} lượt thử:")
            print(s_candidate_vec.flatten())
            return s_candidate_vec

    print("Không tìm thấy s_candidate phù hợp.")
    return None

def encrypt(A, t, plaintext, index=0):
    scaled_pt = (plaintext * (Q // 4)) % Q
    ciphertext = (t[index][0] + scaled_pt) % Q
    return ciphertext, index

def decrypt(ciphertext, A_row, recovered_s):
    t_i_recomputed = int((A_row @ recovered_s % Q)[0])  # Chỉ dùng [0]
    delta = (ciphertext - t_i_recomputed) % Q
    recovered_plaintext = int(round(delta / (Q / 4))) % 4
    return recovered_plaintext


if __name__ == "__main__":
    attempts = 0
    success = False
    while not success:
        attempts += 1
        print(f"\n----- Lần thử {attempts} -----")
        A, t, true_s = generate_lwe_instance()
        plaintext = np.random.randint(0, 4)
        ciphertext, row_index = encrypt(A, t, plaintext)
        print(f"Plaintext: {plaintext}, Ciphertext: {ciphertext}")

        recovered_s = enumeration_attack(A, t)
        if recovered_s is not None:
            print("✅ Tìm được s bằng enumeration!")
            recovered_plaintext = decrypt(ciphertext, A[row_index], recovered_s)
            print(f"Giải mã: {recovered_plaintext}")
            if recovered_plaintext == plaintext:
                print("🎉 Giải mã chính xác, dừng thử!")
                success = True
            else:
                print("❌ Giải mã sai!")
        else:
            print("❌ Không tìm được s bằng enumeration")
