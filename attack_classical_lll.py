import numpy as np
from fpylll import IntegerMatrix, LLL

# Tham số yếu để LLL dễ thành công
N = 6
M = 20
Q = 97
ETA = 1

def generate_lwe_instance():
    A = np.random.randint(0, Q, size=(M, N))
    s = np.random.randint(-ETA, ETA + 1, size=(N, 1))
    e = np.random.randint(-ETA, ETA + 1, size=(M, 1))
    t = (A @ s + e) % Q
    return A, t, s

def build_lattice_basis(A, t):
    m, n = A.shape
    B = np.zeros((n + m, n + m), dtype=int)
    B[:n, :n] = np.identity(n, dtype=int)
    B[:n, n:] = A.T
    B[n:, n:] = Q * np.identity(m, dtype=int)

    B_embedded = np.zeros((n + m + 1, n + m + 1), dtype=int)
    B_embedded[:n + m, :n + m] = B
    B_embedded[n + m, n:n + m] = t.flatten()
    B_embedded[n + m, n + m] = -1
    return B_embedded

def lll_attack(B_matrix, true_s):
    Lattice = IntegerMatrix.from_matrix(B_matrix.tolist())
    lll_basis = LLL.reduction(Lattice)

    print("\nVector đầu tiên sau khi LLL giảm:")
    print(np.array(lll_basis[0]))

    for i in range(min(20, lll_basis.nrows)):
        short_vector = np.array(lll_basis[i])
        if abs(short_vector[-1]) == 1:
            if short_vector[-1] == 1:
                short_vector = -short_vector
            candidate_s = short_vector[:N]
            print(f"Vector {i} ứng cử viên s: {candidate_s}")
            if np.array_equal(candidate_s, true_s.flatten()):
                return candidate_s
    return None

def encrypt(A, t, plaintext, index=0):
    scaled_pt = (plaintext * (Q // 4)) % Q
    ciphertext = (t[index][0] + scaled_pt) % Q
    return ciphertext, index

def decrypt(ciphertext, A_row, recovered_s):
    t_i_recomputed = int((A_row @ recovered_s) % Q)
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

        B = build_lattice_basis(A, t)
        recovered_s = lll_attack(B, true_s)
        if recovered_s is not None:
            print("✅ Tìm được s!")
            recovered_plaintext = decrypt(ciphertext, A[row_index], recovered_s)
            print(f"Giải mã: {recovered_plaintext}")
            if recovered_plaintext == plaintext:
                print("🎉 Giải mã chính xác, dừng thử!")
                success = True
            else:
                print("❌ Giải mã sai!")
        else:

            print("❌ Không tìm được s")
