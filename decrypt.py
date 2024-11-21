# import socket

def convert_hexbin(s, direction="hex2bin"):
    map_hexbin = {
        '0': "0000", '1': "0001", '2': "0010", '3': "0011",
        '4': "0100", '5': "0101", '6': "0110", '7': "0111",
        '8': "1000", '9': "1001", 'A': "1010", 'B': "1011",
        'C': "1100", 'D': "1101", 'E': "1110", 'F': "1111"
    }
    map_binhex = {v:k for k,v in map_hexbin.items()}
    
    result = ""
    
    if direction == "hex2bin":
            for i in s:
                    result = result + map_hexbin[i]
    elif direction == "bin2hex":
            for i in range(0, len(s), 4):
                    result = result + map_binhex[s[i:i+4]]
    return result

def convert_bindec(s, direction="bin2dec"):
    if direction == "bin2dec":
        binary = s
        decimal = 0
        i = 0
        
        while binary != 0:
            dec = binary % 10
            decimal = decimal + dec * pow(2, i)
            binary = binary // 10
            i += 1
        return decimal
    
    elif direction == "dec2bin":
        decimal = s
        binary = ""
        
        while decimal != 0:
            binary = str(decimal % 2) + binary
            decimal = decimal // 2
        return binary

def string_to_hex(plaintext):
    return ''.join([format(ord(c), '02X') for c in plaintext])

def hex_to_string(hex_text):
    return bytes.fromhex(hex_text).decode('utf-8', errors='ignore')

def permute(k, arr, n):
    if len(k) < max (arr):
            return "Panjang string 'k' kurang dari indeks maksimum di 'arr'"
    return ''.join([k[arr[i] - 1] for i in range(n)])

def xor(x, y):
    return ''.join('0' if x == y else '1' for x, y in zip(x, y))

def shift_left(k, shifts):
    s = ""
    for i in range(shifts):
        for j in range(1, len(k)):
                s = s + k[j]
        s = s + k[0]
        k = s
        s = ""
    return k

def decrypt_ecb(ciphertext, key):
    plaintext = ""

    for i in range(0, len(ciphertext), 16):
        block = ciphertext[i:i+16]
        decrypt_block = des_decrypt(block, key)
        plaintext = plaintext + decrypt_block
    
    return plaintext

# Initializing the Initial Permutation Table (IP)
init_perm = [58, 50, 42, 34, 26, 18, 10, 2,
            60, 52, 44, 36, 28, 20, 12, 4,
            62, 54, 46, 38, 30, 22, 14, 6,
            64, 56, 48, 40, 32, 24, 16, 8,
            57, 49, 41, 33, 25, 17, 9, 1,
            59, 51, 43, 35, 27, 19, 11, 3,
            61, 53, 45, 37, 29, 21, 13, 5,
            63, 55, 47, 39, 31, 23, 15, 7]

# Expansion D-box Table (E-box)
e_box = [32, 1, 2, 3, 4, 5, 4, 5,
        6, 7, 8, 9, 8, 9, 10, 11,
        12, 13, 12, 13, 14, 15, 16, 17,
        16, 17, 18, 19, 20, 21, 20, 21,
        22, 23, 24, 25, 24, 25, 26, 27,
        28, 29, 28, 29, 30, 31, 32, 1]

# Straight Permutation (P-box)
p_box = [16, 7, 20, 21,
        29, 12, 28, 17,
        1, 15, 23, 26,
        5, 18, 31, 10,
        2, 8, 24, 14,
        32, 27, 3, 9,
        19, 13, 30, 6,
        22, 11, 4, 25]

# Substitution Boxes
s_box = [[[14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7],
        [0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8],
        [4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0],
        [15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13]],

        [[15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10],
        [3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5],
        [0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15],
        [13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9]],

        [[10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8],
        [13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1],
        [13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7],
        [1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12]],

        [[7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15],
        [13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9],
        [10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4],
        [3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14]],

        [[2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9],
        [14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6],
        [4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14],
        [11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3]],

        [[12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11],
        [10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8],
        [9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6],
        [4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13]],

        [[4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1],
        [13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6],
        [1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2],
        [6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12]],

        [[13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7],
        [1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2],
        [7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8],
        [2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11]]]

# Initializing the Final Permutation Table (FP)
final_perm = [40, 8, 48, 16, 56, 24, 64, 32,
            39, 7, 47, 15, 55, 23, 63, 31,
            38, 6, 46, 14, 54, 22, 62, 30,
            37, 5, 45, 13, 53, 21, 61, 29,
            36, 4, 44, 12, 52, 20, 60, 28,
            35, 3, 43, 11, 51, 19, 59, 27,
            34, 2, 42, 10, 50, 18, 58, 26,
            33, 1, 41, 9, 49, 17, 57, 25]

# Key Schedule
keyp = [57, 49, 41, 33, 25, 17, 9,
        1, 58, 50, 42, 34, 26, 18,
        10, 2, 59, 51, 43, 35, 27,
        19, 11, 3, 60, 52, 44, 36,
        63, 55, 47, 39, 31, 23, 15,
        7, 62, 54, 46, 38, 30, 22,
        14, 6, 61, 53, 45, 37, 29,
        21, 13, 5, 28, 20, 12, 4]

# Number of bit shifts
shift_table = [1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1]

# Key Compression Table
key_comp = [14, 17, 11, 24, 1, 5, 3, 28,
        15, 6, 21, 10, 23, 19, 12, 4,
        26, 8, 16, 7, 27, 20, 13, 2,
        41, 52, 31, 37, 47, 55, 30, 40,
        51, 45, 33, 48, 44, 49, 39, 56,
        34, 53, 46, 42, 50, 36, 29, 32]


def des_decrypt (ciphertext, round_keys):
    ciphertext_bin = convert_hexbin(ciphertext, "hex2bin").zfill(64)
    # print("Ciphertext dalam biner:", ciphertext_bin)  # Debugging
    initial_perm = permute(ciphertext_bin, init_perm, 64)

    left = initial_perm[0:32]
    right = initial_perm[32:64]
    
    for i in range(0, 16):
            right_expanded = permute(right, e_box, 48)
            right_xor = xor(right_expanded, round_keys[i])

            sbox_substitution = ""
            for j in range(0, 8):
                    row = convert_bindec(int(right_xor[j*6] + right_xor[j*6 + 5]), "bin2dec")
                    col = convert_bindec(int(right_xor[j*6 + 1] + right_xor[j*6 + 2] + right_xor[j*6 + 3] + right_xor[j*6 + 4]), "bin2dec")
                    val = s_box[j][row][col]
                    sbox_substitution = sbox_substitution + convert_bindec(val, "dec2bin").zfill(4)

            sbox_substitution = permute(sbox_substitution, p_box, 32)
            # permute_right = permute(sbox_substitution, p_box, 32)
            result = xor(left, sbox_substitution)
            left = result

            if i != 15:
                    left, right = right, left

    combined = right + left
    decrypt_bin = permute(combined, final_perm, 64)
    # decrypt_hex = convert_hexbin(decrypt_bin, "bin2hex")
    # decrypt_text = hex_to_string(decrypt_hex)

    print("Hasil dekripsi dalam biner:", decrypt_bin)  # Debugging
    # return convert_bindec(decrypt_bin, "bin2hex")
    return decrypt_bin

def decrypt(ciphertext, key):
    # client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    # host = socket.gethostname()
    # port = 31231
    # client_socket.connect((host, port))

    # print("Terhubung dengan server", host, "pada port", port)
    # key = '00010011001101000101011101111001100110111011110011011111111100'
    # print("Key: ", key)
    # bin_key = convert_hexbin(key, "hex2bin").zfill(64)
    key = permute(key, keyp, 56)
    left = key[0:28]
    right = key[28:56]
    round_keys_decrypt = []

    for i in range(0, 16):
            left = shift_left(left, shift_table[i])
            right = shift_left(right, shift_table[i])
            combined_key = left + right
            round_key = permute(combined_key, key_comp, 48)
            round_keys_decrypt.insert(0, round_key)

    # ciphertext = client_socket.recv(1024).decode()
    # decrypted_text = des_decrypt(ciphertext, round_keys_decrypt)
    # decrypted_text = convert_hexbin(des_decrypt(ciphertext, round_keys_decrypt), "bin2hex")
    decrypted_text = convert_hexbin(decrypt_ecb(ciphertext, round_keys_decrypt), "bin2hex")
    plaintext = hex_to_string(decrypted_text)
    print("Ciphertext yang diterima:", ciphertext)
    if decrypted_text:
            print("Plaintext yang diterima:", plaintext)
    else:
            print("Plaintext tidak ditemukan")
    # print("Plaintext yang diterima:", decrypted_text)