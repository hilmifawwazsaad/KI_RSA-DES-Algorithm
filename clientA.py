import random
import os
import socket
import time
import RSA as rsa
import pickle
import json
import encrypt as enc
import decrypt as dec

key_DES = '00010011001101000101011101111001100110111011110011011111111100'

public_key_a = {
    "e": 1199,
    "n": 1711
}

private_key_a = {
    "d": 1047, 
    "n": 1711
}

public_key_server = {
    "e": 259,
    "n": 1219
}

public_key_b = {
    "e": 0,
    "n": 0
}

# Fungsi ini untuk generate RSA key pair
def isprime(n, k=5):
    if n <= 1:
        return False
    if n <= 3:
        return True
    if n % 2 == 0 or n % 3 == 0:
        return False

    r, d = 0, n - 1
    while d % 2 == 0:
        r += 1
        d //= 2

    for _ in range(k):
        a = random.randint(2, n - 2)
        x = pow(a, d, n)
        if x == 1 or x == n - 1:
            continue
        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True

def generate_large_prime(bits=1024):
    while True:
        prime_candidate = random.getrandbits(bits)
        if isprime(prime_candidate):
            return prime_candidate

def gcd(a, b):
    while b != 0:
        a, b = b, a % b
    return a

def mod_inverse(a, m):
    m0, x0, x1 = m, 0, 1
    if m == 1:
        return 0
    while a > 1:
        q = a // m
        m, a = a % m, m
        x0, x1 = x1 - q * x0, x0
    if x1 < 0:
        x1 += m0
    return x1

def generate_key_pair(bits=1024):
    p = generate_large_prime(bits)
    q = generate_large_prime(bits)
    
    n = p * q
    phi_n = (p - 1) * (q - 1)
    
    while True:
        e = random.randrange(2, phi_n)
        if gcd(e, phi_n) == 1:
            break

    d = mod_inverse(e, phi_n)
    public_key = (e, n)
    private_key = (d, n)
    return public_key, private_key

def request_public_key_b():
    global public_key_b, public_key_server
    server_host = socket.gethostname()
    server_port = 31232  # Assuming the server is running on this port

    e, n = public_key_server["e"], public_key_server["n"]
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((server_host, server_port))
        print("Connected to server to request public key of Client B")
        
        # Kirim permintaan ke server
        s.sendall(b"REQUEST_PUBLIC_KEY_B")
        public_key_b = pickle.loads(s.recv(2048)) # Terima data yang terenkripsi
        public_key_b = rsa.rsa_decrypt(public_key_b, e, n)  # Dekripsi data
        public_key_b = json.loads(public_key_b)  # Ubah data menjadi dictionary
        
        print(f"Received and decrypted public key for Client B: {public_key_b}")
    
    send_handshake_to_b()
        

def send_handshake_to_b():
    global public_key_b
    e, n = public_key_b["e"], public_key_b["n"]
    server_host = socket.gethostname()
    server_port = 31233  
    
    while True:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.connect((server_host, server_port))
                print(f"Connection established with Client B on port {server_port}")
                
                id = "A"
                n1 = "10"
                handshake = f"{id}||{n1}"
                encrypted_handshake = rsa.rsa_encrypt(handshake, e, n)
                s.send(pickle.dumps(encrypted_handshake))
                print(f"Handshake sent to Client B: {handshake}")
                
                handshake_response = pickle.loads(s.recv(2048))
                handshake_response = rsa.rsa_decrypt(handshake_response, private_key_a["d"], private_key_a["n"])
                print(f"Handshake response from Client B: {handshake_response}")
                
                send_key_DES(s, server_host, server_port)
                
                break  # Berhenti setelah handshake berhasil
        except ConnectionRefusedError:
            print("Client B not ready, retrying...")
            time.sleep(1)  # Tunggu 1 detik sebelum mencoba lagi

def send_key_DES(s, server_host, server_port):
    attachment()
    global key_DES, public_key_b, private_key_a
    # print(f"Connection established with {server_host}:{server_port}")
    
    key = key_DES
    
    print(f"DES Key: {key}")
    encrypted_key = rsa.rsa_encrypt(key, public_key_b["e"], public_key_b["n"])
    s.send(pickle.dumps(encrypted_key))
    print(f"DES key sent to server")
    
    # Terima konfirmasi dari client
    confirmation = pickle.loads(s.recv(2048))
    confirmation = rsa.rsa_decrypt(confirmation, private_key_a["d"], private_key_a["n"])
    print(f"Confirmation from client B: {confirmation}")
    print("--------------------------------------------------------")
    start_des()

def start_des():
    global key_DES
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect((socket.gethostname(), 31234))
    
    while True:
        message = input("Enter message: ")
        encrypted_message = enc.encrypt(message, key_DES)
        
        client_socket.send(encrypted_message.encode())
        print("Encrypted message sent to Client B")
        
        if message.lower() == "exit":
            print("You have ended the conversation")
            client_socket.close()
            break
        
        encrypted_response = client_socket.recv(2048).decode()
        decrypted_response = dec.decrypt(encrypted_response, key_DES)
        
def attachment():
    print("--------------------------------------------------------")
    print("Client 1 Ready for Communication")
    print("--------------------------------------------------------")
    
if __name__ == "__main__":
    request_public_key_b()
