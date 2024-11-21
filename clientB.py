import random
import os
import socket
import time
import RSA as rsa
import pickle
import json
import encrypt as enc
import decrypt as dec

# public_key_server = None
# public_key_b = None
# private_key_b = None
# public_key_a = None

key_DES = ''

public_key_b = {
    "e": 773,
    "n": 1891
}

private_key_b = {
    "d": 1637,
    "n": 1891
}

public_key_server = {
    "e": 259,
    "n": 1219
}

public_key_a = {
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

# def rsa_key():
#     global public_key_b, private_key_b
#     public_key_b, private_key_b = generate_key_pair()
#     print("RSA Key Pair for Client B Generated")

#     folder = "key"
#     if not os.path.exists(folder):
#         os.makedirs(folder)

#     with open("key/5. public_key_B.txt", "w") as pub_file:
#         pub_file.write(f"{public_key_b[0]}\n{public_key_b[1]}")
#     with open("key/6. private_key_B.txt", "w") as priv_file:
#         priv_file.write(f"{private_key_b[0]}\n{private_key_b[1]}")

# Fungsi ini untuk mendapatkan public key dari server dan mengirimkan public key B ke server
# def get_server_public_key():
#     global public_key_server, public_key_b, private_key_b
#     server_host = socket.gethostname()
#     server_port = 31232  # Assuming the server is running on this port

#     with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
#         s.connect((server_host, server_port))
#         print("Connected to server to get public key")
        
#         s.sendall(b"REQUEST_PUBLIC_KEY")
#         data = s.recv(1024).decode()
        
#         e, n = map(int, data.split('\n'))
#         public_key_server = (e, n)
#         print("Received public key from server:", public_key_server)
        
#         public_key_b_str = f"{public_key_b[0]}\n{public_key_b[1]}"
#         s.sendall(public_key_b_str.encode())
#         print("Public key B sent to server")
        
#         s.sendall(b"PUBLIC_KEY_RECEIVED")
#         print("Public key successfully received and sent")



def request_public_key_a():
    global public_key_a, public_key_server
    server_host = socket.gethostname()
    server_port = 31232  # Assuming the server is running on this port

    e, n = public_key_server["e"], public_key_server["n"]
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((server_host, server_port))
        print("Connected to server to request public key of Client A")
        
        s.sendall(b"REQUEST_PUBLIC_KEY_A")
        public_key_a = pickle.loads(s.recv(2048))
        public_key_a = rsa.rsa_decrypt(public_key_a, e, n)
        public_key_a = json.loads(public_key_a)
        
        print(f"Received public key for Client A: {public_key_a}")
    
    # send_handshake_to_a()
    receive_handshake_from_a()

def receive_handshake_from_a():
    global public_key_a
    e, n = public_key_a["e"], public_key_a["n"]
    if not e or not n or n == 0:
        raise ValueError(f"Invalid public key: e={e}, n={n}")

    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_host = socket.gethostname()  # Alamat lokal Client B
    server_port = 31233        # Port Client B

    server_socket.bind((server_host, server_port))
    server_socket.listen()
    print(f"Client B listening for connection on port {server_port}")

    client_socket, client_address = server_socket.accept()
    with client_socket:
        print(f"Connection established with {client_address}")
        
        # Terima handshake dari Client A
        encrypted_handshake = pickle.loads(client_socket.recv(2048))
        handshake = rsa.rsa_decrypt(encrypted_handshake, private_key_b["d"], private_key_b["n"])
        print(f"Received handshake from Client A: {handshake}")

        # Kirimkan respon handshake ke Client A
        id = "B"
        n2 = "20"
        response = f"{id}||{n2}"
        encrypted_response = rsa.rsa_encrypt(response, e, n)
        client_socket.send(pickle.dumps(encrypted_response))
        print(f"Handshake response sent to Client A: {response}")
        
        receive_key_DES(client_socket)

def receive_key_DES(client_socket):
    attachment()
    global public_key_a, private_key_b, key_DES
    with client_socket:

        # Terima key DES dari Client A
        encrypted_key = pickle.loads(client_socket.recv(2048))
        key = rsa.rsa_decrypt(encrypted_key, private_key_b["d"], private_key_b["n"])
        print(f"Received key from Client A: {key}")
        
        key_DES = key
        
        # Kirimkan respon key ke Client A
        response = "Key received"
        encrypted_response = rsa.rsa_encrypt(response, public_key_a["e"], public_key_a["n"])
        client_socket.send(pickle.dumps(encrypted_response))
        print(f"Key response sent to Client A: {response}")
        print("--------------------------------------------------------")
        start_des()


# def send_handshake_to_a():
#     global public_key_a
#     e, n = public_key_a["e"], public_key_a["n"]
#     server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
#     server_host = socket.gethostname()
#     server_port = 31233
    
#     server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)  # Untuk menghindari port terblokir
#     server_socket.bind((server_host, server_port))
#     server_socket.listen()
#     print(f"Listening for connection from Client A on port {server_port}")
    
#     client_socket, client_address = server_socket.accept()
#     with client_socket:
#         request_public_key_a()
#         print(f"Connection established with {client_address}")
        
#         # Buat dan kirim handshake ke Client A
#         id = "B"
#         n2 = "20"
#         handshake = f"{id}||{n2}"
#         encrypted_handshake = rsa.rsa_encrypt(handshake, e, n)
#         client_socket.send(pickle.dumps(encrypted_handshake))
        
#         print(f"Handshake sent to Client A: {handshake}")
        
#         handshake_response = pickle.loads(client_socket.recv(2048))
#         handshake_response = rsa.rsa_decrypt(handshake_response, private_key_b["d"], private_key_b["n"])
#         handshake_response = json.loads(handshake_response)
        
#         print(f"Handshake response from Client A: {handshake_response}")
    
def start_des():
    # global key_DES
    # client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    # client_socket.connect((socket.gethostname(), 31234))
    
    # while True:
    #     message = input("Enter message to send to Client A: ")
    #     encrypted_message = enc.encrypt(message, key_DES)
        
    #     client_socket.send(encrypted_message.encode())
    #     print(f"Message sent to Client A: {message}")
        
    #     if message.lower() == "exit":
    #         print("You have ended the conversation")
    #         client_socket.close()
    #         break
        
    #     encrypted_response = client_socket.recv(2048).decode()
    #     decrypted_response = dec.decrypt(encrypted_response, key_DES)
    #     print(f"Response from Client A: {encrypted_response}")
    #     print(f"Decrypted response from Client A: {decrypted_response}")
    global key_DES
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((socket.gethostname(), 31234))
    server_socket.listen()
    
    conn, addr = server_socket.accept()
    while True:
        encrypted_message = conn.recv(2048).decode()
        decrypted_message = dec.decrypt(encrypted_message, key_DES)
        # print(f"Decrypted message from Client B: {decrypted_message}")
        # print(f"Message after decryption: {decrypted_message}")
        
        if decrypted_message == "exit":
            print("Client B has ended the conversation")
            break
        
        message = input("Enter message: ")
        # print(f"Plaintext: {message}")
        encrypted_message = enc.encrypt(message, key_DES)
        conn.send(encrypted_message.encode())
        print(f"Encrypted message sent to Client B")
        
        if message == "exit":
            print("You have ended the conversation")
            break
    
    conn.close()
    server_socket.close()

        # # Terima pesan dari Client A
        # encrypted_message = pickle.loads(client_socket.recv(2048))
        # message = dec.decrypt(encrypted_message, key_DES)
        # print(f"Received message from Client A: {message}")

        # # Kirim pesan ke Client A
        # message = input("Enter message to send to Client A: ")
        # encrypted_message = enc.encrypt(message, key_DES)
        # client_socket.send(pickle.dumps(encrypted_message))
        # print(f"Message sent to Client A: {message}")
        # # try:
        #     # Terima pesan terenkripsi dari Client A
        #     encrypted_message = pickle.loads(client_socket.recv(2048))
        #     message = dec.decrypt(encrypted_message, key_DES)
        #     print(f"Received message from Client A: {message}")

        #     # Kirim pesan terenkripsi ke Client A
        #     message = input("Enter message to send to Client A: ")
        #     encrypted_message = enc.encrypt(message, key_DES)
        #     print(f"Encrypted message: {encrypted_message}")
        #     client_socket.send(pickle.dumps(encrypted_message))
        #     print("Encrypted message sent to Client B")
        # except OSError as e:
        #     print(f"Socket error: {e}")
        #     break
        
        # server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        # server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        # server_host = socket.gethostname()
        # server_port = 31234  # Port for DES communication

        # server_socket.bind((server_host, server_port))
        # server_socket.listen()

        # client_socket, client_address = server_socket.accept()
        # with client_socket:

        #     # Receive encrypted message from Client A
        #     encrypted_message = pickle.loads(client_socket.recv(2048))
        #     message = dec.decrypt(encrypted_message, key_DES)
        #     # print(f"Received message from Client A: {message}")

        # # Send encrypted message to Client A
        # message = input("Enter message to send to Client A: ")
        # encrypted_message = enc.encrypt(message, key_DES)
        # client_socket.send(pickle.dumps(encrypted_message))
        # print(f"Message sent to Client A: {message}")

        # # Receive encrypted response from Client A
        # encrypted_response = pickle.loads(client_socket.recv(2048))
        # response = dec.decrypt(encrypted_response, key_DES)
        # print(f"Response from Client A: {response}")
        

def attachment():
    print("--------------------------------------------------------")
    print("Client 2 Ready for Communication")
    print("--------------------------------------------------------")
if __name__ == "__main__":
    # rsa_key()
    # get_server_public_key() 
    
    request_public_key_a()
    
    start_des()
    # send_handshake_to_a()
    # decrypt()