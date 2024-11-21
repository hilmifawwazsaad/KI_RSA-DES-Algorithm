import random
import threading
import os
import socket
import time
import RSA as rsa
import pickle
import json

MAX_CLIENTS = 2
COMPLETED_CLIENTS = 0

# client_keys = {}

public_key_server = {
    "e": 259,
    "n": 1219
}

private_key_server = {
    "d": 1091,
    "n": 1219
}

clientA = {
    "e": 1199,
    "n": 1711
}

clientB = {
    "e": 773,
    "n": 1891
}

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

def rsa_key():
    public_key, private_key = generate_key_pair()
    print("RSA Key Pair for Server Generated")

    folder = "key"
    if not os.path.exists(folder):
        os.makedirs(folder)

    with open("key/1. public_key_server.txt", "w") as pub_file:
        pub_file.write(f"{public_key[0]}\n{public_key[1]}")
    with open("key/2. private_key_server.txt", "w") as priv_file:
        priv_file.write(f"{private_key[0]}\n{private_key[1]}")
    
    return public_key

def start_server():
    server_host = socket.gethostname()
    server_port = 31232
    
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
        server_socket.bind((server_host, server_port))
        server_socket.listen(5)
        print(f"Server listening on {server_host}:{server_port}...")

        while True:
            client_socket, client_address = server_socket.accept()
            print(f"Connection from {client_address}")
            client_thread = threading.Thread(target=sent_public_keys, args=(client_socket, client_address))
            client_thread.start()
            
def sent_public_keys(client_socket, client_address): 
    global COMPLETED_CLIENTS, clientB, clientA, private_key_server
    
    d, n = private_key_server["d"], private_key_server["n"]
    try:
        print(f"Connection established with {client_address}")
        request = client_socket.recv(2048).decode()
        
        if request == "REQUEST_PUBLIC_KEY_B":
            # Enkripsi public key dari clientB dengan private key server
            B_dumps = json.dumps(clientB)
            print(f"B dumbs: {B_dumps}")
            B_keys = rsa.rsa_encrypt(B_dumps, d, n)
            print(f"B keys: {B_keys}")
            client_socket.send(pickle.dumps(B_keys))
            print(f"Sent encrypted public key of clientB to {client_address}.")
        elif request == "REQUEST_PUBLIC_KEY_A":
            # Enkripsi public key dari clientA dengan private key server
            A_dumps = json.dumps(clientA)
            print(f"A dumbs: {A_dumps}")
            A_keys = rsa.rsa_encrypt(A_dumps, d, n)
            print(f"A keys: {A_keys}")
            client_socket.send(pickle.dumps(A_keys))
            print(f"Sent encrypted public key of clientA to {client_address}.")
        else:
            response = "Error: Invalid request."
            client_socket.sendall(response.encode())
            print(f"Invalid request from {client_address}: {request}")
        
    except Exception as e:
        print(f"Error with client {client_address}: {e}")
    finally:
        client_socket.close()
        print(f"Connection with {client_address} closed.")
        
        # Tambahkan counter selesai untuk client
        COMPLETED_CLIENTS += 1
        if COMPLETED_CLIENTS >= MAX_CLIENTS:
            print("All clients have completed their processes. Shutting down server...")
            COMPLETED_CLIENTS = 0
            print(f"RESET")
            print(f"Completed clients = {COMPLETED_CLIENTS} for the next session.")
            os._exit(0)  # Menghentikan server secara paksa

if __name__ == "__main__":   
    start_server()
    sent_public_keys()
    print("Server is running...")