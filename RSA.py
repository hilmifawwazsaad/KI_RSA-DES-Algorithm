import random

def rsa_encrypt(plaintext, e, n):
    plaintext_encoded = [ord(c) for c in plaintext]
    chipertext = [pow(c, e, n) for c in plaintext_encoded]
    return chipertext

def rsa_decrypt(chipertext, d, n):
	msg_encoded = [pow(ch, d, n) for ch in chipertext]
	msg = ''.join([chr(c) for c in msg_encoded])
	return msg