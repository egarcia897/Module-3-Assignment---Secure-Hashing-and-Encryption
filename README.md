"""Estela Garcia
Date: November 15, 2025
Course: SDEV245
Short Desc: Write an app that generates SHA-256 hashes for input strings or files.
Write app that uses a simple substitution cipher(Caesar cipher or similar)to encrypt/decrypt
input text. Use OpenSSL or a tool to simulate a digital signature(sign/verify).
Language of choice is Python."""

import hashlib, secrets
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization

users = {
    "Mr.Emily": {"password": hashlib.sha256("admin245".encode()).hexdigest(), "role": "admin"},
    "Andrew": {"password": hashlib.sha256("user245".encode()).hexdigest(), "role": "user"}
}

# generate SHA-256 Hash
def generate_hash(text):
    return hashlib.sha256(text.encode()).hexdigest()

#login function
def login():
    username = input("Enter username: ")
    password = input("password:")
    hashed_password = generate_hash(password)

    if username == "Mr.Emily" and password == "admin245":
        print(f"Welcome {username}! Role: admin")
        return username, "admin"
    elif username == "Andrew" and password == "user245":
        print(f"Welcome {username}! Role: user")
        return username, "user"
    else: 
        print("Unauthorized! Access denied!")
        return None, None
    

#caesar cipher
def caesar_cipher(text, shift):
    encrypted = ""
    for char in text: 
        if char.isalpha():
            base = 65 if char.isupper() else 97
            encrypted += chr((ord(char) - base + shift) % 26 + base)
        else: 
            encrypted += char 
    
    decrypted = ""
    for char in encrypted: 
        if char.isalpha():
            base =  65 if char.isupper() else 97
            decrypted += chr((ord(char) - base - shift) % 26 + base)
        else:
            decrypted += char
    print(f"Encrypted: {encrypted}")
    print(f"Decrypted: {decrypted}")

#digital signature generated

def signature():
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()
    message = (input("Enter message to sign (or press Enter for 'Hello'):") or "Hello").encode()

    digital_signature = private_key.sign(message, padding.PKCS1v15(), hashes.SHA256())
    print("Message signed!")

#verification
    try: 
        public_key.verify(digital_signature, message, padding.PKCS1v15(), hashes.SHA256())
        print("Signature verified!")
    except:
        print("Signature Verification Failed!")

#randomness
def randomness():
    password = "test245"
    for _ in range(2):
        salt = secrets.token_hex(4)
        print("Salted:", hashlib.sha256((password+salt).encode()).hexdigest())

#hash text
def hash_text():
    text = input("Enter text to hash (or press Enter for 'test'): ") or "test"
    original_hash = generate_hash(text)
    print(f"SHA-256 Hash: {original_hash}")

    print("\nVerifying integrity with same text:")
    if generate_hash(text) == original_hash:
        print("Match!")

    print("\nVerifying with modified text 'test123':")
    if generate_hash("test123") == original_hash:
        print("MATCH!")
    else: 
        print("Wrong! Hash doesn't match.")
#main

def main():
    user, role = login()

    if user:
        hash_text()
        print("\ncaesar_cipher:")
        caesar_cipher("Hello", 3)
        
        randomness()
        
    if role == "admin":
            signature()

if __name__ == "__main__":
    main()
    
# Module-3-Assignment---Secure-Hashing-and-Encryption
