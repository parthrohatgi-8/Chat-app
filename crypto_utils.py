import os, base64
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad

KEY_DIR = "keys"
os.makedirs(KEY_DIR, exist_ok=True)

# ---------- RSA ----------
def generate_rsa_keys(uid):
    key = RSA.generate(2048)
    with open(f"{KEY_DIR}/user_{uid}_private.pem", "wb") as f:
        f.write(key.export_key())
    with open(f"{KEY_DIR}/user_{uid}_public.pem", "wb") as f:
        f.write(key.publickey().export_key())

def rsa_encrypt_key(aes_key, receiver_id):
    pub = RSA.import_key(open(f"{KEY_DIR}/user_{receiver_id}_public.pem").read())
    cipher = PKCS1_OAEP.new(pub)
    return base64.b64encode(cipher.encrypt(aes_key)).decode()

def rsa_decrypt_key(enc_key, user_id):
    priv = RSA.import_key(open(f"{KEY_DIR}/user_{user_id}_private.pem").read())
    cipher = PKCS1_OAEP.new(priv)
    return cipher.decrypt(base64.b64decode(enc_key))

# ---------- AES ----------
def aes_encrypt(msg, key):
    cipher = AES.new(key, AES.MODE_CBC)
    return cipher.iv + cipher.encrypt(pad(msg.encode(), AES.block_size))

def aes_decrypt(ciphertext, key):
    iv = ciphertext[:16]
    ct = ciphertext[16:]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return unpad(cipher.decrypt(ct), AES.block_size).decode()
