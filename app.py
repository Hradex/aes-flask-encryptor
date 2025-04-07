from flask import Flask, render_template, request
import base64, json
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Hash import SHA256

app = Flask(__name__)

def encrypt_message(message, passkey):
    salt = get_random_bytes(16)
    key = PBKDF2(passkey, salt, dkLen=32, count=100000, hmac_hash_module=SHA256)
    cipher = AES.new(key, AES.MODE_GCM)
    ciphertext, tag = cipher.encrypt_and_digest(message.encode())
    smushed = b"".join([
        base64.b64encode(ciphertext), b"|",
        base64.b64encode(tag), b"|",
        base64.b64encode(cipher.nonce), b"|",
        base64.b64encode(salt)
    ])
    return smushed.decode()

def decrypt_message(smushed, passkey):
    try:
        parts = smushed.split("|")
        if len(parts) != 4:
            return "❌ Invalid smushed format."
        ciphertext = base64.b64decode(parts[0])
        tag = base64.b64decode(parts[1])
        nonce = base64.b64decode(parts[2])
        salt = base64.b64decode(parts[3])
        key = PBKDF2(passkey, salt, dkLen=32, count=100000, hmac_hash_module=SHA256)
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        plaintext = cipher.decrypt_and_verify(ciphertext, tag)
        return plaintext.decode()
    except Exception as e:
        return f"❌ Error: {str(e)}"

@app.route("/", methods=["GET", "POST"])
def home():
    result = ""
    if request.method == "POST":
        action = request.form.get("action")
        message = request.form.get("message")
        passkey = request.form.get("passkey")
        if action == "Encrypt":
            result = encrypt_message(message, passkey)
        elif action == "Decrypt":
            result = decrypt_message(message, passkey)
    return render_template("index.html", result=result)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
