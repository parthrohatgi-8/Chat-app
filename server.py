from flask import Flask, render_template, request, redirect, session, jsonify
from flask_socketio import SocketIO, join_room, emit
import mysql.connector, hashlib, random, os, base64
from datetime import datetime
from Crypto.Random import get_random_bytes

from crypto_utils import (
    generate_rsa_keys,
    rsa_encrypt_key,
    rsa_decrypt_key,
    aes_encrypt,
    aes_decrypt
)

app = Flask(__name__)
app.secret_key = "secret"
socketio = SocketIO(app, cors_allowed_origins="*")

# ---------- DATABASE ----------
db = mysql.connector.connect(
    host="localhost",
    user="root",
    password="root",
    database="chat_app"
)
cursor = db.cursor(dictionary=True)

# ---------- CHAT STORAGE ----------
CHAT_DIR = "chat_logs"
os.makedirs(CHAT_DIR, exist_ok=True)

# ---------- HELPERS ----------
def hash_pw(p):
    return hashlib.sha256(p.encode()).hexdigest()

def gen_uid():
    while True:
        uid = random.randint(100000, 999999)
        cursor.execute("SELECT id FROM users WHERE unique_id=%s", (uid,))
        if not cursor.fetchone():
            return uid

def chat_file(a, b):
    x, y = sorted([str(a), str(b)])
    return f"{CHAT_DIR}/{x}_{y}.txt"

# ---------- ROUTES ----------
@app.route("/", methods=["GET","POST"])
def login():
    if request.method == "POST":
        u = request.form["username"]
        p = hash_pw(request.form["password"])
        cursor.execute(
            "SELECT unique_id FROM users WHERE username=%s AND password=%s",
            (u,p)
        )
        user = cursor.fetchone()
        if user:
            session["uid"] = user["unique_id"]
            return redirect("/chat")
    return render_template("login.html")

@app.route("/register", methods=["GET","POST"])
def register():
    if request.method == "POST":
        u = request.form["username"]
        p = hash_pw(request.form["password"])
        uid = gen_uid()

        cursor.execute(
            "INSERT INTO users (username,password,unique_id) VALUES (%s,%s,%s)",
            (u,p,uid)
        )
        db.commit()
        generate_rsa_keys(uid)
        return redirect("/")
    return render_template("register.html")

@app.route("/chat")
def chat():
    if "uid" not in session:
        return redirect("/")
    return render_template("chat.html", uid=session["uid"])

@app.route("/get_user/<uid>")
def get_user(uid):
    cursor.execute("SELECT username FROM users WHERE unique_id=%s", (uid,))
    u = cursor.fetchone()
    return jsonify({"username": u["username"] if u else "Unknown"})

# 🔁 RESTORE CHAT LIST
@app.route("/my_chats/<uid>")
def my_chats(uid):
    chats = []
    for f in os.listdir(CHAT_DIR):
        if uid in f:
            other = f.replace(".txt","").replace(uid,"").replace("_","")
            chats.append(other)
    return jsonify(chats)

# ---------- SOCKET ----------
@socketio.on("join")
def join(data):
    join_room(data["room"])

@socketio.on("send_message")
def send_message(data):
    sender = data["sender"]
    receiver = data["receiver"]
    room = data["room"]
    path = chat_file(sender, receiver)

    # AES key handling (PERSISTENT)
    if not os.path.exists(path):
        aes_key = get_random_bytes(32)
        enc_key = rsa_encrypt_key(aes_key, receiver)
        with open(path, "w", encoding="utf-8") as f:
            f.write("---AESKEY---\n")
            f.write(enc_key + "\n")
            f.write("---MESSAGES---\n")
    else:
        with open(path, "r", encoding="utf-8") as f:
            enc_key = f.readlines()[1]
            aes_key = rsa_decrypt_key(enc_key, receiver)

    encrypted = base64.b64encode(aes_encrypt(data["message"], aes_key)).decode()
    time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    with open(path, "a", encoding="utf-8") as f:
        f.write(f"[{time}]|{sender}|{encrypted}\n")

    emit("receive_message", {
        "sender": sender,
        "message": data["message"],
        "time": time
    }, room=room)

@socketio.on("load_history")
def load_history(data):
    sender = data["sender"]
    receiver = data["receiver"]
    path = chat_file(sender, receiver)

    if not os.path.exists(path):
        return emit("chat_history", [])

    with open(path, "r", encoding="utf-8") as f:
        lines = f.readlines()

    aes_key = rsa_decrypt_key(lines[1], sender)
    msgs = []

    for line in lines[3:]:
        t, rest = line.split("]|")
        s, enc = rest.split("|",1)
        text = aes_decrypt(base64.b64decode(enc.strip()), aes_key)
        msgs.append({
            "time": t.replace("[",""),
            "sender": s,
            "message": text
        })

    emit("chat_history", msgs)

@socketio.on("typing")
def typing(data):
    emit("typing_status", data, room=data["room"], include_self=False)

if __name__ == "__main__":
    socketio.run(app, host="0.0.0.0", port=5000)
