import os
import base64
import hashlib
import random
from datetime import datetime

from flask import Flask, render_template, request, redirect, session, jsonify
from flask_socketio import SocketIO, join_room, emit

import psycopg2
from psycopg2.extras import RealDictCursor

from Crypto.Random import get_random_bytes
from crypto_utils import (
    generate_rsa_keys,
    aes_encrypt,
    aes_decrypt
)

# ------------------ APP INIT ------------------

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "dev-secret")

socketio = SocketIO(app, cors_allowed_origins="*")

# ------------------ DATABASE ------------------

DATABASE_URL = os.environ.get("DATABASE_URL")

if not DATABASE_URL:
    raise Exception("DATABASE_URL not set")

db = psycopg2.connect(DATABASE_URL)
cursor = db.cursor(cursor_factory=RealDictCursor)

# ------------------ CREATE TABLES ------------------

cursor.execute("""
CREATE TABLE IF NOT EXISTS users (
    id SERIAL PRIMARY KEY,
    username VARCHAR(50) UNIQUE NOT NULL,
    password VARCHAR(255) NOT NULL,
    unique_id INTEGER UNIQUE NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
""")

cursor.execute("""
CREATE TABLE IF NOT EXISTS conversations (
    id SERIAL PRIMARY KEY,
    user1 INTEGER NOT NULL,
    user2 INTEGER NOT NULL,
    aes_key TEXT NOT NULL
);
""")

cursor.execute("""
CREATE TABLE IF NOT EXISTS messages (
    id SERIAL PRIMARY KEY,
    sender INTEGER NOT NULL,
    receiver INTEGER NOT NULL,
    message TEXT NOT NULL,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
""")

db.commit()

# ------------------ HELPERS ------------------

def hash_pw(p):
    return hashlib.sha256(p.encode()).hexdigest()

def gen_uid():
    while True:
        uid = random.randint(100000, 999999)
        cursor.execute("SELECT id FROM users WHERE unique_id=%s", (uid,))
        if not cursor.fetchone():
            return uid

def get_conversation(sender, receiver):
    user1, user2 = sorted([sender, receiver])
    cursor.execute(
        "SELECT * FROM conversations WHERE user1=%s AND user2=%s",
        (user1, user2)
    )
    return cursor.fetchone()

# ------------------ ROUTES ------------------

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
    cursor.execute(
        "SELECT username FROM users WHERE unique_id=%s",
        (uid,)
    )
    u = cursor.fetchone()
    return jsonify({"username": u["username"] if u else "Unknown"})

# ------------------ SOCKET EVENTS ------------------

@socketio.on("join")
def join(data):
    join_room(data["room"])

@socketio.on("send_message")
def send_message(data):

    sender = int(data["sender"])
    receiver = int(data["receiver"])
    room = data["room"]

    conversation = get_conversation(sender, receiver)

    if not conversation:
        aes_key = get_random_bytes(32)
        enc_key = base64.b64encode(aes_key).decode()

        user1, user2 = sorted([sender, receiver])

        cursor.execute(
            "INSERT INTO conversations (user1,user2,aes_key) VALUES (%s,%s,%s)",
            (user1,user2,enc_key)
        )
        db.commit()
    else:
        aes_key = base64.b64decode(conversation["aes_key"])

    encrypted = base64.b64encode(
        aes_encrypt(data["message"], aes_key)
    ).decode()

    cursor.execute(
        "INSERT INTO messages (sender,receiver,message) VALUES (%s,%s,%s)",
        (sender,receiver,encrypted)
    )
    db.commit()

    emit("receive_message", {
        "sender": sender,
        "message": data["message"],
        "time": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    }, room=room)

@socketio.on("load_history")
def load_history(data):

    sender = int(data["sender"])
    receiver = int(data["receiver"])

    conversation = get_conversation(sender, receiver)

    if not conversation:
        emit("chat_history", [])
        return

    aes_key = base64.b64decode(conversation["aes_key"])

    cursor.execute("""
        SELECT sender,message,timestamp
        FROM messages
        WHERE (sender=%s AND receiver=%s)
           OR (sender=%s AND receiver=%s)
        ORDER BY timestamp ASC
    """, (sender,receiver,receiver,sender))

    rows = cursor.fetchall()

    msgs = []
    for row in rows:
        decrypted = aes_decrypt(
            base64.b64decode(row["message"]),
            aes_key
        )
        msgs.append({
            "sender": row["sender"],
            "message": decrypted,
            "time": row["timestamp"].strftime("%Y-%m-%d %H:%M:%S")
        })

    emit("chat_history", msgs)

@socketio.on("typing")
def typing(data):
    emit("typing_status", data, room=data["room"], include_self=False)

# ------------------ RUN ------------------

if __name__ == "__main__":
    socketio.run(app)
