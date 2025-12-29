"""
Intentionally Vulnerable Python Application
DO NOT use in production.

Contains:
1. SQL Injection
2. Command Injection
3. Path Traversal
4. Hardcoded Secret
5. Insecure Deserialization
"""

import os
import pickle
import sqlite3
from flask import Flask, request

app = Flask(__name__)

# -----------------------------
# 1️⃣ HARDCODED SECRET
# -----------------------------

SECRET_KEY = "my_super_secret_password_123"


# -----------------------------
# 2️⃣ SQL INJECTION
# -----------------------------

@app.route("/user")
def get_user():
    user_id = request.args.get("id")

    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()

    # ❌ Vulnerable: user input concatenated directly
    query = "SELECT * FROM users WHERE id = " + user_id
    cursor.execute(query)

    result = cursor.fetchall()
    conn.close()

    return str(result)


# -----------------------------
# 3️⃣ COMMAND INJECTION
# -----------------------------

@app.route("/ping")
def ping():
    host = request.args.get("host")

    # ❌ Vulnerable: user input passed to shell
    os.system("ping -c 1 " + host)

    return "Ping executed"


# -----------------------------
# 4️⃣ PATH TRAVERSAL
# -----------------------------

@app.route("/read")
def read_file():
    filename = request.args.get("file")

    # ❌ Vulnerable: no validation on file path
    with open("/var/data/" + filename, "r") as f:
        return f.read()


# -----------------------------
# 5️⃣ INSECURE DESERIALIZATION
# -----------------------------

@app.route("/load")
def load_object():
    data = request.args.get("data")

    # ❌ Vulnerable: untrusted pickle loading
    obj = pickle.loads(data.encode())

    return str(obj)


if __name__ == "__main__":
    app.run(debug=True)
