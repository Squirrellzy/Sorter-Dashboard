
import streamlit as st
import pandas as pd
import base64
import os
import sqlite3
import pyAesCrypt
import requests
from passlib.hash import bcrypt
from datetime import datetime

st.set_page_config(layout="wide")

# --- CONFIG ---
ENCRYPTED_DB_PATH = "user_auth.db.aes"
DECRYPTED_DB_PATH = "/tmp/user_auth.db"
ENCRYPTION_KEY = st.secrets["auth"]["encryption_key"]
GITHUB_TOKEN = st.secrets["auth"]["github_token"]
GITHUB_REPO = st.secrets["auth"]["github_repo"]
GITHUB_BRANCH = st.secrets["auth"].get("github_branch", "main")
ALLOWED_DOMAIN = st.secrets["auth"]["allowed_domain"]
DB_PATH = DECRYPTED_DB_PATH

# --- AES Encrypt/Decrypt ---
def encrypt_db(input_file, output_file, password):
    buffer_size = 64 * 1024
    pyAesCrypt.encryptFile(input_file, output_file, password, buffer_size)

def decrypt_db(input_file, output_file, password):
    buffer_size = 64 * 1024
    try:
        pyAesCrypt.decryptFile(input_file, output_file, password, buffer_size)
        return True
    except Exception as e:
        st.warning(f"Decryption failed or not found. Starting fresh. ({e})")
        return False

# --- GitHub Push ---
def push_file_to_github(file_path, repo, token, branch):
    api_url = f"https://api.github.com/repos/{repo}/contents/{file_path}"
    headers = {
        "Authorization": f"token {token}",
        "Accept": "application/vnd.github+json"
    }
    with open(file_path, "rb") as f:
        content = base64.b64encode(f.read()).decode("utf-8")
    get_resp = requests.get(api_url, headers=headers)
    if get_resp.status_code == 200:
        sha = get_resp.json()["sha"]
        data = {
            "message": "Update encrypted user db",
            "content": content,
            "branch": branch,
            "sha": sha
        }
    else:
        data = {
            "message": "Initial commit encrypted user db",
            "content": content,
            "branch": branch
        }
    put_resp = requests.put(api_url, headers=headers, json=data)
    return put_resp.status_code in [200, 201]

# Decrypt if available
decrypt_db(ENCRYPTED_DB_PATH, DECRYPTED_DB_PATH, ENCRYPTION_KEY)

# Init DB
def init_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS users (
        email TEXT PRIMARY KEY,
        password TEXT NOT NULL,
        site TEXT NOT NULL,
        last_login TEXT
    )''')
    conn.commit()
    conn.close()
init_db()

# User DB actions
def register_user(email, password, site):
    if not email.endswith(ALLOWED_DOMAIN):
        return "Only company emails are allowed."
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT * FROM users WHERE email = ?", (email,))
    if c.fetchone():
        conn.close()
        return "Email already registered."
    hashed_pw = bcrypt.hash(password)
    c.execute("INSERT INTO users VALUES (?, ?, ?, ?)", 
              (email, hashed_pw, site, datetime.now().strftime("%Y-%m-%d %H:%M:%S")))
    conn.commit()
    conn.close()
    encrypt_db(DB_PATH, ENCRYPTED_DB_PATH, ENCRYPTION_KEY)
    push_file_to_github(ENCRYPTED_DB_PATH, GITHUB_REPO, GITHUB_TOKEN, GITHUB_BRANCH)
    return "✅ Registered successfully."

def authenticate_user(email, password):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT password, site FROM users WHERE email = ?", (email,))
    row = c.fetchone()
    if row and bcrypt.verify(password, row[0]):
        c.execute("UPDATE users SET last_login = ? WHERE email = ?", 
                  (datetime.now().strftime("%Y-%m-%d %H:%M:%S"), email))
        conn.commit()
        conn.close()
        encrypt_db(DB_PATH, ENCRYPTED_DB_PATH, ENCRYPTION_KEY)
        push_file_to_github(ENCRYPTED_DB_PATH, GITHUB_REPO, GITHUB_TOKEN, GITHUB_BRANCH)
        return True, row[1]
    conn.close()
    return False, None

# --- Streamlit App ---
if "authenticated" not in st.session_state:
    st.session_state.authenticated = False
    st.session_state.user = None
    st.session_state.site = None

# UI
st.markdown("## 🔐 Login")
tab1, tab2 = st.tabs(["Login", "Register"])

with tab1:
    email = st.text_input("Email")
    pw = st.text_input("Password", type="password")
    if st.button("Login"):
        ok, site = authenticate_user(email, pw)
        if ok:
            st.session_state.authenticated = True
            st.session_state.user = email
            st.session_state.site = site
            st.success("Logged in.")
            st.rerun()
        else:
            st.error("Login failed.")

with tab2:
    new_email = st.text_input("New Email")
    new_pw = st.text_input("New Password", type="password")
    new_site = st.selectbox("Site", ["Indy", "Atlanta", "Chicago"])
    if st.button("Register"):
        st.info(register_user(new_email, new_pw, new_site))

# Post-login dashboard
if st.session_state.authenticated:
    st.success(f"Welcome, {st.session_state.user} | Site: {st.session_state.site}")
    st.button("Log out", on_click=lambda: st.session_state.clear())
    st.markdown("---")
    st.write("📊 Site-specific dashboards will appear here.")
