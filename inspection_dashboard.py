
import streamlit as st
import pandas as pd
import os
import base64
from cryptography.fernet import Fernet
import sqlite3
from datetime import datetime
from io import BytesIO

# Page configuration
st.set_page_config(page_title="Inspection Dashboard", layout="wide")

# Load encryption key from Streamlit secrets
ENCRYPTION_KEY = st.secrets["auth"]["encryption_key"]
GITHUB_REPO = st.secrets["auth"]["github_repo"]
GITHUB_TOKEN = st.secrets["auth"]["github_token"]
ALLOWED_DOMAIN = st.secrets["auth"]["allowed_domain"]

ENCRYPTED_DB_PATH = "user_auth.db.enc"
DECRYPTED_DB_PATH = "user_auth.db"

# Function to decrypt the database
def decrypt_db(enc_path, dec_path, key):
    try:
        with open(enc_path, "rb") as file:
            encrypted_data = file.read()
        fernet = Fernet(key.encode())
        decrypted = fernet.decrypt(encrypted_data)
        with open(dec_path, "wb") as dec_file:
            dec_file.write(decrypted)
    except Exception as e:
        st.error("❌ Failed to decrypt database.")
        st.stop()

# Function to load Excel files
def load_excel_data(file_path):
    try:
        excel_data = pd.read_excel(file_path, sheet_name=None)
        weekly_df = excel_data.get("Weekly Summary")
        daily_df = excel_data.get("Inspection Log")
        return weekly_df, daily_df
    except Exception as e:
        st.error(f"Failed to load Excel data: {e}")
        return None, None

# Authentication utilities
def create_users_table():
    conn = sqlite3.connect(DECRYPTED_DB_PATH)
    c = conn.cursor()
    c.execute('''
        CREATE TABLE IF NOT EXISTS users (
            email TEXT PRIMARY KEY,
            password TEXT,
            site TEXT,
            is_admin INTEGER DEFAULT 0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    conn.commit()
    conn.close()

def get_user(email):
    conn = sqlite3.connect(DECRYPTED_DB_PATH)
    c = conn.cursor()
    c.execute("SELECT * FROM users WHERE email = ?", (email,))
    user = c.fetchone()
    conn.close()
    return user

def add_user(email, password, site, is_admin=False):
    conn = sqlite3.connect(DECRYPTED_DB_PATH)
    c = conn.cursor()
    c.execute("INSERT INTO users (email, password, site, is_admin) VALUES (?, ?, ?, ?)", (email, password, site, int(is_admin)))
    conn.commit()
    conn.close()

# UI: Login/Register
def login_ui():
    st.title("🔐 Inspection Dashboard Login")
    mode = st.radio("Select mode", ["Login", "Register"])

    email = st.text_input("Email")
    password = st.text_input("Password", type="password")
    site = st.selectbox("Select Site", ["Indy", "Chicago", "Atlanta"]) if mode == "Register" else None
    login_button = st.button(mode)

    if login_button:
        if not email or not password:
            st.warning("Please enter both email and password.")
            return None, None, False
        if not email.endswith(ALLOWED_DOMAIN):
            st.error("Only emails from the authorized domain are allowed.")
            return None, None, False

        create_users_table()
        if mode == "Register":
            if get_user(email):
                st.error("User already exists.")
            else:
                add_user(email, password, site)
                st.success("Account created. Please login.")
        elif mode == "Login":
            user = get_user(email)
            if user and user[1] == password:
                return user[0], user[2], bool(user[3])
            else:
                st.error("Invalid credentials.")
    return None, None, False

# Decrypt DB before anything else
if os.path.exists(ENCRYPTED_DB_PATH):
    decrypt_db(ENCRYPTED_DB_PATH, DECRYPTED_DB_PATH, ENCRYPTION_KEY)

# Handle authentication
email, site_choice, is_admin = login_ui()
if not email:
    st.stop()

# Load Excel file by site
site_excel_files = {
    "Indy": "indy_data.xlsx",
    "Chicago": "chicago_data.xlsx",
    "Atlanta": "atlanta_data.xlsx"
}

file_path = site_excel_files.get(site_choice)
weekly_df, daily_df = load_excel_data(file_path)

# DASHBOARD
if weekly_df is not None and daily_df is not None:
    st.header(f"📍 Dashboard - {site_choice}")

    # Weekly Heatmap (placeholder style)
    st.subheader("📊 Weekly Pass/Fail Heatmap")
    heatmap_data = weekly_df[["Week Range", "All 8 Present"]]
    st.dataframe(heatmap_data)

    # Weekly Summary
    st.subheader("📋 Weekly Summary")
    st.dataframe(weekly_df)

    # Daily Inspection Log
    st.subheader("🧾 Daily Log")
    st.dataframe(daily_df)

    # Admin tools
    if is_admin:
        st.sidebar.title("🔧 Admin Tools")
        st.sidebar.write("Admin can manage users or view all sites.")
else:
    st.warning("Data not loaded.")
