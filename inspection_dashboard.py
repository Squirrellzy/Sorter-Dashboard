import streamlit as st
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
import os
import base64
import sqlite3
from passlib.hash import bcrypt
import re
from datetime import datetime

# --- Secure config ---
ALLOWED_DOMAIN = st.secrets["auth"]["allowed_domain"]  # From .streamlit/secrets.toml
DB_PATH = "user_auth.db"

# --- DB Init ---
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

# --- DB Helpers ---
def register_user(email, password, site):
    if not email.endswith(ALLOWED_DOMAIN):
        return "Only @retiina.com emails are allowed."
    if not re.match(r"^[\w\.-]+@\w+\.\w+$", email):
        return "Invalid email format."

    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT * FROM users WHERE email = ?", (email,))
    if c.fetchone():
        conn.close()
        return "Email already registered."
    hashed_pw = bcrypt.hash(password)
    c.execute("INSERT INTO users (email, password, site, last_login) VALUES (?, ?, ?, ?)", (email, hashed_pw, site, "Never"))
    conn.commit()
    conn.close()
    return "✅ Account created! You can now log in."

def authenticate_user(email, password):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT password, site FROM users WHERE email = ?", (email,))
    result = c.fetchone()
    if result and bcrypt.verify(password, result[0]):
        c.execute("UPDATE users SET last_login = ? WHERE email = ?", (datetime.now().strftime("%Y-%m-%d %H:%M:%S"), email))
        conn.commit()
        c.execute("SELECT site FROM users WHERE email = ?", (email,))
        site_result = c.fetchone()
        conn.close()
        return True, site_result[0]
    conn.close()
    return False, None

def get_all_users():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT email, site, last_login FROM users ORDER BY email")
    users = c.fetchall()
    conn.close()
    return users

def delete_user(email):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("DELETE FROM users WHERE email = ?", (email,))
    conn.commit()
    conn.close()

def update_user_site(email, new_site):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("UPDATE users SET site = ? WHERE email = ?", (new_site, email))
    conn.commit()
    conn.close()

# --- Init DB on first load ---
init_db()

# --- Initialize session state variables ---
if "authenticated" not in st.session_state:
    st.session_state.authenticated = False
    st.session_state.user = None
    st.session_state.site = None

# --- Login / Register UI ---
if not st.session_state.authenticated:
    st.title("🔐 Login or Register")

    tab1, tab2 = st.tabs(["Login", "Register"])

    with tab1:
        login_email = st.text_input("Email")
        login_pw = st.text_input("Password", type="password")
        if st.button("Login"):
            success, user_site = authenticate_user(login_email, login_pw)
            if success:
                st.session_state.authenticated = True
                st.session_state.user = login_email
                st.session_state.site = user_site
                st.success("✅ Logged in successfully")
                st.rerun()
            else:
                st.error("Invalid credentials.")

    with tab2:
        reg_email = st.text_input("New Email")
        reg_pw = st.text_input("New Password", type="password")
        reg_site = st.selectbox("Select your site", ["Indy", "Atlanta", "Chicago"])
        if st.button("Create Account"):
            msg = register_user(reg_email, reg_pw, reg_site)
            if msg.startswith("✅"):
                st.success(msg)
            else:
                st.warning(msg)

    st.stop()

# --- Load logo ---
logo_path = "data/logo.png"
with open(logo_path, "rb") as f:
    logo_data = f.read()
    logo_base64 = base64.b64encode(logo_data).decode()

# --- Layout: Title left, logo and logout right ---
left_col, right_col = st.columns([6, 1])
with left_col:
    st.title("Sorter Inspection Dashboard")
with right_col:
    st.image(f"data:image/png;base64,{logo_base64}", width=200)
    st.markdown("<div style='height: 5px'></div>", unsafe_allow_html=True)
    if st.button("Log out", key="logout_button_right"):
        st.session_state.authenticated = False
        st.session_state.user = None
        st.session_state.site = None
        st.rerun()

# --- Admin Panel ---
if st.session_state.site == "all":
    with st.expander("🛠️ Admin Panel: View, Edit, and Delete Users", expanded=False):
        all_users = get_all_users()
        user_df = pd.DataFrame(all_users, columns=["Email", "Site", "Last Login"])
        st.dataframe(user_df, use_container_width=True)

        st.markdown("---")
        st.subheader("Edit or Delete a User")
        selected_email = st.selectbox("Select user to manage:", user_df["Email"])
        action = st.radio("Action", ["Edit Site", "Delete User"])

        if action == "Edit Site":
            new_site = st.selectbox("New site:", ["Indy", "Atlanta", "Chicago", "all"])
            if st.button("Update Site"):
                update_user_site(selected_email, new_site)
                st.success(f"✅ Updated site for {selected_email} to {new_site}")
                st.rerun()

        elif action == "Delete User":
            if st.button("Delete Now", type="primary"):
                delete_user(selected_email)
                st.warning(f"❌ Deleted user {selected_email}")
                st.rerun()

# --- Site Dashboard Loading continues below...
