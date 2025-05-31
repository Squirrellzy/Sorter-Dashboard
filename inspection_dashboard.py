
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

# Set wide layout before anything else
st.set_page_config(layout="wide")

# --- Configs ---
DB_PATH = os.path.join("/tmp", "user_auth.db")
ALLOWED_DOMAIN = st.secrets["auth"]["allowed_domain"]

# --- Init DB ---
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
    c.execute("INSERT INTO users (email, password, site, last_login) VALUES (?, ?, ?, ?)", 
              (email, hashed_pw, site, "Never"))
    conn.commit()
    conn.close()
    return "✅ Account created!"

def authenticate_user(email, password):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT password, site FROM users WHERE email = ?", (email,))
    result = c.fetchone()
    if result and bcrypt.verify(password, result[0]):
        c.execute("UPDATE users SET last_login = ? WHERE email = ?", 
                  (datetime.now().strftime("%Y-%m-%d %H:%M:%S"), email))
        conn.commit()
        conn.close()
        return True, result[1]
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

init_db()

# --- Session State ---
if "authenticated" not in st.session_state:
    st.session_state.authenticated = False
    st.session_state.user = None
    st.session_state.site = None

# --- Logo Load ---
logo_path = "data/logo.png"
with open(logo_path, "rb") as f:
    logo_data = f.read()
    logo_base64 = base64.b64encode(logo_data).decode()

# --- Login / Register ---
if not st.session_state.authenticated:
    st.title("🔐 Login or Register")
    tab1, tab2 = st.tabs(["Login", "Register"])
    with tab1:
        login_email = st.text_input("Email")
        login_pw = st.text_input("Password", type="password")
        if st.button("Login"):
            success, site = authenticate_user(login_email, login_pw)
            if success:
                st.session_state.authenticated = True
                st.session_state.user = login_email
                st.session_state.site = site
                st.success("✅ Logged in")
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

# --- Header UI ---
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
    with st.expander("🛠️ Admin Panel", expanded=False):
        all_users = get_all_users()
        df = pd.DataFrame(all_users, columns=["Email", "Site", "Last Login"])
        st.dataframe(df, use_container_width=True)
        st.markdown("---")
        selected = st.selectbox("Manage User", df["Email"])
        action = st.radio("Action", ["Edit Site", "Delete User"])
        if action == "Edit Site":
            new_site = st.selectbox("New site:", ["Indy", "Atlanta", "Chicago", "all"])
            if st.button("Update Site"):
                update_user_site(selected, new_site)
                st.success("✅ Site updated")
                st.rerun()
        elif action == "Delete User":
            if st.button("Delete Now"):
                delete_user(selected)
                st.warning("❌ User deleted")
                st.rerun()

# --- Dashboard Display ---
def load_excel_data(location, filename):
    path = os.path.join("data", filename)
    try:
        w_df = pd.read_excel(path, sheet_name="Weekly Summary")
        d_df = pd.read_excel(path, sheet_name="Inspection Log")
        return w_df, d_df
    except Exception as e:
        st.error(f"Error loading Excel: {e}")
        return None, None

def prepare_weekly_summary(df):
    df = df.loc[:, ["Week Range", "Strands Completed", "All 8 Present"]]
    df.columns = ["Week", "Strands", "Pass/Fail"]
    df["Week_Start"] = pd.to_datetime(df["Week"].str.extract(r"^(\d{2}-\d{2}-\d{2})")[0], format="%m-%d-%y")
    return df.sort_values("Week_Start", ascending=False).drop("Week_Start", axis=1)

def prepare_weekly_heatmap(df):
    df = df.loc[:, ["Week Range", "All 8 Present"]].copy()
    df.columns = ["Week", "Pass/Fail"]
    df = df.drop_duplicates("Week").sort_values("Week", ascending=False)
    return pd.DataFrame([df.set_index("Week")["Pass/Fail"]], index=["Status"])

def style_heatmap(df):
    return df.applymap(lambda x: "background-color: lightgreen" if str(x).lower() == "pass" else "background-color: lightcoral")

def convert_time_to_minutes(s):
    try:
        h, m, sec = map(int, str(s).split(":"))
        return h * 60 + m + sec / 60
    except:
        return 0

def prepare_daily_log(df):
    df = df.loc[:, ~df.columns.str.contains("^Unnamed")]
    df["__Minutes__"] = df.iloc[:, 2].apply(convert_time_to_minutes)
    txt = df.pivot_table(index=df.columns[1], columns=df.columns[0], values=df.columns[2], aggfunc='first').fillna("")
    num = df.pivot_table(index=df.columns[1], columns=df.columns[0], values="__Minutes__", aggfunc='sum').fillna(0)
    return txt[sorted(txt.columns, reverse=True)], num[sorted(num.columns, reverse=True)]

def highlight_minutes(df):
    return df.applymap(lambda v: "background-color: lightgreen" if v >= 60 else 
                                "background-color: khaki" if v >= 50 else 
                                "background-color: lightcoral" if v > 0 else "")

files = {
    "Indy": "Sorter Inspection Validation Indy.xlsx",
    "Atlanta": "Sorter Inspection Validation Atlanta.xlsx",
    "Chicago": "Sorter Inspection Validation Chicago.xlsx"
}

user_site = st.session_state.site
if user_site == "all":
    site_choice = st.selectbox("Select a location to view:", list(files.keys()))
else:
    site_choice = user_site
    st.subheader(f"📍 Site: {site_choice}")

file = files.get(site_choice)
weekly_df, daily_df = load_excel_data(site_choice, file)

if weekly_df is not None:
    st.header("📊 Weekly Heatmap")
    h_df = prepare_weekly_heatmap(weekly_df)
    st.dataframe(h_df.style.apply(style_heatmap, axis=None))
    st.header("📋 Weekly Summary")
    w_df = prepare_weekly_summary(weekly_df)
    st.dataframe(w_df)
if daily_df is not None:
    st.header("📅 Daily Log")
    text, minutes = prepare_daily_log(daily_df)
    st.dataframe(text.style.apply(lambda _: highlight_minutes(minutes), axis=None))
