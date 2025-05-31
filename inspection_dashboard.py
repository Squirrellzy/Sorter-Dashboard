import streamlit as st
import pandas as pd
import base64
import os
from passlib.hash import bcrypt
import sqlite3
from cryptography.fernet import Fernet
from datetime import datetime

# Page setup
st.set_page_config(layout="wide")

# Constants
DB_NAME = "user_auth.db"
ENCRYPTED_DB_PATH = "user_auth_encrypted.db"
DECRYPTED_DB_PATH = "user_auth.db"
ENCRYPTION_KEY = st.secrets["encryption_key"]
LOCATIONS = {
    "Indy": "Sorter Inspection Validation Indy.xlsx",
    "Atlanta": "Sorter Inspection Validation Atlanta.xlsx",
    "Chicago": "Sorter Inspection Validation Chicago.xlsx"
}
LOGO_PATH = "data/logo.png"

# Logo display
if os.path.exists(LOGO_PATH):
    with open(LOGO_PATH, "rb") as f:
        logo_data = f.read()
        logo_base64 = base64.b64encode(logo_data).decode()
    st.markdown(
        f"""
        <div style='position: absolute; top: 10px; right: 10px; z-index: 100;'>
            <img src='data:image/png;base64,{logo_base64}' width='120'/>
        </div>
        """,
        unsafe_allow_html=True
    )

# Encryption helpers
def encrypt_db(src, dst, key):
    fernet = Fernet(key.encode())
    with open(src, "rb") as f:
        data = f.read()
    encrypted = fernet.encrypt(data)
    with open(dst, "wb") as f:
        f.write(encrypted)

def decrypt_db(src, dst, key):
    try:
        fernet = Fernet(key.encode())
        with open(src, "rb") as f:
            encrypted = f.read()
        data = fernet.decrypt(encrypted)
        with open(dst, "wb") as f:
            f.write(data)
    except Exception as e:
        st.error("Failed to decrypt user database.")

# Database and user session
if "authenticated" not in st.session_state:
    st.session_state.authenticated = False
if "site" not in st.session_state:
    st.session_state.site = None
if "is_admin" not in st.session_state:
    st.session_state.is_admin = False

# Load users
def validate_user(email, password):
    try:
        decrypt_db(ENCRYPTED_DB_PATH, DECRYPTED_DB_PATH, ENCRYPTION_KEY)
        conn = sqlite3.connect(DECRYPTED_DB_PATH)
        c = conn.cursor()
        c.execute("SELECT password, site, is_admin FROM users WHERE email = ?", (email,))
        row = c.fetchone()
        conn.close()
        if row and bcrypt.verify(password, row[0]):
            return row[1], bool(row[2])
    except Exception as e:
        st.error("User validation failed.")
    return None, False

# Login form
if not st.session_state.authenticated:
    st.title("🔐 Login Required")
    with st.form("login_form"):
        email = st.text_input("Email")
        password = st.text_input("Password", type="password")
        submitted = st.form_submit_button("Login")
        if submitted:
            if not email.endswith("@retiina.com"):
                st.warning("Only @retiina.com emails allowed.")
            else:
                site, is_admin = validate_user(email, password)
                if site:
                    st.session_state.authenticated = True
                    st.session_state.site = site
                    st.session_state.is_admin = is_admin
                    st.experimental_rerun()
                else:
                    st.error("Invalid email or password.")
    st.stop()

# Logout
col1, col2 = st.columns([6,1])
with col2:
    if st.button("Log out"):
        st.session_state.authenticated = False
        st.session_state.site = None
        st.session_state.is_admin = False
        st.experimental_rerun()

# Site selection for admin
if st.session_state.is_admin:
    site_choice = st.selectbox("Select a location to view:", list(LOCATIONS.keys()))
else:
    site_choice = st.session_state.site

file_name = LOCATIONS[site_choice]

# --- Load Excel Data ---
def load_excel_data(file_name):
    full_path = os.path.join("data", file_name)
    try:
        weekly_df = pd.read_excel(full_path, sheet_name="Weekly Summary")
        daily_df = pd.read_excel(full_path, sheet_name="Inspection Log")
        return weekly_df, daily_df
    except Exception as e:
        st.error(f"Error loading Excel file: {e}")
        return None, None

def prepare_weekly_summary(weekly_df):
    weekly_df = weekly_df.loc[:, ["Week Range", "Strands Completed", "All 8 Present"]].copy()
    weekly_df.columns = ["Week", "Strands", "Pass/Fail"]
    weekly_df["Week"] = weekly_df["Week"].astype(str).str.strip()
    weekly_df["Strands"] = weekly_df["Strands"].astype(str).str.strip()
    weekly_df["Pass/Fail"] = weekly_df["Pass/Fail"].astype(str).str.strip().str.title()
    weekly_df["Week_Start"] = pd.to_datetime(weekly_df["Week"].str.extract(r"^(\d{2}-\d{2}-\d{2})")[0], format="%m-%d-%y")
    weekly_df = weekly_df.sort_values("Week_Start", ascending=False).drop(columns="Week_Start")
    return weekly_df[["Week", "Strands", "Pass/Fail"]]

def style_weekly_summary(df):
    styles = pd.DataFrame("", index=df.index, columns=df.columns)
    for i in df.index:
        val = df.loc[i, "Pass/Fail"]
        if isinstance(val, str) and val.lower() == "pass":
            styles.loc[i, "Pass/Fail"] = "background-color: lightgreen"
        elif isinstance(val, str) and val.lower() == "fail":
            styles.loc[i, "Pass/Fail"] = "background-color: lightcoral"
    return styles

def prepare_weekly_heatmap(weekly_df):
    weekly_df = weekly_df.loc[:, ["Week Range", "All 8 Present"]].copy()
    weekly_df.columns = ["Week", "Pass/Fail"]
    weekly_df["Week"] = weekly_df["Week"].astype(str).str.strip()
    weekly_df["Pass/Fail"] = weekly_df["Pass/Fail"].astype(str).str.strip().str.title()
    weekly_df = weekly_df.drop_duplicates(subset="Week")
    weekly_df = weekly_df.sort_values(by="Week", ascending=False)
    heatmap_df = pd.DataFrame([weekly_df.set_index("Week")["Pass/Fail"]])
    heatmap_df.index = ["Status"]
    return heatmap_df

def style_weekly_heatmap(df):
    styles = pd.DataFrame("", index=df.index, columns=df.columns)
    for row in df.index:
        for col in df.columns:
            val = df.loc[row, col]
            if isinstance(val, str) and val.lower() == "pass":
                styles.loc[row, col] = "background-color: lightgreen"
            elif isinstance(val, str) and val.lower() == "fail":
                styles.loc[row, col] = "background-color: lightcoral"
    return styles

def convert_time_to_minutes(time_str):
    try:
        h, m, s = map(int, str(time_str).split(":"))
        return h * 60 + m + s / 60
    except:
        return 0

def prepare_daily_log(daily_df):
    daily_df = daily_df.loc[:, ~daily_df.columns.str.contains("^Unnamed")]
    date_col = daily_df.columns[0]
    strand_col = daily_df.columns[1]
    time_col = daily_df.columns[2]
    daily_df["__Minutes__"] = daily_df[time_col].apply(convert_time_to_minutes)
    text_pivot = daily_df.pivot_table(index=strand_col, columns=date_col, values=time_col, aggfunc='first')
    numeric_pivot = daily_df.pivot_table(index=strand_col, columns=date_col, values="__Minutes__", aggfunc='sum')
    text_pivot = text_pivot[sorted(text_pivot.columns, reverse=True)]
    numeric_pivot = numeric_pivot[sorted(numeric_pivot.columns, reverse=True)]
    return text_pivot.fillna(""), numeric_pivot.fillna(0)

def highlight_by_minutes(minutes_df):
    styles = pd.DataFrame("", index=minutes_df.index, columns=minutes_df.columns)
    for row in styles.index:
        for col in styles.columns:
            val = minutes_df.loc[row, col]
            try:
                val = float(val)
            except:
                continue
            if val >= 60:
                styles.loc[row, col] = 'background-color: lightgreen'
            elif 50 <= val < 60:
                styles.loc[row, col] = 'background-color: khaki'
            elif val > 0:
                styles.loc[row, col] = 'background-color: lightcoral'
    return styles

# --- Dashboard Content ---
weekly_df, daily_df = load_excel_data(file_name)
if weekly_df is not None and daily_df is not None:
    st.header("📊 Weekly Pass/Fail")
    heatmap_df = prepare_weekly_heatmap(weekly_df)
    st.dataframe(heatmap_df.style.apply(style_weekly_heatmap, axis=None))
    st.markdown("**🟩 Pass** = All 8 strands inspected during the week  |  **🟥 Fail** = One or more strands missing")

    st.header("📋 Weekly Overview")
    weekly_detailed = prepare_weekly_summary(weekly_df)
    st.dataframe(weekly_detailed.style.apply(style_weekly_summary, axis=None))

    st.header("📅 Daily Inspection Log")
    text_pivot, numeric_pivot = prepare_daily_log(daily_df)
    styled = text_pivot.style.apply(lambda _: highlight_by_minutes(numeric_pivot), axis=None)
    st.dataframe(styled)
