import streamlit as st
import pandas as pd
import base64
import os
import sqlite3
import pyAesCrypt
import requests
from passlib.hash import bcrypt
from datetime import datetime

# Mapping of site to Excel filenames
SITE_FILES = {
    "Indy": "Sorter Inspection Validation Indy.xlsx",
    "Chicago": "Sorter Inspection Validation Chicago.xlsx",
    "Atlanta": "Sorter Inspection Validation Atlanta.xlsx"
}

# --- CONFIG ---
st.set_page_config(layout="wide")

ENCRYPTED_DB_PATH = "user_auth.db.aes"
DECRYPTED_DB_PATH = "/tmp/user_auth.db"
DB_PATH = DECRYPTED_DB_PATH
BUFFER_SIZE = 64 * 1024

ENCRYPTION_KEY = st.secrets["auth"]["encryption_key"]
GITHUB_TOKEN = st.secrets["auth"]["github_token"]
GITHUB_REPO = st.secrets["auth"]["github_repo"]
GITHUB_BRANCH = st.secrets["auth"].get("github_branch", "main")
ALLOWED_DOMAIN = st.secrets["auth"]["allowed_domain"]

# --- ENCRYPTION ---
def encrypt_db(input_file, output_file, password):
    pyAesCrypt.encryptFile(input_file, output_file, password, BUFFER_SIZE)

def decrypt_db(input_file, output_file, password):
    try:
        pyAesCrypt.decryptFile(input_file, output_file, password, BUFFER_SIZE)
        return True
        except Exception as e:
        st.warning(f"Decryption failed or not found. Starting fresh. ({e})")
        return False

# --- GITHUB PUSH ---
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

# --- DATABASE INIT ---
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

# --- USER ACTIONS ---
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
        c.execute("INSERT INTO users VALUES (?, ?, ?, ?)", (email, hashed_pw, site, datetime.now().strftime("%Y-%m-%d %H:%M:%S")))
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
        c.execute("UPDATE users SET last_login = ? WHERE email = ?", (datetime.now().strftime("%Y-%m-%d %H:%M:%S"), email))
        conn.commit()
        conn.close()
        encrypt_db(DB_PATH, ENCRYPTED_DB_PATH, ENCRYPTION_KEY)
        push_file_to_github(ENCRYPTED_DB_PATH, GITHUB_REPO, GITHUB_TOKEN, GITHUB_BRANCH)
        return True, row[1]
        conn.close()
        return False, None

# --- STARTUP ---
if decrypt_db(ENCRYPTED_DB_PATH, DECRYPTED_DB_PATH, ENCRYPTION_KEY):
    init_db()
else:
    init_db()

if "authenticated" not in st.session_state:
    st.session_state.authenticated = False
    st.session_state.user = None
    st.session_state.site = None

if not st.session_state.authenticated:
    st.title("🔐 Secure Inspection Dashboard")
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
        new_site = st.selectbox("Site", ["Indy", "Atlanta", "Chicago", "all"])
        if st.button("Register"):
            st.info(register_user(new_email, new_pw, new_site))
else:
    st.success(f"Welcome, {st.session_state.user} | Site: {st.session_state.site}")
    if st.button("Log out"):
        st.session_state.clear()
        st.rerun()

        site_files = {
        "Indy": "Sorter Inspection Validation Indy.xlsx",
        "Atlanta": "Sorter Inspection Validation Atlanta.xlsx",
        "Chicago": "Sorter Inspection Validation Chicago.xlsx"
        }

    if st.session_state.site == "all":
        site_choice = st.selectbox("Select site to view:", list(site_files.keys()))
    else:
        site_choice = st.session_state.site

        file_path = f"data/Sorter Inspection Validation {site_choice}.xlsx"
def load_excel_data(location_name, file_name):
    full_path = os.path.join("data", file_name)
    try:
        weekly_df = pd.read_excel(full_path, sheet_name="Weekly Summary")
        daily_df = pd.read_excel(full_path, sheet_name="Inspection Log")
        return weekly_df, daily_df
        except Exception as e:
        st.error(f"Error loading file for {location_name}: {e}")
        return None, None

        weekly_df = weekly_df.loc[:, ["Week Range", "Strands Completed", "All 8 Present"]].copy()
        weekly_df.columns = ["Week", "Strands", "Pass/Fail"]
        weekly_df["Week"] = weekly_df["Week"].astype(str).str.strip()
        weekly_df["Strands"] = weekly_df["Strands"].astype(str).str.strip()
        weekly_df["Pass/Fail"] = weekly_df["Pass/Fail"].astype(str).str.strip().str.title()

    # Extract and parse the start date for sorting
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

            weekly_df = weekly_df.loc[:, ["Week Range", "All 8 Present"]].copy()
            weekly_df.columns = ["Week", "Pass/Fail"]
            weekly_df["Week"] = weekly_df["Week"].astype(str).str.strip()
            weekly_df["Pass/Fail"] = weekly_df["Pass/Fail"].astype(str).str.strip().str.title()
            weekly_df = weekly_df.drop_duplicates(subset="Week")
            weekly_df = weekly_df.sort_values(by="Week", ascending=False)
            heatmap_df = pd.DataFrame([weekly_df.set_index("Week")["Pass/Fail"]])
            heatmap_df.index = ["Status"]
            return heatmap_df

def convert_time_to_minutes(time_str):
    try:
        h, m, s = map(int, str(time_str).split(":"))
        return h * 60 + m + s / 60
        except:
        return 0

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

                styles = pd.DataFrame("", index=df.index, columns=df.columns)
    for row in df.index:
        for col in df.columns:
            val = df.loc[row, col]
            if isinstance(val, str) and val.lower() == "pass":
                styles.loc[row, col] = "background-color: lightgreen"
            elif isinstance(val, str) and val.lower() == "fail":
                styles.loc[row, col] = "background-color: lightcoral"
                return styles

                st.markdown("**🟩 Pass** = All 8 strands inspected during the week  |  **🟥 Fail** = One or more strands missing")

                st.header("📋 Weekly Overview")

    try:
        st.header("📊 Weekly Heatmap Overview")
        st.dataframe(weekly_heatmap)

        st.header("📈 Weekly Summary")
        st.dataframe(weekly_detailed.style.apply(style_weekly_summary, axis=None))
        st.markdown("**🟩 Pass** = All 8 strands inspected during the week  |  **🟥 Fail** = One or more strands missing")

        st.header("📅 Daily Inspection Log")
        styled = text_pivot.style.apply(lambda _: highlight_by_minutes(numeric_pivot), axis=None)
        st.dataframe(styled)
        st.markdown("**🟩 Green** = ≥ 60 min  |  **🟨 Yellow** = 50–59 min  |  **🟥 Red** = < 50 min")

        except Exception as e:
        st.error(f"Could not load dashboard for {site_choice}: {e}")

if st.session_state.get("authenticated") and st.session_state.get("site"):
    site_choice = st.session_state["site"]
    file_name = SITE_FILES.get(site_choice)
    if file_name:
        weekly_df, daily_df = load_excel_data(site_choice, file_name)
        if weekly_df is not None and daily_df is not None:
            render_dashboard(site_choice, weekly_df, daily_df)