
# Decrypt user DB at runtime
try:
except Exception as e:
    st.stop()

import streamlit as st
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
import os
import os
DB_PATH = os.path.join("/tmp", "user_auth.db")
import base64
import sqlite3
from passlib.hash import bcrypt
import re
from datetime import datetime

#set page layout
st.set_page_config(layout="wide")

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

import streamlit as st
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
import os
import base64

# Decrypt user DB at runtime
try:
    decrypt_db(ENCRYPTED_DB_PATH, DECRYPTED_DB_PATH, st.secrets['auth']['encryption_key'])
except Exception as e:
    st.error('❌ Failed to decrypt user_auth.db')
    st.stop()


# Load and encode the logo image
logo_path = "data/logo.png"
with open(logo_path, "rb") as f:
    logo_data = f.read()
    logo_base64 = base64.b64encode(logo_data).decode()

# User-role mapping
USER_CREDENTIALS = {
    "admin": {"password": "retadmin", "site": "all"},
    "indy": {"password": "mars", "site": "Indy"},
    "atlanta": {"password": "mars", "site": "Atlanta"},
    "chicago": {"password": "mars", "site": "Chicago"},
}

# Initialize session state variables if not already set
if "authenticated" not in st.session_state:
    st.session_state.authenticated = False
    st.session_state.user = None

# Login
if not st.session_state.authenticated:
    st.title("🔐 Login Required")

    with st.form("login_form"):
        username = st.text_input("Username")
        password = st.text_input("Password", type="password")
        submitted = st.form_submit_button("Login")

        if submitted:
            user_info = USER_CREDENTIALS.get(username.lower())
            if user_info and user_info["password"] == password:
                st.session_state.authenticated = True
                st.session_state.user = username.lower()
                st.rerun()
            else:
                st.error("Incorrect username or password.")

    st.stop()


def prepare_weekly_summary(weekly_df):
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

def load_excel_data(location_name, file_name):
    full_path = os.path.join("data", file_name)
    try:
        weekly_df = pd.read_excel(full_path, sheet_name="Weekly Summary")
        daily_df = pd.read_excel(full_path, sheet_name="Inspection Log")
        return weekly_df, daily_df
    except Exception as e:
        st.error(f"Error loading file for {location_name}: {e}")
        return None, None

# --- UI ---
# Create a horizontal row: title on left, logo + logout on right
left_col, right_col = st.columns([6, 1])  # Adjust ratios as needed

with left_col:
    st.title("Sorter Inspection Dashboard")

with right_col:
    st.image(f"data:image/png;base64,{logo_base64}", width=200)
    st.markdown("<div style='height: 5px'></div>", unsafe_allow_html=True)  # spacing
    if st.button("Log out", key="logout_button_right"):
        st.session_state.authenticated = False
        st.session_state.user = None
        st.rerun()


locations = {
    "Indy": "Sorter Inspection Validation Indy.xlsx",
    "Atlanta": "Sorter Inspection Validation Atlanta.xlsx",
    "Chicago": "Sorter Inspection Validation Chicago.xlsx"
}

# Role-based access to locations
locations = {
    "Indy": "Sorter Inspection Validation Indy.xlsx",
    "Atlanta": "Sorter Inspection Validation Atlanta.xlsx",
    "Chicago": "Sorter Inspection Validation Chicago.xlsx"
}

user_role = st.session_state.user
user_site = USER_CREDENTIALS[user_role]["site"]

if user_site == "all":
    site_choice = st.selectbox("Select a location to view:", list(locations.keys()))
else:
    site_choice = user_site
    st.subheader(f"📍 Site: {site_choice}")

file_name = locations[site_choice]
weekly_df, daily_df = load_excel_data(site_choice, file_name)

if weekly_df is not None and daily_df is not None:
    st.header("📊 Weekly Pass/Fail")
    heatmap_df = prepare_weekly_heatmap(weekly_df)
    st.dataframe(heatmap_df.style.apply(style_weekly_heatmap, axis=None))
    st.markdown("**🟩 Pass** = All 8 strands inspected during the week  |  **🟥 Fail** = One or more strands missing")

    st.header("📋 Weekly Overview")
    weekly_detailed = prepare_weekly_summary(weekly_df)
    st.dataframe(weekly_detailed.style.apply(style_weekly_summary, axis=None))
    st.markdown("**🟩 Pass** = All 8 strands inspected during the week  |  **🟥 Fail** = One or more strands missing")

    st.header("📅 Daily Inspection Log")
    text_pivot, numeric_pivot = prepare_daily_log(daily_df)
    styled = text_pivot.style.apply(lambda _: highlight_by_minutes(numeric_pivot), axis=None)
    st.dataframe(styled)
    st.markdown("**🟩 Green** = ≥ 60 min  |  **🟨 Yellow** = 50–59 min  |  **🟥 Red** = < 50 min")