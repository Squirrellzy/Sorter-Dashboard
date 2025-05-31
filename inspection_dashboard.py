
import streamlit as st
import pandas as pd
import base64
import os
import sqlite3
import pyAesCrypt
import requests
from passlib.hash import bcrypt
from datetime import datetime

# --- CONFIG ---
ENCRYPTED_DB_PATH = "user_auth.db.aes"
DECRYPTED_DB_PATH = "/tmp/user_auth.db"
ENCRYPTION_KEY = st.secrets["auth"]["encryption_key"]
GITHUB_TOKEN = st.secrets["auth"]["github_token"]
GITHUB_REPO = st.secrets["auth"]["github_repo"]
GITHUB_BRANCH = st.secrets["auth"].get("github_branch", "main")
ALLOWED_DOMAIN = st.secrets["auth"]["allowed_domain"]
DB_PATH = DECRYPTED_DB_PATH

st.set_page_config(layout="wide")

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

                                                        # --- Login UI ---
                                                        if "authenticated" not in st.session_state:
                                                            st.session_state.authenticated = False
                                                            st.session_state.user = None
                                                            st.session_state.site = None

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

                                                                                    # --- Dashboards ---
                                                                                    if st.session_state.authenticated:
                                                                                        # 🔒 User is authenticated, show dashboards
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
                                                                                                    try:
                                                                                                        weekly_df = pd.read_excel(file_path, sheet_name="Weekly Summary")
                                                                                                        daily_df = pd.read_excel(file_path, sheet_name="Inspection Log")

                                                                                                        st.markdown("### ✅ Weekly Summary")
                                                                                                        st.dataframe(weekly_df)

                                                                                                        st.markdown("### 📅 Daily Inspection Log")
                                                                                                        daily_df["Duration (minutes)"] = daily_df.iloc[:, 2].apply(
                                                                                                        lambda t: sum(int(x) * 60 ** i for i, x in enumerate(reversed(str(t).split(':'))))
                                                                                                        )
                                                                                                        styled = daily_df.style.applymap(
                                                                                                        lambda v: "background-color: lightgreen" if isinstance(v, (int, float)) and v >= 60
                                                                                                    else "background-color: khaki" if isinstance(v, (int, float)) and v >= 50
                                                                                                    else "background-color: lightcoral" if isinstance(v, (int, float)) and v > 0
                                                                                                    else ""
                                                                                                        , subset=["Duration (minutes)"])
                                                                                                        st.dataframe(styled)

                                                                                                    except Exception as e:
                                                                                                            st.error(f"Could not load dashboard for {site_choice}: {e}")


                                                                                                            # --- Dashboard Code Injected ---

                                                                                                            #set page layout

                                                                                                            # Load and encode the logo image
                                                                                                            logo_path = "data/logo.png"
                                                                                                            with open(logo_path, "rb") as f:
                                                                                                                logo_data = f.read()
                                                                                                                logo_base64 = base64.b64encode(logo_data).decode()

                                                                                                                # Display logo in top-right corner
                                                                                                                st.markdown(
                                                                                                                f"""
                                                                                                                <div style='position: absolute; top: 10px; right: 10px; z-index: 100;'>
                                                                                                                <img src='data:image/png;base64,{logo_base64}' width='120'/>
                                                                                                                </div>
                                                                                                                """,
                                                                                                                unsafe_allow_html=True
                                                                                                                )


                                                                                                                def load_excel_data(location_name, file_name):
                                                                                                                    full_path = os.path.join("data", file_name)
                                                                                                                    try:
                                                                                                                        weekly_df = pd.read_excel(full_path, sheet_name="Weekly Summary")
                                                                                                                        daily_df = pd.read_excel(full_path, sheet_name="Inspection Log")
                                                                                                                        return weekly_df, daily_df
                                                                                                                    except Exception as e:
                                                                                                                            st.error(f"Error loading file for {location_name}: {e}")
                                                                                                                            return None, None

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

                                                                                                                                                                                                                        # --- UI ---

                                                                                                                                                                                                                        locations = {
                                                                                                                                                                                                                        "Indy": "Sorter Inspection Validation Indy.xlsx",
                                                                                                                                                                                                                        "Atlanta": "Sorter Inspection Validation Atlanta.xlsx",
                                                                                                                                                                                                                        "Chicago": "Sorter Inspection Validation Chicago.xlsx"
                                                                                                                                                                                                                        }

                                                                                                                                                                                                                        site_choice = st.selectbox("Select a location to view:", list(locations.keys()))
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