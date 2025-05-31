import streamlit as st
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
import os

st.set_page_config(layout="wide")

# Add logo in the top right
logo_path = "data/logo.jpg"
st.markdown(
    f"""
    <div style='position: absolute; top: 10px; right: 10px;'>
        <img src='data:image/png;base64,{open(logo_path, "rb").read().encode("base64").decode()}' width='120'/>
    </div>
    """,
    unsafe_allow_html=True
)

# User-role mapping
USER_CREDENTIALS = {
    "admin": {"password": "adminpass", "site": "all"},
    "indy": {"password": "mars", "site": "Indy"},
    "atlanta": {"password": "mars", "site": "Atlanta"},
    "chicago": {"password": "mars", "site": "Chicago"},
}

# Login
if "authenticated" not in st.session_state:
    st.session_state.authenticated = False
    st.session_state.user = None

if not st.session_state.authenticated:
    st.title("🔐 Login Required")
    username = st.text_input("Username")
    password = st.text_input("Password", type="password")
    if st.button("Login"):
        user_info = USER_CREDENTIALS.get(username.lower())
        if user_info and user_info["password"] == password:
            st.session_state.authenticated = True
            st.session_state.user = username.lower()
            st.rerun()
        else:
            st.error("Incorrect username or password.")
    st.stop()

# --- Sidebar logout ---
st.sidebar.markdown(f"👤 Logged in as: `{st.session_state.user}`")
if st.sidebar.button("🔁 Log out / Switch User"):
    st.session_state.authenticated = False
    st.session_state.user = None
    st.rerun()

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

# --- UI ---
st.title("Sorter Inspection Dashboard")

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