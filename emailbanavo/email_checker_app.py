import streamlit as st
import pandas as pd
import smtplib
import dns.resolver
import tempfile
import hashlib
import json
import os
import random
import string

# ---------- Config ----------
USER_DB = "users.json"
ORG_DOMAIN = "datagateway.in"
OTP_STORE = {}

# ---------- Utility Functions ----------
def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

def load_users():
    if os.path.exists(USER_DB):
        with open(USER_DB, "r") as file:
            return json.load(file)
    return {}

def save_users(users):
    with open(USER_DB, "w") as file:
        json.dump(users, file)

def send_verification_code(email, code):
    try:
        smtp_server = smtplib.SMTP('smtp.gmail.com', 587)
        smtp_server.starttls()
        smtp_server.login("your-email@gmail.com", "your-app-password")  # Replace with actual credentials
        message = f"Subject: Email Verification Code\n\nYour verification code is: {code}"
        smtp_server.sendmail("your-email@gmail.com", email, message)
        smtp_server.quit()
    except Exception as e:
        st.error(f"Failed to send email: {e}")

def extract_domain(email):
    try:
        return email.split("@")[1]
    except IndexError:
        return None

def is_domain_valid(domain):
    try:
        mx_records = dns.resolver.resolve(domain, 'MX')
        return True if mx_records else False
    except Exception:
        return False

def is_email_valid(email, domain):
    try:
        mx_records = dns.resolver.resolve(domain, 'MX')
        mx_record = str(mx_records[0].exchange)
        server = smtplib.SMTP(timeout=10)
        server.connect(mx_record)
        server.helo()
        server.mail('noreply@datagateway.in')
        code, _ = server.rcpt(email)
        server.quit()
        return code == 250
    except:
        return False

def validate_emails(df):
    results = []
    for email in df['Email']:
        domain = extract_domain(email)
        if domain:
            domain_status = is_domain_valid(domain)
            email_status = is_email_valid(email, domain) if domain_status else False
            results.append([email, domain, domain_status, email_status])
        else:
            results.append([email, None, False, False])
    return pd.DataFrame(results, columns=['Email', 'Domain', 'Domain Valid', 'Email Valid'])

# ---------- Session ----------
if "logged_in" not in st.session_state:
    st.session_state.logged_in = False
if "user" not in st.session_state:
    st.session_state.user = ""

# ---------- Auth ----------
st.sidebar.title("User Authentication")
auth_option = st.sidebar.radio("Choose Option", ["Login", "Sign Up"])
users = load_users()

if auth_option == "Sign Up":
    email = st.sidebar.text_input("Organization Email (only @datagateway.in)")
    password = st.sidebar.text_input("Password", type="password")
    if st.sidebar.button("Get Code"):
        if not email.endswith(f"@{ORG_DOMAIN}"):
            st.sidebar.error("Only emails from datagateway.in are allowed.")
        elif email in users:
            st.sidebar.error("User already exists.")
        else:
            code = ''.join(random.choices(string.digits, k=6))
            OTP_STORE[email] = code
            send_verification_code(email, code)
            st.sidebar.success("Verification code sent to your org email.")
    otp = st.sidebar.text_input("Enter Verification Code")
    if st.sidebar.button("Create Account"):
        if OTP_STORE.get(email) == otp:
            users[email] = hash_password(password)
            save_users(users)
            st.session_state.logged_in = True
            st.session_state.user = email
            st.sidebar.success("Account created and logged in.")
        else:
            st.sidebar.error("Invalid verification code.")

elif auth_option == "Login":
    email = st.sidebar.text_input("Email")
    password = st.sidebar.text_input("Password", type="password")
    if st.sidebar.button("Login"):
        if email in users and users[email] == hash_password(password):
            st.session_state.logged_in = True
            st.session_state.user = email
            st.sidebar.success("Logged in successfully.")
        else:
            st.sidebar.error("Invalid credentials.")

    # Forgot password option
    with st.sidebar.expander("Forgot Password?"):
        reset_email = st.text_input("Reset Email")
        if st.button("Send Reset Code"):
            if reset_email in users:
                code = ''.join(random.choices(string.digits, k=6))
                OTP_STORE[reset_email] = code
                send_verification_code(reset_email, code)
                st.success("Reset code sent.")
            else:
                st.error("User not found.")
        reset_code = st.text_input("Enter Reset Code")
        new_password = st.text_input("New Password", type="password")
        if st.button("Reset Password"):
            if OTP_STORE.get(reset_email) == reset_code:
                users[reset_email] = hash_password(new_password)
                save_users(users)
                st.success("Password reset successful.")
            else:
                st.error("Invalid reset code.")

# ---------- Main App ----------
if st.session_state.logged_in:
    st.markdown(f"<h1 style='text-align: center;'>Email Checker</h1>", unsafe_allow_html=True)
    st.success(f"Welcome {st.session_state.user}!")

    single_email = st.text_input("Enter a single email to validate")
    if st.button("Validate Email"):
        if single_email:
            domain = extract_domain(single_email)
            if domain:
                domain_status = is_domain_valid(domain)
                email_status = is_email_valid(single_email, domain) if domain_status else False
                st.write(f"**Email:** {single_email}")
                st.write(f"**Domain:** {domain}")
                st.write(f"**Domain Valid:** {'✅' if domain_status else '❌'}")
                st.write(f"**Email Valid:** {'✅' if email_status else '❌'}")
            else:
                st.error("Invalid email format.")
        else:
            st.error("Please enter an email.")

    st.write("Upload your Excel file here")
    uploaded_file = st.file_uploader("Upload CSV or Excel", type=["csv", "xlsx"])
    if uploaded_file is not None:
        ext = uploaded_file.name.split(".")[-1]
        df = pd.read_csv(uploaded_file) if ext == "csv" else pd.read_excel(uploaded_file)
        
        if 'Email' in df.columns:
            st.write("### Uploaded Data")
            st.dataframe(df.head())
            if st.button("Validate Emails"):
                result_df = validate_emails(df)
                st.write("### Validation Results")
                st.dataframe(result_df)

                temp_csv = tempfile.NamedTemporaryFile(delete=False, suffix=".csv")
                result_df.to_csv(temp_csv.name, index=False)
                temp_xlsx = tempfile.NamedTemporaryFile(delete=False, suffix=".xlsx")
                with pd.ExcelWriter(temp_xlsx.name, engine='xlsxwriter') as writer:
                    result_df.to_excel(writer, index=False)

                with open(temp_csv.name, "rb") as f:
                    st.download_button("Download CSV", f, "validated_emails.csv", "text/csv")
                with open(temp_xlsx.name, "rb") as f:
                    st.download_button("Download Excel", f, "validated_emails.xlsx", "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")
        else:
            st.error("File must contain an 'Email' column.")
else:
    st.warning("Please login to access the Email Checker.")
