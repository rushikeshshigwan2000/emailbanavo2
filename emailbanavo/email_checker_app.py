import streamlit as st
import pandas as pd
import smtplib
import dns.resolver
import tempfile
import random
from email.mime.text import MIMEText
from auth_utils import create_user_table, add_user, validate_user, user_exists, update_password

# Create DB table
create_user_table()

# Session state defaults
if 'logged_in' not in st.session_state:
    st.session_state.logged_in = False
if 'email' not in st.session_state:
    st.session_state.email = ""
if 'otp_stage' not in st.session_state:
    st.session_state.otp_stage = None
if 'generated_otp' not in st.session_state:
    st.session_state.generated_otp = None
if 'pending_email' not in st.session_state:
    st.session_state.pending_email = None
if 'pending_password' not in st.session_state:
    st.session_state.pending_password = None

# Send OTP via Gmail SMTP
def send_otp_email(to_email, otp):
    from_email = "rushikeshshigwan2000@gmail.com"
    msg = MIMEText(f"Your OTP verification code is: {otp}")
    msg['Subject'] = "Email Verification - Data Gateway"
    msg['From'] = from_email
    msg['To'] = to_email

    try:
        with smtplib.SMTP('smtp.gmail.com', 587) as server:
            server.starttls()
            server.login(from_email, "ojkp ausq pyib wavn")  # Your Gmail App Password
            server.sendmail(from_email, to_email, msg.as_string())
        return True
    except Exception as e:
        st.error(f"Failed to send email: {e}")
        return False

# =================== AUTH UI ===================
if not st.session_state.logged_in:
    st.markdown("<h1 style='text-align: center;'>🔐 Login to Use Email Checker</h1>", unsafe_allow_html=True)
    auth_mode = st.sidebar.selectbox("Select Auth Mode", ["Login", "Sign Up", "Reset Password"])

    email = st.text_input("Email")
    password = st.text_input("Password", type="password")

    if email and not email.endswith("@gmail.com"):
        st.warning("Only organization emails ending with @gmail.com are allowed.")

    if auth_mode == "Login":
        if st.button("Login"):
            if validate_user(email, password):
                st.success("Login successful!")
                st.session_state.logged_in = True
                st.session_state.email = email
            else:
                st.error("Invalid credentials")

    elif auth_mode == "Sign Up":
        if st.session_state.otp_stage == "verify":
            input_otp = st.text_input("Enter OTP sent to your email")
            if st.button("Verify OTP"):
                if input_otp == st.session_state.generated_otp:
                    add_user(st.session_state.pending_email, st.session_state.pending_password)
                    st.success("Account created! You can now log in.")
                    st.session_state.otp_stage = None
                else:
                    st.error("Invalid OTP")
        else:
            if st.button("Send OTP"):
                if not user_exists(email):
                    if email.endswith("@gmail.com"):
                        otp = str(random.randint(100000, 999999))
                        if send_otp_email(email, otp):
                            st.success("OTP sent to your email.")
                            st.session_state.generated_otp = otp
                            st.session_state.pending_email = email
                            st.session_state.pending_password = password
                            st.session_state.otp_stage = "verify"
                    else:
                        st.error("Only organization emails allowed.")
                else:
                    st.error("User already exists")

    elif auth_mode == "Reset Password":
        new_pass = st.text_input("New Password", type="password")
        if st.button("Reset Password"):
            if user_exists(email):
                update_password(email, new_pass)
                st.success("Password updated successfully.")
            else:
                st.error("User not found.")

# ================= EMAIL CHECKER UI =================

if st.session_state.logged_in:
    st.markdown("<h1 style='text-align: center;'>📧 Email Checker</h1>", unsafe_allow_html=True)
    st.success(f"Logged in as {st.session_state.email}")
    
    if st.button("Logout"):
        st.session_state.logged_in = False
        st.session_state.email = ""
        st.experimental_rerun()

    def extract_domain(email):
        try:
            return email.split("@")[1]
        except IndexError:
            return None

    def is_domain_valid(domain):
        try:
            mx_records = dns.resolver.resolve(domain, 'MX')
            return True if mx_records else False
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.LifetimeTimeout):
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
        except Exception:
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
                st.error("Invalid email format. Please enter a valid email.")
        else:
            st.error("Please enter an email to validate.")

    uploaded_file = st.file_uploader("Upload CSV or Excel", type=["csv", "xlsx"])
    if uploaded_file is not None:
        file_extension = uploaded_file.name.split(".")[-1]
        if file_extension == "csv":
            df = pd.read_csv(uploaded_file)
        elif file_extension == "xlsx":
            df = pd.read_excel(uploaded_file)
        else:
            st.error("Unsupported file format.")
            st.stop()

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

                with open(temp_csv.name, "rb") as file:
                    st.download_button("Download Results as CSV", file, "validated_emails.csv", "text/csv")
                with open(temp_xlsx.name, "rb") as file:
                    st.download_button("Download Results as Excel", file, "validated_emails.xlsx", "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")
        else:
            st.error("CSV or Excel file must contain an 'Email' column.")
