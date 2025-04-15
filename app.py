import streamlit as st
import json
import uuid
import base64
import hashlib
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from pathlib import Path
import pandas as pd
import bcrypt

# Custom CSS Styling
# Custom CSS Styling
def inject_custom_css():
    st.markdown(f"""
        <style>
            .stApp {{
                background-image: {'url("https://images.unsplash.com/photo-1531297484001-80022131f5a1")' if st.session_state.page in ['login', 'register'] else 'url("https://images.unsplash.com/photo-1531297484001-80022131f5a1")'};
                background-size: cover;
                background-position: center;
                background-attachment: fixed;
            }}

            .main .block-container {{
                background-color: rgba(255, 255, 255, 0.95);
                padding: 2rem;
                border-radius: 15px;
                box-shadow: 0 0 25px rgba(0,0,0,0.1);
                margin-top: 2rem;
                max-width: 600px;
            }}

            /* Styling all input and textarea fields */
            input[type="text"],
            input[type="password"],
            textarea {{
                background-color: #d3d3d3 !important;
                color: black !important;
                caret-color: black !important;  /* Fixes invisible cursor */
                border: 2px solid #e0e0e0 !important;
                border-radius: 8px !important;
                padding: 10px 15px !important;
                box-shadow: none !important;
                transition: none !important;
            }}

            input[type="text"]:hover,
            input[type="password"]:hover,
            textarea:hover {{
                border: 2px solid #aaa !important;
            }}

            /* Custom Login/Register Button Styling */
            button[id^="button-login_tab"],
            button[id^="button-register_tab"] {{
                background-color: #ff0000 !important;
                border: 2px solid transparent !important;
                transition: transform 0.3s ease, border-color 0.3s ease !important;
            }}

            button[id^="button-login_tab"]:hover,
            button[id^="button-register_tab"]:hover {{
                border-color: #ff0000 !important;
                transform: scale(1.05);
            }}
        </style>
    """, unsafe_allow_html=True)

# File paths
USER_CREDENTIALS = "users.json"
DATA_VAULT = "data_vault.json"

# Initialize files
Path(USER_CREDENTIALS).touch(exist_ok=True)
Path(DATA_VAULT).touch(exist_ok=True)

# Session state management
if 'authenticated' not in st.session_state:
    st.session_state.authenticated = False
if 'current_user' not in st.session_state:
    st.session_state.current_user = None
if 'page' not in st.session_state:
    st.session_state.page = 'login'

# Security parameters
SALT = b'secure_salt_123'
KDF_ITERATIONS = 100000

# Key derivation function
def derive_key(passphrase: str):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=SALT,
        iterations=KDF_ITERATIONS
    )
    return base64.urlsafe_b64encode(kdf.derive(passphrase.encode()))

# Password hashing
def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()

def verify_password(password: str, hashed: str) -> bool:
    return bcrypt.checkpw(password.encode(), hashed.encode())

# User management
def register_user(username: str, password: str) -> bool:
    with open(USER_CREDENTIALS, 'r+') as file:
        try:
            users = json.load(file)
        except json.JSONDecodeError:
            users = {}
        
        if username in users:
            return False
        users[username] = hash_password(password)
        file.seek(0)
        json.dump(users, file)
        file.truncate()
        return True

def verify_user(username: str, password: str) -> bool:
    with open(USER_CREDENTIALS, 'r') as file:
        try:
            users = json.load(file)
            hashed = users.get(username)
            return hashed and verify_password(password, hashed)
        except json.JSONDecodeError:
            return False

# Data encryption/decryption
def encrypt_data(data: str, passphrase: str) -> str:
    key = derive_key(passphrase)
    fernet = Fernet(key)
    return fernet.encrypt(data.encode()).decode()

def decrypt_data(encrypted_data: str, passphrase: str) -> str:
    key = derive_key(passphrase)
    fernet = Fernet(key)
    return fernet.decrypt(encrypted_data.encode()).decode()

# Data management
def save_data(user: str, title: str, data: str, passphrase: str) -> str:
    entry_id = str(uuid.uuid4())
    encrypted_data = encrypt_data(data, passphrase)
    
    with open(DATA_VAULT, 'r+') as file:
        try:
            vault = json.load(file)
        except json.JSONDecodeError:
            vault = {}
        
        if user not in vault:
            vault[user] = []
        
        vault[user].append({
            'id': entry_id,
            'title': title,
            'data': encrypted_data
        })
        
        file.seek(0)
        json.dump(vault, file)
        file.truncate()
    return entry_id

def get_user_data(user: str) -> list:
    with open(DATA_VAULT, 'r') as file:
        try:
            vault = json.load(file)
            return vault.get(user, [])
        except json.JSONDecodeError:
            return []

# Authentication Pages
def login_page():
    inject_custom_css()
    col1, col2 = st.columns(2)
    with col1:
        btn_login = st.button("LOGIN", 
                            key="login_tab", 
                            use_container_width=True,
                            type="primary" if st.session_state.page == 'login' else "secondary")
    with col2:
        btn_register = st.button("REGISTER", 
                               key="register_tab", 
                               use_container_width=True,
                               type="primary" if st.session_state.page == 'register' else "secondary")
    
    if btn_register:
        st.session_state.page = 'register'
        st.rerun()
    if btn_login:
        st.session_state.page = 'login'
        st.rerun()
    
    with st.container():
        st.title("Secure Data Vault")
        with st.form("login_form"):
            username = st.text_input("Username")
            password = st.text_input("Password", type='password')
            
            if st.form_submit_button("Login"):
                if verify_user(username, password):
                    st.session_state.authenticated = True
                    st.session_state.current_user = username
                    st.session_state.page = 'dashboard'
                    st.rerun()
                else:
                    st.error("Invalid credentials")

def register_page():
    inject_custom_css()
    col1, col2 = st.columns(2)
    with col1:
        btn_login = st.button("LOGIN", 
                            key="login_tab", 
                            use_container_width=True,
                            type="primary" if st.session_state.page == 'login' else "secondary")
    with col2:
        btn_register = st.button("REGISTER", 
                               key="register_tab", 
                               use_container_width=True,
                               type="primary" if st.session_state.page == 'register' else "secondary")
    
    if btn_register:
        st.session_state.page = 'register'
        st.rerun()
    if btn_login:
        st.session_state.page = 'login'
        st.rerun()
    
    with st.container():
        st.title("Secure Data Vault")
        with st.form("register_form"):
            username = st.text_input("Choose Username")
            password = st.text_input("Create Password", type='password')
            confirm_password = st.text_input("Confirm Password", type='password')
            
            if st.form_submit_button("Register"):
                if len(password) < 8:
                    st.error("Password must be at least 8 characters")
                elif password != confirm_password:
                    st.error("Passwords do not match")
                else:
                    if register_user(username, password):
                        st.success("Registration successful! Please login")
                        st.session_state.page = 'login'
                        st.rerun()
                    else:
                        st.error("Username already exists")

# Dashboard Pages
def dashboard():
    inject_custom_css()
    st.sidebar.title(f"Welcome {st.session_state.current_user}")
    page = st.sidebar.radio("Navigation", [
        "🏠 Home",
        "💾 Store Data",
        "🔓 Retrieve Data",
        "🚪 Logout"
    ], index=0)
    
    if page == "🚪 Logout":
        st.session_state.authenticated = False
        st.session_state.current_user = None
        st.session_state.page = 'login'
        st.rerun()
    
    if page == "🏠 Home":
        home_page()
    elif page == "💾 Store Data":
        store_data_page()
    elif page == "🔓 Retrieve Data":
        retrieve_data_page()

def home_page():
    st.title("📊 Dashboard Overview")
    user_data = get_user_data(st.session_state.current_user)
    st.subheader(f"Hello {st.session_state.current_user}!")
    
    col1, col2 = st.columns(2)
    with col1:
        st.metric("Total Entries", len(user_data))
    with col2:
        st.metric("Last Activity", 
                 pd.Timestamp.now().strftime('%Y-%m-%d %H:%M') if user_data else "Never")
    
    if user_data:
        df = pd.DataFrame(user_data)
        st.dataframe(df[['id', 'title']], use_container_width=True)
    else:
        st.info("No encrypted data stored yet")

def store_data_page():
    st.title("🔒 Store Encrypted Data")
    with st.form("encryption_form"):
        title = st.text_input("Entry Title")
        data = st.text_area("Data to Encrypt", height=200)
        passkey = st.text_input("Encryption Key", 
                               type='password',
                               help="Minimum 8 characters - remember this key!")
        
        if st.form_submit_button("Encrypt and Store"):
            if len(passkey) < 8:
                st.error("Encryption key must be at least 8 characters")
            elif not title or not data:
                st.error("Title and data fields are required")
            else:
                try:
                    entry_id = save_data(
                        st.session_state.current_user,
                        title,
                        data,
                        passkey
                    )
                    st.success(f"Data stored securely! Entry ID: `{entry_id}`")
                except Exception as e:
                    st.error(f"Encryption failed: {str(e)}")

def retrieve_data_page():
    st.title("🔓 Retrieve Encrypted Data")
    user_data = get_user_data(st.session_state.current_user)
    
    if not user_data:
        st.warning("No encrypted entries found")
        return
    
    selected_entry = st.selectbox("Select Entry", 
                                user_data,
                                format_func=lambda x: f"{x['title']} ({x['id'][:8]}...)")
    
    with st.form("decryption_form"):
        passkey = st.text_input("Decryption Key", 
                               type='password',
                               help="Enter the key used during encryption")
        
        if st.form_submit_button("Decrypt Data"):
            try:
                decrypted = decrypt_data(selected_entry['data'], passkey)
                st.subheader("Decrypted Content")
                st.code(decrypted, language='text')
            except Exception as e:
                st.error("Decryption failed - invalid key or corrupted data")

# Main App
def main():
    query_params = st.query_params  # Removed parentheses
    if 'page' in query_params:
        st.session_state.page = query_params['page'][0]
    
    inject_custom_css()
    if st.session_state.page == 'login':
        login_page()
    elif st.session_state.page == 'register':
        register_page()
    elif st.session_state.authenticated:
        dashboard()

if __name__ == "__main__":
    main()