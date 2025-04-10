# app.py

import streamlit as st
from encryption import encrypt_text, decrypt_text, hash_passkey

# Simple function to check if passkey hashes match
def check_passkey(stored_hash, passkey):
    return stored_hash == hash_passkey(passkey)

# In-memory data store
stored_data = {}
failed_attempts = {}

# ----------------- Login Page -----------------
def login_page():
    st.title("🔐 Re-Login Required")
    username = st.text_input("Username")
    password = st.text_input("Password", type="password")
    
    if st.button("Login"):
        if username == "admin" and password == "1234":
            st.session_state["authenticated"] = True
            failed_attempts[username] = 0
            st.success("Logged in successfully!")
        else:
            st.error("Invalid login.")

# ----------------- Insert Data Page -----------------
def insert_data_page():
    st.title("📝 Store Secure Data")
    username = st.text_input("Username")
    text = st.text_area("Enter your secret data")
    passkey = st.text_input("Enter a passkey", type="password")

    if st.button("Encrypt and Store"):
        encrypted = encrypt_text(text, passkey)
        stored_data[username] = {
            "encrypted_text": encrypted,
            "passkey": hash_passkey(passkey)
        }
        st.success("Data stored successfully!")

# ----------------- Retrieve Data Page -----------------
def retrieve_data_page():
    st.title("🔓 Retrieve Your Data")
    username = st.text_input("Username")
    passkey = st.text_input("Enter your passkey", type="password")

    if failed_attempts.get(username, 0) >= 3:
        st.warning("Too many failed attempts. Please login again.")
        login_page()
        return

    if st.button("Retrieve Data"):
        user_data = stored_data.get(username)

        if user_data and check_passkey(user_data["passkey"], passkey):
            decrypted = decrypt_text(user_data["encrypted_text"], passkey)
            st.success("Decrypted Data:")
            st.code(decrypted)
            failed_attempts[username] = 0
        else:
            failed_attempts[username] = failed_attempts.get(username, 0) + 1
            remaining = 3 - failed_attempts[username]
            st.error(f"Wrong passkey! {remaining} attempts left.")

# ----------------- Main Page -----------------
def main():
    st.set_page_config(page_title="🔐 Secure Data App")

    if "authenticated" not in st.session_state:
        st.session_state["authenticated"] = True

    menu = st.sidebar.selectbox("Menu", ["Home", "Store Data", "Retrieve Data", "Login"])

    if menu == "Home":
        st.title("🔐 Secure Data Encryption App")
        st.write("Welcome to a secure storage system.")
    elif menu == "Store Data":
        insert_data_page()
    elif menu == "Retrieve Data":
        retrieve_data_page()
    elif menu == "Login":
        login_page()

if __name__ == "__main__":
    main()
