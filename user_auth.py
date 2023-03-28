import json
import os
import streamlit as st
import pandas as pd
import numpy as np
from passlib.hash import pbkdf2_sha256

# Set up the JSON file
def load_users_data():
    if os.path.exists("track.json"):
        with open("track.json", "r") as f:
            users_data = json.load(f)
    else:
        users_data = {}
    return users_data

def save_users_data(users_data):
    with open("track.json", "w") as f:
        json.dump(users_data, f)

def add_user(username, password, name):
    users_data = load_users_data()
    users_data[username] = {'password': password, 'name': name}
    save_users_data(users_data)

def check_user_exists(username):
    users_data = load_users_data()
    return username in users_data

def verify_login(username, password):
    users_data = load_users_data()
    if username in users_data and pbkdf2_sha256.verify(password, users_data[username]['password']):
        return True
    return False

def update_password(username, new_password):
    users_data = load_users_data()
    if username in users_data:
        users_data[username]['password'] = new_password
        save_users_data(users_data)      


# Streamlit app
def main():

    if "logged_in" not in st.session_state:
        st.session_state.logged_in = False
    if "user_username" not in st.session_state:
        st.session_state.user_username = ""

    if not st.session_state.logged_in:
        menu = ["Login", "Register", "Forgot Password"]
        choice = st.sidebar.selectbox("Menu", menu)

        if choice == "Login":
            st.subheader("Login")
            username = st.text_input("Username")
            password = st.text_input("Password", type='password')

            if st.button("Login"):
                login_result = verify_login(username, password)
                if login_result:
                    st.success("Logged in successfully")
                    st.session_state.logged_in = True
                    st.session_state.user_username = username
                else:
                    st.error("Invalid username or password")

        elif choice == "Register":
            st.subheader("Register")
            name = st.text_input("Name")
            username = st.text_input("Username")
            password = st.text_input("Password", type='password')

            if st.button("Register"):
                if check_user_exists(username):
                    st.warning("Username already exists")
                else:
                    password_hash = pbkdf2_sha256.hash(password)
                    add_user(username, password_hash, name)
                    st.success("Registered successfully")

        elif choice == "Forgot Password":
            st.subheader("Forgot Password")
            username = st.text_input("Username")

            if st.button("Reset Password"):
                user_data = check_user_exists(username)
                if user_data:
                    new_password = st.text_input("New Password", type='password')
                    confirm_password = st.text_input("Confirm New Password", type='password')

                    if new_password == confirm_password:
                        new_password_hash = pbkdf2_sha256.hash(new_password)
                        update_password(username, new_password_hash)
                        st.success("Password reset successfully")
                    else:
                        st.error("Passwords do not match")
                else:
                    st.error("Invalid Username")

    if st.session_state.logged_in:
        st.sidebar.subheader(f"Welcome, {st.session_state.user_username}")
        app_menu = ["Home", "Line Chart"]
        app_choice = st.sidebar.selectbox("App Menu", app_menu)

        if app_choice == "Home":
            st.subheader("Home")

        elif app_choice == "Line Chart":
            st.title("Area Chart")
            chart_data = pd.DataFrame(
                np.random.randn(20, 3),
                columns=['a', 'b', 'c'])

            if st.button('Generate Chart'):
                st.area_chart(chart_data)

        if st.sidebar.button("Logout"):
            st.session_state.logged_in = False
            st.session_state.user_username = ""

if __name__ == '__main__':
    main()