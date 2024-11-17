import streamlit as st
import sqlite3
from datetime import datetime
from hashlib import sha256
import base64

# Database Initialization
def init_db():
    conn = sqlite3.connect('toll_plaza.db')
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY, 
                    username TEXT UNIQUE, 
                    password TEXT, 
                    user_type TEXT)''')
    c.execute('''CREATE TABLE IF NOT EXISTS tolls (
                    id INTEGER PRIMARY KEY, 
                    vehicle_number TEXT,
                    lane TEXT, 
                    vehicle_type TEXT, 
                    toll_amount REAL, 
                    payment_status TEXT, 
                    date TEXT, 
                    username TEXT)''')
    conn.commit()
    conn.close()

# Utility Functions
def encode_image(image_path):
    with open(image_path, "rb") as image_file:
        encoded = base64.b64encode(image_file.read()).decode()
    return encoded

def set_background(image_path):
    encoded_image = encode_image(image_path)
    st.markdown(
        f"""
        <style>
        body {{
            background-image: url("data:image/jpeg;base64,{encoded_image}");
            background-size: cover;
            background-position: center;
            filter: brightness(85%);
        }}
        </style>
        """,
        unsafe_allow_html=True
    )

# User Management
def register_user(username, password, user_type):
    conn = sqlite3.connect('toll_plaza.db')
    c = conn.cursor()
    hashed_password = sha256(password.encode()).hexdigest()
    try:
        c.execute("INSERT INTO users (username, password, user_type) VALUES (?, ?, ?)", 
                  (username, hashed_password, user_type))
        conn.commit()
        st.success("User registered successfully!")
    except sqlite3.IntegrityError:
        st.error("Username already exists.")
    finally:
        conn.close()

def login_user(username, password, user_type):
    conn = sqlite3.connect('toll_plaza.db')
    c = conn.cursor()
    hashed_password = sha256(password.encode()).hexdigest()
    c.execute("SELECT * FROM users WHERE username = ? AND password = ? AND user_type = ?", 
              (username, hashed_password, user_type))
    user = c.fetchone()
    conn.close()
    return user

# Toll Functions
def get_toll_report():
    conn = sqlite3.connect('toll_plaza.db')
    c = conn.cursor()
    c.execute("SELECT vehicle_type, COUNT(*), SUM(toll_amount) FROM tolls WHERE payment_status='Paid' GROUP BY vehicle_type")
    data = c.fetchall()
    conn.close()
    return data

# Main Application
def main():
    # Set Background
    set_background("/mnt/data/image.jpeg")

    st.title("Toll Plaza Management System")
    st.sidebar.title("Navigation")
    menu = ["Login", "Register"]
    choice = st.sidebar.selectbox("Menu", menu)

    if choice == "Login":
        st.subheader("Login Section")
        username = st.text_input("Username")
        password = st.text_input("Password", type="password")
        user_type = st.selectbox("User Type", ["Admin", "Vehicle Owner"])
        if st.button("Login"):
            user = login_user(username, password, user_type)
            if user:
                st.session_state['logged_in'] = True
                st.session_state['username'] = username
                st.session_state['user_type'] = user_type
                st.success(f"Welcome {username} ({user_type})!")
            else:
                st.warning("Incorrect Username/Password")

    elif choice == "Register":
        st.subheader("Create a New Account")
        new_user = st.text_input("Username")
        new_password = st.text_input("Password", type="password")
        user_type = st.selectbox("User Type", ["Admin", "Vehicle Owner"])
        if st.button("Register"):
            register_user(new_user, new_password, user_type)

    if 'logged_in' in st.session_state and st.session_state['logged_in']:
        user_type = st.session_state['user_type']
        username = st.session_state['username']

        st.sidebar.button("Log Out", on_click=lambda: st.session_state.clear())

        if user_type == "Admin":
            functions = ["View Toll Collection Report"]
            choice = st.selectbox("Select Function", functions)

            if choice == "View Toll Collection Report":
                st.subheader("Toll Collection Report")
                report_data = get_toll_report()
                for row in report_data:
                    st.write(f"Vehicle Type: {row[0]} - Total Vehicles: {row[1]} - Total Amount: ₹{row[2]}")

if __name__ == "__main__":
    init_db()
    main()
