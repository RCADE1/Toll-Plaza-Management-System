import streamlit as st
import sqlite3
from datetime import datetime
from hashlib import sha256

# Database setup
def init_db():
    conn = sqlite3.connect('toll_plaza.db')
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY, 
                    username TEXT, 
                    password TEXT)''')
    c.execute('''CREATE TABLE IF NOT EXISTS tolls (
                    id INTEGER PRIMARY KEY, 
                    lane TEXT, 
                    vehicle_type TEXT, 
                    toll_amount REAL, 
                    payment_status TEXT, 
                    date TEXT)''')
    conn.commit()
    conn.close()

def register_user(username, password):
    conn = sqlite3.connect('toll_plaza.db')
    c = conn.cursor()
    hashed_password = sha256(password.encode()).hexdigest()
    c.execute("INSERT INTO users (username, password) VALUES (?, ?)", (username, hashed_password))
    conn.commit()
    conn.close()

def login_user(username, password):
    conn = sqlite3.connect('toll_plaza.db')
    c = conn.cursor()
    hashed_password = sha256(password.encode()).hexdigest()
    c.execute("SELECT * FROM users WHERE username = ? AND password = ?", (username, hashed_password))
    data = c.fetchone()
    conn.close()
    return data

# Toll Plaza Functionalities
def toll_amount_calculation(vehicle_type):
    rates = {'Car': 100, 'Truck': 200, 'Bike': 50}
    return rates.get(vehicle_type, "Unknown Vehicle Type")

def lane_management():
    st.write("Lane Management functionality here...")

def user_account_management():
    st.write("User Account Management functionality here...")

def toll_amount_payment(vehicle_type):
    amount = toll_amount_calculation(vehicle_type)
    st.write(f"The toll amount for {vehicle_type} is {amount}. Proceed to payment.")

def reporting_analysis():
    st.write("Reporting and Analysis of Toll Collections functionality here...")

def vehicle_management_classification():
    st.write("Vehicle Management and Classification functionality here...")

# Streamlit App
def main():
    st.title("Toll Plaza Management System")
    st.sidebar.title("Navigation")
    menu = ["Login", "Register", "Dashboard"]
    choice = st.sidebar.selectbox("Menu", menu)

    if choice == "Login":
        st.subheader("Login Section")
        username = st.text_input("Username")
        password = st.text_input("Password", type="password")
        if st.button("Login"):
            user = login_user(username, password)
            if user:
                st.success(f"Welcome {username}!")
                st.session_state['logged_in'] = True
                st.session_state['username'] = username
            else:
                st.warning("Incorrect Username/Password")

    elif choice == "Register":
        st.subheader("Create a New Account")
        new_user = st.text_input("Username")
        new_password = st.text_input("Password", type="password")
        if st.button("Register"):
            register_user(new_user, new_password)
            st.success("You have successfully created an account!")
            st.info("Go to Login Menu to login")

    elif choice == "Dashboard":
        if 'logged_in' not in st.session_state or not st.session_state['logged_in']:
            st.warning("Please login first.")
        else:
            st.subheader("Toll Plaza Management Dashboard")
            st.sidebar.write("## Functions")
            functions = [
                "Toll Amount Calculation",
                "Lane Management",
                "User Account Management",
                "Toll Amount Payment",
                "Reporting and Analysis",
                "Vehicle Management and Classification"
            ]
            selected_function = st.sidebar.selectbox("Select Function", functions)

            if selected_function == "Toll Amount Calculation":
                st.subheader("Toll Amount Calculation")
                vehicle_type = st.selectbox("Select Vehicle Type", ["Car", "Truck", "Bike"])
                if st.button("Calculate"):
                    amount = toll_amount_calculation(vehicle_type)
                    st.write(f"The toll amount for a {vehicle_type} is ₹{amount}.")

            elif selected_function == "Lane Management":
                lane_management()

            elif selected_function == "User Account Management":
                user_account_management()

            elif selected_function == "Toll Amount Payment":
                vehicle_type = st.selectbox("Select Vehicle Type for Payment", ["Car", "Truck", "Bike"])
                toll_amount_payment(vehicle_type)

            elif selected_function == "Reporting and Analysis":
                reporting_analysis()

            elif selected_function == "Vehicle Management and Classification":
                vehicle_management_classification()

# Initialize Database and Run App
if __name__ == '__main__':
    init_db()
    main()
