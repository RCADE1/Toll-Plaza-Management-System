import streamlit as st
import sqlite3
from datetime import datetime
from hashlib import sha256
import pandas as pd

# Database Setup
def init_db():
    conn = sqlite3.connect('toll_plaza.db')
    c = conn.cursor()

    # Create tables
    c.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY, 
            username TEXT UNIQUE, 
            password TEXT, 
            user_type TEXT
        )
    ''')
    c.execute('''
        CREATE TABLE IF NOT EXISTS tolls (
            id INTEGER PRIMARY KEY, 
            vehicle_number TEXT, 
            lane TEXT, 
            vehicle_type TEXT, 
            toll_amount REAL, 
            payment_status TEXT, 
            date TEXT
        )
    ''')
    c.execute('''
        CREATE TABLE IF NOT EXISTS toll_rates (
            vehicle_type TEXT PRIMARY KEY, 
            toll_amount REAL
        )
    ''')

    # Default toll rates
    default_rates = [('Car', 100), ('Truck', 200), ('Bike', 50)]
    c.executemany(
        "INSERT OR IGNORE INTO toll_rates (vehicle_type, toll_amount) VALUES (?, ?)", 
        default_rates
    )
    conn.commit()
    conn.close()

# User Registration
def register_user(username, password, user_type):
    conn = sqlite3.connect('toll_plaza.db')
    c = conn.cursor()
    hashed_password = sha256(password.encode()).hexdigest()
    try:
        c.execute(
            "INSERT INTO users (username, password, user_type) VALUES (?, ?, ?)", 
            (username, hashed_password, user_type)
        )
        conn.commit()
        st.success("User registered successfully!")
    except sqlite3.IntegrityError:
        st.error("Username already exists. Please choose a different one.")
    finally:
        conn.close()

# User Login
def login_user(username, password, user_type):
    conn = sqlite3.connect('toll_plaza.db')
    c = conn.cursor()
    hashed_password = sha256(password.encode()).hexdigest()
    c.execute(
        "SELECT * FROM users WHERE username = ? AND password = ? AND user_type = ?", 
        (username, hashed_password, user_type)
    )
    user = c.fetchone()
    conn.close()
    return user

# Toll Calculation
def toll_amount_calculation(vehicle_type):
    conn = sqlite3.connect('toll_plaza.db')
    c = conn.cursor()
    c.execute("SELECT toll_amount FROM toll_rates WHERE vehicle_type = ?", (vehicle_type,))
    result = c.fetchone()
    conn.close()
    return result[0] if result else "Unknown Vehicle Type"

# Assign Lane
def assign_lane(vehicle_type):
    lanes = {'Car': 'Lane 1', 'Truck': 'Lane 2', 'Bike': 'Lane 3'}
    return lanes.get(vehicle_type, "General Lane")

# Save Payment
def save_payment(vehicle_number, vehicle_type, amount, status):
    conn = sqlite3.connect('toll_plaza.db')
    c = conn.cursor()
    lane = assign_lane(vehicle_type)
    date = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    c.execute(
        '''
        INSERT INTO tolls 
        (vehicle_number, lane, vehicle_type, toll_amount, payment_status, date) 
        VALUES (?, ?, ?, ?, ?, ?)
        ''',
        (vehicle_number, lane, vehicle_type, amount, status, date)
    )
    conn.commit()
    conn.close()

# Transaction History
def get_transaction_history(username):
    conn = sqlite3.connect('toll_plaza.db')
    c = conn.cursor()
    c.execute("SELECT vehicle_number, vehicle_type, toll_amount, date FROM tolls WHERE vehicle_number IN (SELECT vehicle_number FROM users WHERE username = ?)", (username,))
    transactions = c.fetchall()
    conn.close()
    if transactions:
        return pd.DataFrame(transactions, columns=["Vehicle Number", "Vehicle Type", "Toll Amount", "Date"])
    else:
        return None

# Reporting and Analysis
def reporting_analysis():
    conn = sqlite3.connect('toll_plaza.db')
    c = conn.cursor()
    c.execute("SELECT vehicle_type, COUNT(*), SUM(toll_amount) FROM tolls WHERE payment_status='Paid' GROUP BY vehicle_type")
    data = c.fetchall()
    conn.close()

    st.subheader("Toll Collection Report")
    for vehicle_type, count, total_amount in data:
        st.write(f"Vehicle Type: {vehicle_type}")
        st.write(f"Total Vehicles: {count}")
        st.write(f"Total Amount Collected: ₹{total_amount}")
        st.write("---")

# Update Toll Rates
def update_toll_rates():
    st.subheader("Update Toll Rates")
    vehicle_type = st.selectbox("Select Vehicle Type", ["Car", "Truck", "Bike"])
    current_rate = toll_amount_calculation(vehicle_type)
    st.write(f"Current Toll Rate for {vehicle_type}: ₹{current_rate}")
    new_rate = st.number_input("Enter New Toll Rate", min_value=0.0, value=current_rate)
    if st.button("Save Rate"):
        conn = sqlite3.connect('toll_plaza.db')
        c = conn.cursor()
        c.execute("UPDATE toll_rates SET toll_amount = ? WHERE vehicle_type = ?", (new_rate, vehicle_type))
        conn.commit()
        conn.close()
        st.success(f"Toll rate updated to ₹{new_rate}")

# Main Streamlit App
def main():
    st.title("Toll Plaza Management System")
    st.sidebar.title("Navigation")
    menu = ["Login", "Register", "Dashboard"]
    choice = st.sidebar.selectbox("Menu", menu)

    if choice == "Login":
        st.subheader("Login Section")
        username = st.text_input("Username")
        password = st.text_input("Password", type="password")
        user_type = st.selectbox("User Type", ["Admin", "Vehicle Owner"])
        if st.button("Login"):
            user = login_user(username, password, user_type)
            if user:
                st.session_state['username'] = username
                st.session_state['user_type'] = user_type
                st.success(f"Welcome {username} ({user_type})!")
            else:
                st.warning("Invalid credentials!")

    elif choice == "Register":
        st.subheader("Register")
        username = st.text_input("Username")
        password = st.text_input("Password", type="password")
        user_type = st.selectbox("User Type", ["Admin", "Vehicle Owner"])
        if st.button("Register"):
            register_user(username, password, user_type)

    elif choice == "Dashboard":
        if 'username' not in st.session_state:
            st.warning("Please log in first.")
        else:
            username = st.session_state['username']
            user_type = st.session_state['user_type']
            st.write(f"Logged in as: {username} ({user_type})")
            if user_type == "Admin":
                update_toll_rates()
                reporting_analysis()
            elif user_type == "Vehicle Owner":
                st.write("Vehicle Owner Dashboard")

# Run the app
if __name__ == '__main__':
    init_db()
    main()
