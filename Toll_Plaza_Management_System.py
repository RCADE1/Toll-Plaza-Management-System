import streamlit as st
import sqlite3
from datetime import datetime
from hashlib import sha256
import re
import pandas as pd


# Initialize Database
def init_db():
    conn = sqlite3.connect('toll_plaza.db')
    c = conn.cursor()

    # Create the `users` table with email column
    c.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY, 
            username TEXT UNIQUE, 
            email TEXT UNIQUE, 
            password TEXT, 
            user_type TEXT
        )
    ''')

    # Create the `tolls` table
    c.execute('''
        CREATE TABLE IF NOT EXISTS tolls (
            id INTEGER PRIMARY KEY, 
            username TEXT, 
            vehicle_number TEXT, 
            lane TEXT, 
            vehicle_type TEXT, 
            toll_amount REAL, 
            payment_status TEXT, 
            date TEXT
        )
    ''')

    # Create the `toll_rates` table
    c.execute('''
        CREATE TABLE IF NOT EXISTS toll_rates (
            vehicle_type TEXT PRIMARY KEY, 
            toll_amount REAL
        )
    ''')

    # Insert default toll rates
    default_rates = [('Car', 100), ('Truck', 200), ('Bike', 50)]
    c.executemany(
        "INSERT OR IGNORE INTO toll_rates (vehicle_type, toll_amount) VALUES (?, ?)",
        default_rates
    )

    conn.commit()
    conn.close()


# Email Validation Function
def is_valid_email(email):
    # Regex pattern for email validation
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return re.match(pattern, email) is not None


# Register User
def register_user(username, email, password, user_type):
    if not username or not email or not password:
        st.error("All fields are required!")
        return

    # Validate email
    if not is_valid_email(email):
        st.error("Invalid email address! Please ensure the email meets the following criteria:")
        st.write("""
        - Contains an '@' symbol.
        - Contains a '.' after the '@'.
        - The local part (before '@') must not be empty.
        - The domain (after '@') must be valid.
        """)
        return

    conn = sqlite3.connect('toll_plaza.db')
    c = conn.cursor()
    hashed_password = sha256(password.encode()).hexdigest()
    try:
        # Insert user into the database
        c.execute(
            "INSERT INTO users (username, email, password, user_type) VALUES (?, ?, ?, ?)",
            (username, email, hashed_password, user_type)
        )
        conn.commit()
        st.success("User registered successfully!")
    except sqlite3.IntegrityError as e:
        if "UNIQUE constraint failed" in str(e):
            st.error("Username or email already exists. Please use a different one.")
        else:
            st.error(f"An error occurred: {e}")
    finally:
        conn.close()


# Login User
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


# Toll Amount Calculation
def toll_amount_calculation(vehicle_type):
    conn = sqlite3.connect('toll_plaza.db')
    c = conn.cursor()
    c.execute("SELECT toll_amount FROM toll_rates WHERE vehicle_type = ?", (vehicle_type,))
    result = c.fetchone()
    conn.close()
    return result[0] if result else "Unknown Vehicle Type"


# Lane Management
def assign_lane(vehicle_type):
    lanes = {'Car': 'Lane 1', 'Truck': 'Lane 2', 'Bike': 'Lane 3'}
    return lanes.get(vehicle_type, "General Lane")


# Save Payment
def save_payment(username, vehicle_number, vehicle_type, toll_amount, status):
    conn = sqlite3.connect('toll_plaza.db')
    c = conn.cursor()
    lane = assign_lane(vehicle_type)
    date = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    c.execute(
        '''
        INSERT INTO tolls (username, vehicle_number, lane, vehicle_type, toll_amount, payment_status, date) 
        VALUES (?, ?, ?, ?, ?, ?, ?)
        ''',
        (username, vehicle_number, lane, vehicle_type, toll_amount, status, date)
    )
    conn.commit()
    conn.close()


# Transaction History
def get_transaction_history(username):
    conn = sqlite3.connect('toll_plaza.db')
    c = conn.cursor()
    c.execute("SELECT vehicle_number, vehicle_type, toll_amount, payment_status, date FROM tolls WHERE username = ?", (username,))
    transactions = c.fetchall()
    conn.close()

    if transactions:
        df = pd.DataFrame(transactions, columns=["Vehicle Number", "Vehicle Type", "Toll Amount", "Payment Status", "Date"])
        return df
    else:
        return None


# Update Toll Rates
def update_toll_rates():
    st.subheader("Update Toll Rates")
    vehicle_type = st.selectbox("Select Vehicle Type to Update", ["Car", "Truck", "Bike"])
    current_rate = toll_amount_calculation(vehicle_type)
    st.write(f"Current Toll Rate for {vehicle_type}: ₹{current_rate}")
    new_rate = st.number_input(f"Enter New Toll Rate for {vehicle_type}", min_value=0.0, value=current_rate)
    if st.button("Save New Rate"):
        conn = sqlite3.connect('toll_plaza.db')
        c = conn.cursor()
        c.execute("UPDATE toll_rates SET toll_amount = ? WHERE vehicle_type = ?", (new_rate, vehicle_type))
        conn.commit()
        conn.close()
        st.success(f"Toll rate for {vehicle_type} updated to ₹{new_rate}")


# Reporting and Analysis
def reporting_analysis():
    conn = sqlite3.connect('toll_plaza.db')
    c = conn.cursor()
    c.execute("SELECT vehicle_type, COUNT(*), SUM(toll_amount) FROM tolls WHERE payment_status = 'Paid' GROUP BY vehicle_type")
    data = c.fetchall()
    conn.close()

    st.subheader("Toll Collection Report")
    for vehicle_type, count, total_amount in data:
        st.write(f"Vehicle Type: {vehicle_type}")
        st.write(f"Total Vehicles: {count}")
        st.write(f"Total Amount Collected: ₹{total_amount}")
        st.write("---")


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
                st.success(f"Welcome {user[1]} ({user[4]})!")
                st.session_state['username'] = user[1]
                st.session_state['user_type'] = user[4]
            else:
                st.warning("Invalid login credentials.")

    elif choice == "Register":
        st.subheader("Register")
        username = st.text_input("Username")
        email = st.text_input("Email Address")
        password = st.text_input("Password", type="password")
        user_type = st.selectbox("User Type", ["Admin", "Vehicle Owner"])
        if st.button("Register"):
            register_user(username, email, password, user_type)

    elif choice == "Dashboard":
        if 'username' not in st.session_state:
            st.warning("Please log in first.")
            return

        username = st.session_state['username']
        user_type = st.session_state['user_type']
        st.write(f"Logged in as: {username} ({user_type})")

        if user_type == "Admin":
            st.subheader("Admin Dashboard")
            update_toll_rates()
            reporting_analysis()

        elif user_type == "Vehicle Owner":
            st.subheader("Vehicle Owner Dashboard")
            vehicle_number = st.text_input("Enter Vehicle Number")
            vehicle_type = st.selectbox("Select Vehicle Type", ["Car", "Truck", "Bike"])
            if st.button("Pay Toll"):
                toll_amount = toll_amount_calculation(vehicle_type)
                save_payment(username, vehicle_number, vehicle_type, toll_amount, "Paid")
                st.success(f"Payment of ₹{toll_amount} completed!")

            st.subheader("Transaction History")
            transactions = get_transaction_history(username)
            if transactions is not None:
                st.table(transactions)
            else:
                st.write("No transactions found.")


# Initialize Database and Run App
if __name__ == '__main__':
    init_db()
    main()
