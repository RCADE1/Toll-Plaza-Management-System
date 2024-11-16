import streamlit as st
import sqlite3
from datetime import datetime
from hashlib import sha256
import pandas as pd

# Database Setup
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
                    date TEXT)''')
    conn.commit()
    conn.close()

# User Registration
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
        st.error("Username already exists. Please choose a different one.")
    finally:
        conn.close()

# User Login
def login_user(username, password, user_type):
    conn = sqlite3.connect('toll_plaza.db')
    c = conn.cursor()
    hashed_password = sha256(password.encode()).hexdigest()
    c.execute("SELECT * FROM users WHERE username = ? AND password = ? AND user_type = ?", 
              (username, hashed_password, user_type))
    user = c.fetchone()
    conn.close()
    return user

# Toll Functionality
def toll_amount_calculation(vehicle_type):
    rates = {'Car': 100, 'Truck': 200, 'Bike': 50}
    return rates.get(vehicle_type, "Unknown Vehicle Type")

def assign_lane(vehicle_type):
    lanes = {'Car': 'Lane 1', 'Truck': 'Lane 2', 'Bike': 'Lane 3'}
    return lanes.get(vehicle_type, "General Lane")

def lane_management(vehicle_number, vehicle_type):
    lane = assign_lane(vehicle_type)
    st.write(f"Vehicle {vehicle_number} of type {vehicle_type} is assigned to {lane}.")
    return lane

def toll_amount_payment(vehicle_number, vehicle_type):
    amount = toll_amount_calculation(vehicle_type)
    st.write(f"The toll amount for {vehicle_type} (Vehicle Number: {vehicle_number}) is ₹{amount}.")
    if st.button("Proceed to Payment"):
        st.success("Payment Successful!")
        save_payment(vehicle_number, vehicle_type, amount, "Paid")

def save_payment(vehicle_number, vehicle_type, amount, status):
    conn = sqlite3.connect('toll_plaza.db')
    c = conn.cursor()
    lane = assign_lane(vehicle_type)
    date = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    c.execute("INSERT INTO tolls (vehicle_number, lane, vehicle_type, toll_amount, payment_status, date) VALUES (?, ?, ?, ?, ?, ?)",
              (vehicle_number, lane, vehicle_type, amount, status, date))
    conn.commit()
    conn.close()

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

def get_vehicle_owner_data():
    conn = sqlite3.connect('toll_plaza.db')
    c = conn.cursor()
    c.execute("SELECT username, user_type FROM users WHERE user_type = 'Vehicle Owner'")
    owners = c.fetchall()
    conn.close()
    
    # Formatting the data into a list of dictionaries with Row Number, Name, and User Type
    # Add a "Row Number" column starting from 1
    owners_data = [{"Row Number": idx + 1, "Name": owner[0], "User Type": owner[1]} for idx, owner in enumerate(owners)]
    
    # Convert to DataFrame for cleaner table representation
    df = pd.DataFrame(owners_data)
    return df

# Fetch transaction history for a specific vehicle owner
def get_transaction_history(username):
    conn = sqlite3.connect('toll_plaza.db')
    c = conn.cursor()
    c.execute("SELECT vehicle_number, vehicle_type, toll_amount, date FROM tolls WHERE vehicle_number IN (SELECT vehicle_number FROM users WHERE username = ?)", (username,))
    transactions = c.fetchall()
    conn.close()
    
    if transactions:
        history = pd.DataFrame(transactions, columns=["Vehicle Number", "Vehicle Type", "Toll Amount", "Date"])
        return history
    else:
        return None

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
        user_type = st.selectbox("User Type", ["Admin", "Vehicle Owner"])
        if st.button("Login"):
            user = login_user(username, password, user_type)
            if user:
                user_id, username, _, user_type = user
                st.success(f"Welcome {username} ({user_type})!")
                # Save user information in session state
                st.session_state['logged_in'] = True
                st.session_state['username'] = username
                st.session_state['user_type'] = user_type
            else:
                st.warning("Incorrect Username/Password")

    elif choice == "Register":
        st.subheader("Create a New Account")
        new_user = st.text_input("Username")
        new_password = st.text_input("Password", type="password")
        user_type = st.selectbox("User Type", ["Admin", "Vehicle Owner"])
        if st.button("Register"):
            register_user(new_user, new_password, user_type)

    elif choice == "Dashboard":
        if 'logged_in' not in st.session_state or not st.session_state['logged_in']:
            st.warning("Please login first.")
        else:
            # Show logged-in user information
            username = st.session_state.get('username', "Unknown")
            user_type = st.session_state.get('user_type', "Unknown")
            
            # Dashboard Functionality
            st.write(f"Logged in as: {username} ({user_type})")
            
            if user_type == "Admin":
                st.subheader("Admin Dashboard")
                # Display the table of registered vehicle owners with Row Numbers starting from 1
                owners_df = get_vehicle_owner_data()
                if not owners_df.empty:
                    st.write("### Registered Vehicle Owners")
                    st.table(owners_df)  # Display in table format with "Row Number", "Name", and "User Type"
                else:
                    st.write("No Vehicle Owners have registered yet.")
                
                # Reporting section for Admin only
                reporting_analysis()

            st.subheader("Toll Plaza Management Dashboard")
            functions = [
                "Toll Amount Calculation",
                "Lane Management",
            ]
            
            if user_type == "Vehicle Owner":
                functions.append("Toll Amount Payment")
                functions.append("Transaction History Check")  # Add Transaction History option only for Vehicle Owners

            selected_function = st.sidebar.selectbox("Select Function", functions)

            if selected_function == "Toll Amount Calculation":
                vehicle_type = st.selectbox("Select Vehicle Type", ["Car", "Truck", "Bike"])
                if st.button("Calculate Toll"):
                    amount = toll_amount_calculation(vehicle_type)
                    st.write(f"The toll amount for a {vehicle_type} is ₹{amount}.")

            elif selected_function == "Lane Management":
                vehicle_number = st.text_input("Enter Vehicle Number")
                vehicle_type = st.selectbox("Select Vehicle Type", ["Car", "Truck", "Bike"])
                if st.button("Assign Lane"):
                    lane_management(vehicle_number, vehicle_type)

            elif selected_function == "Toll Amount Payment" and user_type == "Vehicle Owner":
                vehicle_number = st.text_input("Enter Vehicle Number for Payment")
                vehicle_type = st.selectbox("Select Vehicle Type for Payment", ["Car", "Truck", "Bike"])
                toll_amount_payment(vehicle_number, vehicle_type)

            elif selected_function == "Transaction History Check" and user_type == "Vehicle Owner":
                st.subheader("Transaction History Check")
                transaction_history = get_transaction_history(username)
                if transaction_history is not None and not transaction_history.empty:
                    st.write(f"You have made {len(transaction_history)} transactions.")
                    st.table(transaction_history)
                else:
                    st.write("No transactions found for your vehicle number.")

# Initialize Database and Run App
if __name__ == '__main__':
    init_db()
    main()
