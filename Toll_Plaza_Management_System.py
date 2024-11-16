import streamlit as st
import sqlite3
from datetime import datetime
from hashlib import sha256

# Database setup
def init_db():
    """Initialize the database and create tables if they don't exist."""
    conn = sqlite3.connect('toll_plaza.db')
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY, 
                    username TEXT UNIQUE, 
                    password TEXT, 
                    user_type TEXT)''')  # Added UNIQUE constraint for username
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

def register_user(username, password, user_type):
    """Register a new user in the database."""
    if not username or not password or not user_type:
        st.warning("All fields are required for registration.")
        return

    try:
        conn = sqlite3.connect('toll_plaza.db')
        c = conn.cursor()
        hashed_password = sha256(password.encode()).hexdigest()
        c.execute("INSERT INTO users (username, password, user_type) VALUES (?, ?, ?)", 
                  (username, hashed_password, user_type))
        conn.commit()
        conn.close()
        st.success("Registration successful!")
    except sqlite3.IntegrityError as e:
        st.error(f"Error: {e}")
    except Exception as e:
        st.error(f"Unexpected error: {e}")
    finally:
        if conn:
            conn.close()

def login_user(username, password):
    """Authenticate a user and return their details if valid."""
    if not username or not password:
        st.warning("Username and password are required for login.")
        return None

    conn = sqlite3.connect('toll_plaza.db')
    c = conn.cursor()
    hashed_password = sha256(password.encode()).hexdigest()
    c.execute("SELECT * FROM users WHERE username = ? AND password = ?", (username, hashed_password))
    data = c.fetchone()
    conn.close()
    return data

# Main Streamlit app
def main():
    # Initialize session state
    if 'logged_in' not in st.session_state:
        st.session_state['logged_in'] = False
    if 'username' not in st.session_state:
        st.session_state['username'] = None
    if 'user_type' not in st.session_state:
        st.session_state['user_type'] = None

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
                st.session_state['user_type'] = user[3]  # Fetch user type from the database
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
        if not st.session_state['logged_in']:
            st.warning("Please login first.")
        else:
            user_type = st.session_state['user_type']
            st.subheader(f"Dashboard for {user_type}")
            st.sidebar.write("## Functions")

            if user_type == "Admin":
                functions = ["Reporting and Analysis", "Vehicle Management and Classification"]
            else:
                functions = ["Toll Amount Calculation", "Lane Management", "Toll Amount Payment"]

            selected_function = st.sidebar.selectbox("Select Function", functions)

            if selected_function == "Toll Amount Calculation":
                st.subheader("Toll Amount Calculation")
                vehicle_type = st.selectbox("Select Vehicle Type", ["Car", "Truck", "Bike"])
                if st.button("Calculate"):
                    amount = toll_amount_calculation(vehicle_type)
                    st.write(f"The toll amount for a {vehicle_type} is ₹{amount}.")

            elif selected_function == "Lane Management":
                st.subheader("Lane Management")
                vehicle_number = st.text_input("Enter Vehicle Number")
                vehicle_type = st.selectbox("Select Vehicle Type", ["Car", "Truck", "Bike"])
                if st.button("Assign Lane"):
                    lane = lane_management(vehicle_number, vehicle_type)
                    st.write(f"Assigned Lane: {lane}")

            elif selected_function == "Toll Amount Payment":
                st.subheader("Toll Amount Payment")
                vehicle_number = st.text_input("Enter Vehicle Number for Payment")
                vehicle_type = st.selectbox("Select Vehicle Type for Payment", ["Car", "Truck", "Bike"])
                toll_amount_payment(vehicle_number, vehicle_type)

            elif selected_function == "Reporting and Analysis":
                reporting_analysis()

            elif selected_function == "Vehicle Management and Classification":
                vehicle_management_classification()

# Initialize Database and Run App
if __name__ == '__main__':
    init_db()
    main()
