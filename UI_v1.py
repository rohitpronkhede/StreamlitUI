import streamlit as st
import mysql.connector

# Initialize session state
if 'is_signed_in' not in st.session_state:
    st.session_state.is_signed_in = False
if 'user_role' not in st.session_state:
    st.session_state.user_role = None

# Function to authenticate admin user from MySQL database
def authenticate_admin(username, password):
    try:
        # Connect to MySQL database
        conn = mysql.connector.connect(
            host="localhost",
            user="root",
            password="Rohit@123",
            database="genai"
        )

        # Execute SQL query to fetch admin user with given username and password
        cursor = conn.cursor()
        query = "SELECT * FROM admin_users WHERE username = %s AND password = %s"
        cursor.execute(query, (username, password))
        user = cursor.fetchone()

        if user:
            return True
        else:
            return False

    except mysql.connector.Error as e:
        st.error(f"Error connecting to MySQL database: {e}")
        return False

# Function to authenticate normal user from MySQL database
def authenticate_normal_user(username, password):
    try:
        # Connect to MySQL database
        conn = mysql.connector.connect(
            host="localhost",
            user="root",
            password="Rohit@123",
            database="genai"
        )

        # Execute SQL query to fetch normal user with given username and password
        cursor = conn.cursor()
        query = "SELECT * FROM normal_users WHERE username = %s AND password = %s"
        cursor.execute(query, (username, password))
        user = cursor.fetchone()

        if user:
            return True
        else:
            return False

    except mysql.connector.Error as e:
        st.error(f"Error connecting to MySQL database: {e}")
        return False

# Function to create a new admin user in MySQL database
def create_admin_user(username, password):
    try:
        # Connect to MySQL database
        conn = mysql.connector.connect(
            host="localhost",
            user="root",
            password="Rohit@123",
            database="genai"
        )

        # Execute SQL query to insert new admin user
        cursor = conn.cursor()
        query = "INSERT INTO admin_users (username, password) VALUES (%s, %s)"
        cursor.execute(query, (username, password))
        conn.commit()

        st.success("Admin user created successfully")
        return True

    except mysql.connector.Error as e:
        st.error(f"Error connecting to MySQL database: {e}")
        return False

# Function to create a new normal user in MySQL database
def create_normal_user(username, password):
    try:
        # Connect to MySQL database
        conn = mysql.connector.connect(
            host="localhost",
            user="root",
            password="Rohit@123",
            database="genai"
        )

        # Execute SQL query to insert new normal user
        cursor = conn.cursor()
        query = "INSERT INTO normal_users (username, password) VALUES (%s, %s)"
        cursor.execute(query, (username, password))
        conn.commit()

        st.success("Normal user created successfully")
        return True

    except mysql.connector.Error as e:
        st.error(f"Error connecting to MySQL database: {e}")
        return False

# Define function for admin sign-in
def admin_sign_in():
    st.write("Admin Sign In Form")
    
    # Username input field
    username = st.text_input("Username")

    # Password input field (masked)
    password = st.text_input("Password", type="password")

    # Sign-in button
    if st.button("Sign In"):
        # Authenticate admin user
        if authenticate_admin(username, password):
            st.success("Admin sign in successful")
            st.session_state.is_signed_in = True
            st.session_state.user_role = "admin"
        else:
            st.error("Invalid username or password")

# Define function for normal user sign-in
def user_sign_in():
    st.write("Normal User Sign In Form")
    
    # Username input field
    username = st.text_input("Username")

    # Password input field (masked)
    password = st.text_input("Password", type="password")

    # Sign-in button
    if st.button("Sign In"):
        # Authenticate normal user
        if authenticate_normal_user(username, password):
            st.success("Normal user sign in successful")
            st.session_state.is_signed_in = True
            st.session_state.user_role = "normal"
        else:
            st.error("Invalid username or password")

# Define function for admin sign-up
def admin_sign_up():
    st.write("Admin Sign Up Form")
    
    # Username input field
    username = st.text_input("Username")

    # Password input field (masked)
    password = st.text_input("Password", type="password")

    # Sign-up button
    if st.button("Sign Up"):
        # Create admin user
        if create_admin_user(username, password):
            st.success("Admin user created successfully. Please sign in.")
        else:
            st.error("Failed to create admin user. Please try again.")

# Define function for normal user sign-up
def user_sign_up():
    st.write("Normal User Sign Up Form")
    
    # Username input field
    username = st.text_input("Username")

    # Password input field (masked)
    password = st.text_input("Password", type="password")

    # Sign-up button
    if st.button("Sign Up"):
        # Create normal user
        if create_normal_user(username, password):
            st.success("Normal user created successfully. Please sign in.")
        else:
            st.error("Failed to create normal user. Please try again.")

# Main Streamlit app
def main():
    st.title("Authentication Example")

    # Create sidebar navigation for roles and authentication options
    action = st.sidebar.radio("Select Action", ["Sign In", "Sign Up"])
    role = st.sidebar.radio("Select Role", ["Admin", "Normal User"])

    # Display appropriate authentication options based on action and role
    if action == "Sign In":
        if role == "Admin":
            admin_sign_in()
        elif role == "Normal User":
            user_sign_in()
    elif action == "Sign Up":
        if role == "Admin":
            admin_sign_up()
        elif role == "Normal User":
            user_sign_up()

    # After successful sign-in, provide chat interface based on user role
    if st.session_state.is_signed_in:
        user_role = st.session_state.user_role
        st.write(f"Chat interface for {user_role} user")

if __name__ == "__main__":
    main()
