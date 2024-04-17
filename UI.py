import streamlit as st
import mysql.connector

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

def chat_interface(user_role):
    st.write(f"Chat interface for {user_role} user")


def main():
    st.title("Chatbot with Authentication")

    # Create sidebar navigation for roles
    role = st.sidebar.radio("Select Role", ["Admin", "Normal User"])

    # Display appropriate authentication options based on role
    if role == "Admin":
        admin_sign_in()
    elif role == "Normal User":
        user_sign_in()

    # After successful sign-in, provide chat interface based on user role
    if st.session_state.is_signed_in:
        user_role = st.session_state.user_role
        chat_interface(user_role)

if __name__ == "__main__":
    main()


