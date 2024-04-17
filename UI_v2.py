import streamlit as st
import mysql.connector
import hashlib

if 'is_signed_in' not in st.session_state:
    st.session_state.is_signed_in = False
if 'user_role' not in st.session_state:
    st.session_state.user_role = None


def authenticate_admin(username, password):
    try:
        conn = mysql.connector.connect(
            host="localhost",
            user="root",
            password="Rohit@123",
            database="genai"
        )

        cursor = conn.cursor()
        query = "SELECT * FROM admin_users WHERE username = %s"
        cursor.execute(query, (username,))
        user = cursor.fetchone()

        if user:
            stored_password_hash = user[2]  
            password_hash = hashlib.sha256(password.encode()).hexdigest()
            if stored_password_hash == password_hash:
                return True
            else:
                return False
        else:
            return False

    except mysql.connector.Error as e:
        st.error(f"Error connecting to MySQL database: {e}")
        return False

def authenticate_normal_user(username, password):
    try:
        conn = mysql.connector.connect(
            host="localhost",
            user="root",
            password="Rohit@123",
            database="genai"
        )

        cursor = conn.cursor()
        query = "SELECT * FROM normal_users WHERE username = %s"
        cursor.execute(query, (username,))
        user = cursor.fetchone()

        if user:
            stored_password_hash = user[2]  
            password_hash = hashlib.sha256(password.encode()).hexdigest()
            if stored_password_hash == password_hash:
                return True
            else:
                return False
        else:
            return False

    except mysql.connector.Error as e:
        st.error(f"Error connecting to MySQL database: {e}")
        return False

def create_admin_user(username, password):
    try:
        conn = mysql.connector.connect(
            host="localhost",
            user="root",
            password="Rohit@123",
            database="genai"
        )

        password_hash = hashlib.sha256(password.encode()).hexdigest()

        cursor = conn.cursor()
        query = "INSERT INTO admin_users (username, password_hash) VALUES (%s, %s)"
        cursor.execute(query, (username, password_hash))
        conn.commit()

        st.success("Admin user created successfully")
        return True

    except mysql.connector.Error as e:
        st.error(f"Error connecting to MySQL database: {e}")
        return False

def create_normal_user(username, password):
    try:
        conn = mysql.connector.connect(
            host="localhost",
            user="root",
            password="Rohit@123",
            database="genai"
        )

        password_hash = hashlib.sha256(password.encode()).hexdigest()

        cursor = conn.cursor()
        query = "INSERT INTO normal_users (username, password_hash) VALUES (%s, %s)"
        cursor.execute(query, (username, password_hash))
        conn.commit()

        st.success("Normal user created successfully")
        return True

    except mysql.connector.Error as e:
        st.error(f"Error connecting to MySQL database: {e}")
        return False

def admin_sign_in():
    st.write("Admin Sign In Form")
    
    username = st.text_input("Username")

    password = st.text_input("Password", type="password")

    if st.button("Sign In"):
        
        if authenticate_admin(username, password):
            st.success("Admin sign in successful")
            st.session_state.is_signed_in = True
            st.session_state.user_role = "admin"
        else:
            st.error("Invalid username or password")

def user_sign_in():
    st.write("Normal User Sign In Form")
    
    username = st.text_input("Username")

    password = st.text_input("Password", type="password")

    if st.button("Sign In"):

        if authenticate_normal_user(username, password):
            st.success("Normal user sign in successful")
            st.session_state.is_signed_in = True
            st.session_state.user_role = "normal"
        else:
            st.error("Invalid username or password")


def admin_sign_up():
    st.write("Admin Sign Up Form")
    
    username = st.text_input("Username")

    password = st.text_input("Password", type="password")

    if st.button("Sign Up"):
        
        if create_admin_user(username, password):
            st.success("Admin user created successfully. Please sign in.")
        else:
            st.error("Failed to create admin user. Please try again.")

def user_sign_up():
    st.write("Normal User Sign Up Form")
  
    username = st.text_input("Username")

    password = st.text_input("Password", type="password")

    if st.button("Sign Up"):
       
        if create_normal_user(username, password):
            st.success("Normal user created successfully. Please sign in.")
        else:
            st.error("Failed to create normal user. Please try again.")

def main():
    st.title("Authentication Example")

    action = st.sidebar.radio("Select Action", ["Sign In", "Sign Up"])
    role = st.sidebar.radio("Select Role", ["Admin", "Normal User"])

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

    if st.session_state.is_signed_in:
        user_role = st.session_state.user_role
        st.write(f"Chat interface for {user_role} user")

if __name__ == "__main__":
    main()
