import streamlit as st
import mysql.connector
import hashlib
from google.oauth2 import id_token
from google_auth_oauthlib.flow import Flow
from google.auth.transport.requests import Request


GOOGLE_CLIENT_ID = "114743897872-gdumt08asn8crd5cerpn6a5380i4f0ad.apps.googleusercontent.com"
GOOGLE_CLIENT_SECRET = "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"
GOOGLE_REDIRECT_URI = "http://localhost:8501"

def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

def connect_to_database():
    return mysql.connector.connect(
        host="localhost",
        user="root",
        password="Rohit@123",
        database="genai"
    )

def authenticate(username, password):
    conn = connect_to_database()
    cursor = conn.cursor()

    query = "SELECT * FROM users WHERE username = %s"
    cursor.execute(query, (username,))
    user = cursor.fetchone()

    if user:
        stored_password_hash = user[2]
        password_hash = hash_password(password)
        if stored_password_hash == password_hash:
            return True, user[3]
        else:
            return False, None
    else:
        return False, None

def create_user(username, password, role):
    conn = connect_to_database()
    cursor = conn.cursor()

    password_hash = hash_password(password)

    query = "INSERT INTO users (username, password_hash, role) VALUES (%s, %s, %s)"
    cursor.execute(query, (username, password_hash, role))
    conn.commit()

    return True

# Google sign-in function
def google_sign_in():
    flow = Flow.from_client_secrets_file(
        "/Users/rohitronkhede/Desktop/UI/client_secret_114743897872-gdumt08asn8crd5cerpn6a5380i4f0ad.apps.googleusercontent.com.json",
        scopes=["openid", "https://www.googleapis.com/auth/userinfo.email", "https://www.googleapis.com/auth/userinfo.profile"],
        redirect_uri=GOOGLE_REDIRECT_URI
    )
    auth_url, _ = flow.authorization_url(prompt="consent")

    if 'code' not in st.session_state:
        st.write(f"Click [here]({auth_url}) to sign up with Google.")
        role = st.selectbox("Role", ["Admin", "Normal"])
        st.session_state.role = role
    else:
        try:
            flow.fetch_token(code=st.session_state.code)
            id_info = id_token.verify_oauth2_token(flow.credentials._id_token, Request(), GOOGLE_CLIENT_ID)

            # Check if the user exists in the database
            conn = connect_to_database()
            cursor = conn.cursor()
            query = "SELECT * FROM users WHERE username = %s"
            cursor.execute(query, (id_info['email'],))
            user = cursor.fetchone()

            if user:
                st.success("Signed in successfully.")
                st.session_state.is_signed_in = True
                st.session_state.user_role = user[3]
            else:
                # Create the user with the selected role
                if create_user(id_info['email'], '', st.session_state.role):
                    st.success("Signed up successfully. Please sign in.")
                else:
                    st.error("Failed to sign up. Please try again.")
        except Exception as e:
            st.error("Error signing in with Google.")
            st.session_state.is_signed_in = False
            st.session_state.user_role = None

def sign_in():
    st.write("## Sign In")
    username = st.text_input("Username")
    password = st.text_input("Password", type="password")
    if st.button("Sign In"):
        authenticated, role = authenticate(username, password)
        if authenticated:
            st.success("Signed in successfully.")
            st.session_state.is_signed_in = True
            st.session_state.user_role = role
        else:
            st.error("Invalid username or password.")

def sign_up():
    st.write("## Sign Up")
    username = st.text_input("Username")
    password = st.text_input("Password", type="password")
    role = st.selectbox("Role", ["Admin", "Normal"])
    if st.button("Sign Up"):
        if create_user(username, password, role):
            st.success("Signed up successfully. Please sign in.")
        else:
            st.error("Failed to sign up. Please try again.")

def main():
    st.title("Welcome to our chatbot")

    st.session_state.setdefault("is_signed_in", False)
    st.session_state.setdefault("user_role", None)

    action = st.sidebar.radio("Select Action", ["Sign In", "Sign Up", "Sign Up with Google"])

    if action == "Sign In":
        sign_in()
    elif action == "Sign Up":
        sign_up()
    elif action == "Sign Up with Google":
        google_sign_in()

    if st.session_state.is_signed_in:
        if st.session_state.user_role == "Admin":
            st.write("Admin UI")
            # Add admin UI components here
        
            st.title("Chat Bot")
            if "messages" not in  st.session_state:
                st.session_state.messages = []
    
            for message in st.session_state.messages:
                with st.chat_message(message["role"]):
                    st.markdown(message["content"])


            prompt = st.chat_input("What is up?")
            if prompt:
                with st.chat_message("user"):
                    st.markdown(prompt)
                st.session_state.messages.append({"role":"user","content":"prompt"})

            response = f"Chat Bot: {prompt}"
            with st.chat_message("assistant"):
                st.markdown(response)
            st.session_state.messages.append({"role":"assistant","content":"response"})


    elif st.session_state.user_role == "Normal":
        st.write("Normal User UI")
        # Add normal user UI components here
        

if __name__ == "__main__":
    main()
