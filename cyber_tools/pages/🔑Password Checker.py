import streamlit as st
import string

st.title("Password integrity checker")

st.session_state.common=False

with open(r"C:\Users\anand\Documents\VS code\python\streamlit\common_pass.txt","r", encoding="utf-8") as file: 

    common_passwords=[line.strip() for line in file]

if "score" not in st.session_state:
    st.session_state.score = 0


def password_strength():

    text = st.session_state.password 
    
    score = 0
    length = len(text)

    upper_case = any(c.isupper() for c in text)
    lower_case = any(c.islower() for c in text)
    special = any(c in string.punctuation for c in text)
    digits = any(c.isdigit() for c in text)

    characters = [upper_case, lower_case, special, digits]

    if length > 8:
        score += 1
    if length > 12:
        score += 1
    if length > 17:
        score += 1
    if length > 20:
        score += 1

    score += sum(characters)
    
    st.session_state.score=score

    if text in common_passwords:
        st.error("⚠️ This password is found in the common password list!")
        st.session_state.score=0

    

password=st.text_input("Enter the password",key="password",on_change=password_strength)

progress=min(st.session_state.score, 7) * (1/7)

progress = max(0, min(progress, 1))

st.progress(progress)

st.write("Password strength : ",st.session_state.score)




