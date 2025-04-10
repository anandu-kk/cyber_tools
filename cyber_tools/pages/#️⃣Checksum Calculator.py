import streamlit as st
import hashlib

st.title("Checksum Calculator")
original_hash="aaa"


uploaded_file=st.file_uploader("Choose a file")
hash_type=st.selectbox("Select the type of hash",("MD5","SHA1","SHA256" ))
original_hash=st.text_input("Enter the original hash").strip()

is_validated=uploaded_file and original_hash

submitted=st.button(label="Compare Hash" ,disabled=not is_validated)

if submitted:
    if hash_type=="MD5":
        hasher=hashlib.md5()    
    elif hash_type=="SHA1":
        hasher=hashlib.sha1()
    elif hash_type=="SHA256":
        hasher=hashlib.sha256()

    for chunk in iter(lambda: uploaded_file.read(4096), b''):
        hasher.update(chunk)
    new_hash=hasher.hexdigest()
    
    if new_hash==original_hash:
        st.success("Matching hashes")
    else:
        st.error("Hashes not matching")

    
    
