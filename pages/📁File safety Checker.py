import os
import requests
import streamlit as st
import hashlib
import time
from dotenv import load_dotenv

load_dotenv()

api_key=os.getenv("VIRUSTOTAL_API_KEY")
headers = {
    "accept": "application/json",
    "x-apikey": api_key
    }

def existing_report():
    detected=response.json()["data"]["attributes"]["last_analysis_stats"]["malicious"]
    total_scans=sum(response.json()["data"]["attributes"]["last_analysis_stats"].values())
    if detected>0:
        st.error(f"{detected} out of {total_scans} antiviruses found the given file as malicious")
    else:
        st.success(f"{detected} out of {total_scans} antiviruses found the given file as malicious")

    with st.expander("see details"):
        for i in response.json()["data"]["attributes"]["last_analysis_results"]:
            st.write(i+" : "+response.json()["data"]["attributes"]["last_analysis_results"][i]["category"])

def new_scan():
    if uploaded_file.size>32000000:  #if size bigger than 32 MB
        new_url = "https://www.virustotal.com/api/v3/files/upload_url"
        new_response= requests.get(url=new_url, headers=headers)
        if new_response.status_code!=200:
            st.error("upload link not available")
        upload_url=new_response.json()["data"]
    else:  #if size smaller than 32 MB
        upload_url = "https://www.virustotal.com/api/v3/files"
    files = { "file": (uploaded_file.name, uploaded_file, "application/x-msdownload") }
    response = requests.post(upload_url, files=files, headers=headers)
    report_url=response.json()["data"]["links"]["self"]
    response=requests.get(url=report_url,headers=headers)
    with st.spinner("Scanning..."):
        while response.json()["data"]["attributes"]["status"]!="completed":
            time.sleep(2)
            response = requests.get(url=report_url,headers=headers)
    detected=response.json()["data"]["attributes"]["stats"]["malicious"]
    total_scans=sum(response.json()["data"]["attributes"]["stats"].values())
    if detected>0:
        st.error(f"{detected} out of {total_scans} antiviruses found the given file as malicious")
    else:
        st.success(f"{detected} out of {total_scans} antiviruses found the given file as malicious")
    with st.expander("see details"):
        for i in response.json()["data"]["attributes"]["results"]:
            st.write(i+" : "+response.json()["data"]["attributes"]["results"][i]["category"])


            
uploaded_file=st.file_uploader("Choose a file")
submitted=st.button(label="Upload",disabled=not uploaded_file)
if submitted:
    hasher=hashlib.sha256()
    for chunk in iter(lambda: uploaded_file.read(4096), b''):
        hasher.update(chunk)
    new_hash=hasher.hexdigest()
    url = f"https://www.virustotal.com/api/v3/files/{new_hash}"
    response = requests.get(url, headers=headers)

    if response.status_code==200:# if the file is already scanned
        existing_report()
        
    else: #if file is not already scanned
        new_scan()
        
        

        

