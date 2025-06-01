import os
import requests
import streamlit as st
import re
import time
from dotenv import load_dotenv

load_dotenv()

st.title("Url safety checker")
url = "https://www.virustotal.com/api/v3/urls"
api_key=os.getenv("VIRUSTOTAL_API_KEY")
test_url=st.text_input("Enter the link for scanning")
url_pattern = re.compile(
    r"^(?:http://|https://)?" 
    r"(([a-zA-Z0-9_-]+\.)+[a-zA-Z]{2,6}|localhost)"
    r"(:\d+)?(/[a-zA-Z0-9_/-]*)*$"
)
if test_url:
    if not url_pattern.match(test_url):
        st.error("Invalid URL. Please enter a valid URL.")
    else:
        payload = { "url": test_url }
        headers = {
            "accept": "application/json",
            "x-apikey": api_key,
            "content-type": "application/x-www-form-urlencoded"
        }

        response = requests.post(url, data=payload, headers=headers)
        report_url=response.json()["data"]["links"]["self"]
        new_response = requests.get(report_url, headers=headers)
        with st.spinner("Scanning..."):
            while new_response.json()["data"]["attributes"]["status"]!="completed":
                time.sleep(2)
                new_response = requests.get(report_url, headers=headers)
        
        detected=new_response.json()["data"]["attributes"]["stats"]["malicious"]
        
        total_scans=sum(new_response.json()["data"]["attributes"]["stats"].values())
        if detected>0:
            st.error(f"{detected} out of {total_scans} antiviruses found the given website as malicious")
        else:
            st.success(f"{detected} out of {total_scans} antiviruses found the given website as malicious")
        
        with st.expander("see details"):
            for i in new_response.json()["data"]["attributes"]["results"]:
                st.write(i+" : "+new_response.json()["data"]["attributes"]["results"][i]["result"])

