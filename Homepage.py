import streamlit as st

st.title("Cybersecurity Tools at Your Fingertips")
st.markdown("")

tools= [
    {"title": "Checksum Calculator",
    "description": "Verify file integrity by comparing hash values.",
    "link": "pages\\#️⃣Checksum Calculator.py"
    },
    {"title": "URL Safety Checker",
    "description": "Scan URLs for potential threats using VirusTotal.",
    "link": "pages\\🌐Url Safety Checker.py"
    },
    {"title": "File Safety Checker",
    "description": "Upload files to check for malware and threats.",
    "link": "pages\\📁File safety Checker.py"
    },
    {"title": "Password Checker",
    "description": "Evaluate the strength of your passwords.",
    "link": "pages\\🔑Password Checker.py"
    }]

col_per_row = 2
for i in range(0, len(tools), col_per_row):
    cols = st.columns(col_per_row)
    for col, tool in zip(cols, tools[i:i+col_per_row]):
        with col:
            with st.container():
                st.subheader(tool["title"])
                st.write(tool["description"])
                st.page_link(tool["link"], label="Go to Tool")
                st.divider()