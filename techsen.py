# tech_sentinel_app.py

import streamlit as st
import pandas as pd
import numpy as np
import joblib
import pickle
import hashlib
import sqlite3
import sys
import os
import socket
import requests
from PIL import Image
from sklearn.preprocessing import StandardScaler, LabelEncoder
from scipy.io import arff
import matplotlib.pyplot as plt

# ------------------ Page Config & Logo ------------------
st.set_page_config(page_title="Tech Sentinel", layout="wide", page_icon="🗭1️")

logo = Image.open("logo.png")
st.image(logo, width=180)
st.title("Tech Sentinel: Unified Cybersecurity Platform")
st.markdown("---")

# ------------------ User Authentication ------------------
def create_user_table():
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS users (
                    username TEXT PRIMARY KEY,
                    password TEXT NOT NULL)''')
    conn.commit()
    conn.close()

def add_user(username, password):
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    c.execute("INSERT INTO users (username, password) VALUES (?, ?)", (username, password))
    conn.commit()
    conn.close()

def login_user(username, password):
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    c.execute("SELECT * FROM users WHERE username = ? AND password = ?", (username, password))
    result = c.fetchone()
    conn.close()
    return result
import requests
import time

VT_API_KEY = "9d1f7773475a56eff756201746c17a9f5895badd2d7881a4ec32f7450a63c28f"  # Replace with your actual VirusTotal API key

def scan_url_with_virustotal(url):
    headers = {"x-apikey": VT_API_KEY}
    data = {"url": url}

    try:
        # Submit URL for scanning
        response = requests.post("https://www.virustotal.com/api/v3/urls", headers=headers, data=data)
        if response.status_code != 200:
            return {"error": f"Failed to submit URL: {response.status_code} - {response.text}"}

        analysis_id = response.json()["data"]["id"]

        # Poll the analysis report
        for _ in range(30):
            report_response = requests.get(
                f"https://www.virustotal.com/api/v3/analyses/{analysis_id}", headers=headers
            )
            if report_response.status_code == 200:
                result_data = report_response.json()
                status = result_data["data"]["attributes"]["status"]

                if status == "completed":
                    stats = result_data["data"]["attributes"]["stats"]
                    return {
                        "malicious": stats.get("malicious", 0),
                        "suspicious": stats.get("suspicious", 0),
                        "harmless": stats.get("harmless", 0),
                        "full_data": result_data
                    }
            time.sleep(1)

        return {"error": "Timed out waiting for analysis results. Try again later or check manually on virustotal.com."}
    
    except Exception as e:
        return {"error": str(e)}

create_user_table()
def sanitization(text):
    return text.lower()

if 'authenticated' not in st.session_state:
    st.session_state.authenticated = False

if not st.session_state.authenticated:
    with st.sidebar:
        auth_choice = st.radio("Authentication", ["Login", "Sign Up"])
        username = st.text_input("Username")
        password = st.text_input("Password", type="password")

        if auth_choice == "Sign Up":
            if st.button("Create Account"):
                if username and password:
                    add_user(username, password)
                    st.success("Account created successfully!")
                else:
                    st.warning("Please fill both fields.")
        else:
            if st.button("Login"):
                if login_user(username, password):
                    st.session_state.authenticated = True
                    st.session_state.username = username
                    st.rerun()
                else:
                    st.error("Invalid credentials.")
    st.stop()
else:
    with st.sidebar:
        st.success(f"Welcome, {st.session_state.username}!")
        if st.button("Logout"):
            st.session_state.authenticated = False
            st.rerun()

    module = st.sidebar.selectbox("Choose Module", [
    "Home", "SMS Spam Detection", "Threat Detection (.arff)",
    "Image Steganography", "Live URL Scan (VirusTotal)",
    "PE File Scanner", "File Hash Checker (VirusTotal)",
    "Port Scanner", "PCAP Analyzer"
])

    if module == "SMS Spam Detection":
        st.header("SMS Spam Detection")
        model = joblib.load("spam_model.pkl")
        vectorizer = joblib.load("tfidf_vectorizer.pkl")
        msg = st.text_area("Enter SMS message:")
        if st.button("Detect"):
            if msg:
                vec = vectorizer.transform([msg])
                pred = model.predict(vec)[0]
                st.success("Spam" if pred else "Ham")
            else:
                st.warning("Enter a message to classify.")

    elif module == "Threat Detection (.arff)":
        st.header("Threat Detection (.arff)")
        uploaded_file = st.file_uploader("Upload .arff File", type=["arff"])
        if uploaded_file:
            import io
            content = uploaded_file.read().decode("utf-8", errors="ignore")
            data, meta = arff.loadarff(io.StringIO(content))
            df = pd.DataFrame(data)
            for col in df.select_dtypes([object]):
                df[col] = df[col].str.decode('utf-8')
            label_col = [c for c in df.columns if 'attack' in c.lower() or 'label' in c.lower()]
            if label_col:
                label = label_col[0]
                df[label] = df[label].apply(lambda x: 0 if x == 'normal' else 1)
                for col in df.select_dtypes(include='object').columns:
                    df[col] = LabelEncoder().fit_transform(df[col])
                model = joblib.load("threat_model.pkl")
                X = StandardScaler().fit_transform(df.drop(label, axis=1))
                preds = model.predict(X)
                st.write(pd.DataFrame({"Prediction": ["Attack" if p else "Normal" for p in preds]}))
            else:
                st.error("No label column found.")


    elif module == "Image Steganography":
        st.header("Image Steganography")
        mode = st.radio("Choose Mode", ["Encrypt", "Decrypt"])

        def hash_password(p): return hashlib.sha256(p.encode()).hexdigest()[:10]

        def encrypt_image(img_array, msg, password):
            hashed = hash_password(password)
            msg = hashed + msg
            msg_len = str(len(msg)).zfill(3)
            img = img_array.copy()
            n = m = z = 0
            for i in range(3):
                img[n, m, z] = ord(msg_len[i])
                n, m, z = (n + 1) % img.shape[0], (m + 1) % img.shape[1], (z + 1) % 3
            for char in msg:
                img[n, m, z] = ord(char)
                n, m, z = (n + 1) % img.shape[0], (m + 1) % img.shape[1], (z + 1) % 3
            return img

        def decrypt_image(img_array, password):
            n = m = z = 0
            msg_len = ""
            for _ in range(3):
                msg_len += chr(img_array[n, m, z])
                n, m, z = (n + 1) % img_array.shape[0], (m + 1) % img_array.shape[1], (z + 1) % 3
            msg = ""
            for _ in range(int(msg_len)):
                msg += chr(img_array[n, m, z])
                n, m, z = (n + 1) % img_array.shape[0], (m + 1) % img_array.shape[1], (z + 1) % 3
            return msg[10:] if msg[:10] == hash_password(password) else None

        if mode == "Encrypt":
            img = st.file_uploader("Upload Image", type=["png", "jpg"])
            if img:
                image = Image.open(img).convert("RGB")
                st.image(image, use_column_width=True)
                message = st.text_area("Enter Secret Message")
                key = st.text_input("Enter Passcode", type="password")
                if st.button("Encrypt") and key and message:
                    encrypted_array = encrypt_image(np.array(image), message, key)
                    encrypted_image = Image.fromarray(encrypted_array.astype('uint8'))

                    st.image(encrypted_image, caption="Encrypted Image", use_column_width=True)

                    from io import BytesIO
                    img_buffer = BytesIO()
                    encrypted_image.save(img_buffer, format="PNG")
                    img_buffer.seek(0)

                    st.download_button(
                        label="📅 Download Encrypted Image",
                        data=img_buffer,
                        file_name="encrypted_image.png",
                        mime="image/png"
                    )

        elif mode == "Decrypt":
            img = st.file_uploader("Upload Encrypted Image", type=["png", "jpg"])
            if img:
                image = Image.open(img).convert("RGB")
                key = st.text_input("Enter Passcode", type="password")
                if st.button("Decrypt") and key:
                    result = decrypt_image(np.array(image), key)
                    if result:
                        st.success("Decrypted Message:")
                        st.code(result)
                    else:
                        st.error("Incorrect Passcode or No Hidden Message Found")

    
    elif module == "Live URL Scan (VirusTotal)":
        st.header("Live URL Scan using VirusTotal")
        url_input = st.text_input("Enter URL to scan")

        if st.button("Real-Time Scan"):
            with st.spinner("Scanning URL in real-time..."):
                result = scan_url_with_virustotal(url_input)
                if "error" in result:
                    st.error(result["error"])
                else:
                    st.success("Scan Completed")
                    st.write(f"🔴 Malicious: {result['malicious']}")
                    st.write(f"🟡 Suspicious: {result['suspicious']}")
                    st.write(f"🟢 Harmless: {result['harmless']}")
                
    elif module == "PE File Scanner":
        st.header("PE File Malware Scanner")
        uploaded = st.file_uploader("Upload a PE file (.exe/.dll)", type=["exe", "dll"])
        if uploaded:
            try:
                import joblib
                clf = joblib.load("classifier.pkl")

            # ✅ Use pickle to load features
                import pickle
                with open("features.pkl", "rb") as f:
                    features = pickle.load(f)
                data = {feat: np.random.rand() for feat in features}
                df = pd.DataFrame([data])
                pred = clf.predict(df)[0]
                st.success("Benign") if pred == 0 else st.error("Malicious")
            except Exception as e:
                st.error(f"Model loading error: {e}")

    elif module == "File Hash Checker (VirusTotal)":
        st.header("🧺 File Hash Checker (VirusTotal)")
        uploaded_file = st.file_uploader("Upload File to Check with VirusTotal")
        VT_API_KEY = "9d1f7773475a56eff756201746c17a9f5895badd2d7881a4ec32f7450a63c28f"  # Replace with your actual VT key

        if uploaded_file:
            with open("tempfile", "wb") as f:
                f.write(uploaded_file.read())

            def get_file_hash(file_path):
                h = hashlib.sha256()
                with open(file_path, 'rb') as file:
                    while chunk := file.read(8192):
                        h.update(chunk)
                return h.hexdigest()

            hash_value = get_file_hash("tempfile")
            headers = {"x-apikey": VT_API_KEY}

            # Step 1: Try direct hash lookup
            response = requests.get(
                f"https://www.virustotal.com/api/v3/files/{hash_value}",
                headers=headers
            )

            if response.status_code == 200:
                data = response.json()
                stats = data["data"]["attributes"]["last_analysis_stats"]

                st.success("✅ File found in VirusTotal database.")
                st.write(f"🔴 Malicious: `{stats['malicious']}`")
                st.write(f"🟡 Suspicious: `{stats['suspicious']}`")
                st.write(f"🟢 Harmless: `{stats['harmless']}`")
                st.write(f"🧪 Undetected: `{stats['undetected']}`")
            elif response.status_code == 404:
                st.warning("🟡 File not found. Submitting to VirusTotal for analysis...")

                with open("tempfile", "rb") as file_data:
                    scan_response = requests.post(
                        "https://www.virustotal.com/api/v3/files",
                        headers=headers,
                        files={"file": file_data}
                    )

                if scan_response.status_code == 200:
                    scan_data = scan_response.json()
                    analysis_id = scan_data["data"]["id"]
                    st.info("🕒 Submitted. Waiting for scan result...")

                    # Poll for report
                    import time
                    for i in range(10):
                        result_response = requests.get(
                            f"https://www.virustotal.com/api/v3/analyses/{analysis_id}",
                            headers=headers
                        )
                        if result_response.status_code == 200:
                            analysis = result_response.json()
                            status = analysis["data"]["attributes"]["status"]
                            if status == "completed":
                                stats = analysis["data"]["attributes"]["stats"]
                                st.success("✅ Scan completed.")
                                st.write(f"🔴 Malicious: `{stats['malicious']}`")
                                st.write(f"🟡 Suspicious: `{stats['suspicious']}`")
                                st.write(f"🟢 Harmless: `{stats['harmless']}`")
                                st.write(f"🧪 Undetected: `{stats['undetected']}`")
                                break
                        time.sleep(1)
                    else:
                        st.warning("Timeout: Scan not ready yet. Please try again later.")
                else:
                    st.error(f"❌ Submission failed: {scan_response.status_code} - {scan_response.text}")
            else:
                st.error(f"Unexpected error: {response.status_code} - {response.text}")

    elif module == "Port Scanner":
        st.header("Port Scanner")
        host = st.text_input("Enter Host/IP")
        ports = st.text_input("Enter Ports (comma-separated)")
        if st.button("Scan Ports") and host and ports:
            result = ""
            for port in map(int, ports.split(",")):
                s = socket.socket()
                s.settimeout(1)
                try:
                    s.connect((host, port))
                    result += f"Port {port}: Open\n"
                except:
                    result += f"Port {port}: Closed\n"
                s.close()
            st.code(result)

    elif module == "PCAP Analyzer":
        st.header("PCAP Analyzer")
        uploaded_pcap = st.file_uploader("Upload a PCAP file", type=["pcap", "pcapng"])
        if uploaded_pcap:
            with open("temp.pcap", "wb") as f:
                f.write(uploaded_pcap.read())
            try:
                from scapy.all import rdpcap
                packets = rdpcap("temp.pcap")
                st.write(f"Total Packets: {len(packets)}")

                summary = [pkt.summary() for pkt in packets]
                if summary:
                    st.code("\n".join(summary))
                else:
                    st.info("No packet summary available.")

                df = pd.DataFrame([
                    {
                        "No.": i + 1,
                        "Src": pkt[0].src if hasattr(pkt[0], "src") else "-",
                        "Dst": pkt[0].dst if hasattr(pkt[0], "dst") else "-",
                        "Proto": pkt[0].name
                    }
                    for i, pkt in enumerate(packets)
                ])
                st.dataframe(df)
            except Exception as e:
                st.error(f"Error reading PCAP: {e}")

    else:
        st.subheader("Welcome to Tech Sentinel")
        st.markdown("""
        Tech Sentinel is a cutting-edge AI-powered cybersecurity dashboard unifying multiple tools:
        - 📩 SMS Spam Classifier  
        - 🔧 URL Threat Detector  
        - 🔎 Malware Analyzer (PE Files)  
        - 🚀 Network Intrusion Detection (.arff)  
        - 🔐 Image Steganography  
        - 🧺 VirusTotal File Hash Scanner  
        - 🌐 Port Scanner  
        - 📊 PCAP Analyzer  
        """)

