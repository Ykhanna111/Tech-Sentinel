import streamlit as st

# ✅ MUST be the first Streamlit command
st.set_page_config(page_title="SMS Spam Classifier (SVM)", layout="centered")

import joblib

@st.cache_resource
def load_model():
    return joblib.load("spam_model.pkl")

@st.cache_resource
def load_vectorizer():
    return joblib.load("tfidf_vectorizer.pkl")

model = load_model()
vectorizer = load_vectorizer()

st.title("📩 SMS Spam Classifier (SVM)")
st.markdown("Classify SMS messages as **Spam** or **Ham** using a pre-trained SVM model.")

user_input = st.text_area("✉️ Enter your SMS message below:", height=150)

if st.button("Predict"):
    if not user_input.strip():
        st.warning("Please enter a valid message.")
    else:
        input_vec = vectorizer.transform([user_input])
        st.write(f"Input shape: {input_vec.shape}")  # Expect (1, 3000)
        prediction = model.predict(input_vec)[0]
        result = "📢 Spam" if prediction == 1 else "✅ Ham"
        st.success(f"Prediction: **{result}**")
