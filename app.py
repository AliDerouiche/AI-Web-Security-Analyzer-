import streamlit as st
import joblib
import time
from datetime import datetime
import re

# --- Page config ---
st.set_page_config(
    page_title="URL Security Checker",
    page_icon="🔐",
    layout="centered",
    initial_sidebar_state="collapsed"
)

# --- Custom CSS ---
st.markdown("""
<style>
    .main {
        padding-top: 2rem;
    }
    .stButton>button {
        width: 100%;
        background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
        color: white;
        font-weight: 600;
        padding: 0.75rem 2rem;
        border-radius: 10px;
        border: none;
        transition: all 0.3s ease;
    }
    .stButton>button:hover {
        transform: translateY(-2px);
        box-shadow: 0 10px 20px rgba(102, 126, 234, 0.3);
    }
    .info-card {
        background: linear-gradient(135deg, #f5f7fa 0%, #c3cfe2 100%);
        padding: 1.5rem;
        border-radius: 15px;
        margin: 1rem 0;
        box-shadow: 0 4px 6px rgba(0,0,0,0.1);
    }
    .metric-card {
        background: white;
        padding: 1rem;
        border-radius: 10px;
        box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        margin: 0.5rem 0;
    }
    h1 {
        background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
        -webkit-background-clip: text;
        -webkit-text-fill-color: transparent;
        font-size: 3rem !important;
        font-weight: 800 !important;
    }
    .safe-badge {
        background: #10b981;
        color: white;
        padding: 0.5rem 1rem;
        border-radius: 20px;
        font-weight: 600;
        display: inline-block;
    }
    .danger-badge {
        background: #ef4444;
        color: white;
        padding: 0.5rem 1rem;
        border-radius: 20px;
        font-weight: 600;
        display: inline-block;
    }
    .warning-badge {
        background: #f59e0b;
        color: white;
        padding: 0.5rem 1rem;
        border-radius: 20px;
        font-weight: 600;
        display: inline-block;
    }
</style>
""", unsafe_allow_html=True)

# --- Load model ---
@st.cache_resource
def load_model():
    try:
        return joblib.load("url_security_model.pkl")
    except FileNotFoundError:
        st.error("⚠️ Model file not found. Please ensure 'url_security_model.pkl' exists.")
        st.stop()

model = load_model()

# --- URL Validation ---
def is_valid_url(url):
    url_pattern = re.compile(
        r'^https?://'
        r'(?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+[A-Z]{2,6}\.?|'
        r'localhost|'
        r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'
        r'(?::\d+)?'
        r'(?:/?|[/?]\S+)$', re.IGNORECASE)
    return url_pattern.match(url) is not None

# --- Threat Info ---
def get_threat_info(prediction):
    info = {
        "benign": {
            "icon": "✅",
            "title": "SAFE",
            "description": "This URL appears to be legitimate and safe to visit.",
            "color": "success",
            "recommendations": [
                "URL shows no signs of malicious activity",
                "Standard security practices still apply",
                "Always verify the domain spelling"
            ]
        },
        "phishing": {
            "icon": "⚠️",
            "title": "PHISHING DETECTED",
            "description": "This URL may attempt to steal your personal information.",
            "color": "error",
            "recommendations": [
                "Do NOT enter credentials or personal info",
                "Verify the sender's authenticity",
                "Report to your security team",
                "Check for domain spelling variations"
            ]
        },
        "malware": {
            "icon": "🚫",
            "title": "MALWARE DETECTED",
            "description": "This URL may contain harmful software.",
            "color": "error",
            "recommendations": [
                "Do NOT visit this website",
                "Scan your system if already visited",
                "Report to security authorities",
                "Update your antivirus software"
            ]
        },
        "defacement": {
            "icon": "🔍",
            "title": "DEFACEMENT DETECTED",
            "description": "This site may have been compromised.",
            "color": "warning",
            "recommendations": [
                "Avoid interacting with the site",
                "Content may be malicious",
                "Report to site administrators"
            ]
        }
    }
    return info.get(prediction, {
        "icon": "🔍",
        "title": f"SUSPICIOUS ({prediction.upper()})",
        "description": "This URL shows unusual characteristics.",
        "color": "warning",
        "recommendations": ["Exercise caution when visiting"]
    })

# --- Header ---
st.title("🔐 URL Security Checker")
st.markdown("**AI-powered threat detection** • Analyze URLs for phishing, malware, and security risks")

# --- Info Section ---
with st.expander("ℹ️ How does it work?"):
    st.markdown("""
    This tool uses advanced **machine learning algorithms** trained on thousands of URLs to detect:
    - 🎣 **Phishing attempts** - Fake sites trying to steal your data
    - 🦠 **Malware distribution** - Sites hosting harmful software  
    - 🔓 **Defaced websites** - Compromised legitimate sites
    - ✅ **Safe URLs** - Legitimate and secure websites
    
    Simply paste any URL and get an instant security assessment with confidence scores.
    """)

st.divider()

# --- Input Section ---
col1, col2 = st.columns([4, 1])
with col1:
    url = st.text_input(
        "🔗 Enter URL to analyze",
        placeholder="https://example.com",
        label_visibility="visible"
    )

with col2:
    st.markdown("<br>", unsafe_allow_html=True)
    analyze_button = st.button("🔍 Analyze", use_container_width=True)

# --- Analysis ---
if analyze_button:
    if not url.strip():
        st.warning("⚠️ Please enter a URL to analyze.")
    elif not is_valid_url(url):
        st.error("❌ Invalid URL format. Please enter a valid URL (e.g., https://example.com)")
    else:
        with st.spinner("🔄 Analyzing URL security..."):
            time.sleep(1.2)
            
            try:
                prediction = model.predict([url])[0]
                probabilities = model.predict_proba([url])[0]
                confidence = max(probabilities) * 100
                threat_info = get_threat_info(prediction)
                
                st.divider()
                
                # --- Result Header ---
                col1, col2 = st.columns([2, 1])
                with col1:
                    st.markdown(f"## {threat_info['icon']} {threat_info['title']}")
                    st.markdown(threat_info['description'])
                with col2:
                    st.metric("Confidence", f"{confidence:.1f}%")
                
                # --- Detailed Analysis ---
                st.markdown("### 📊 Threat Analysis")
                
                # Probability bars
                for label, prob in zip(model.classes_, probabilities):
                    percentage = prob * 100
                    
                    # Color coding
                    if label == "benign":
                        color = "🟢"
                    elif label in ["phishing", "malware"]:
                        color = "🔴"
                    else:
                        color = "🟡"
                    
                    col1, col2 = st.columns([3, 1])
                    with col1:
                        st.progress(int(percentage), text=f"{color} {label.upper()}")
                    with col2:
                        st.markdown(f"**{percentage:.1f}%**")
                
                st.divider()
                
                # --- Recommendations ---
                st.markdown("### 💡 Security Recommendations")
                for rec in threat_info['recommendations']:
                    st.markdown(f"- {rec}")
                
                # --- Metadata ---
                with st.expander("🔎 Analysis Details"):
                    st.markdown(f"""
                    - **URL Analyzed:** `{url}`
                    - **Timestamp:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
                    - **Model Prediction:** {prediction}
                    - **Confidence Score:** {confidence:.2f}%
                    - **Classes Detected:** {len(model.classes_)}
                    """)
                
            except Exception as e:
                st.error(f"❌ Analysis failed: {str(e)}")

# --- Statistics (Optional) ---
if 'analysis_count' not in st.session_state:
    st.session_state.analysis_count = 0

if analyze_button and url.strip() and is_valid_url(url):
    st.session_state.analysis_count += 1

# --- Footer ---
st.divider()
col1, col2, col3 = st.columns(3)
with col1:
    st.metric("Analyses Performed", st.session_state.get('analysis_count', 0))
with col2:
    st.metric("Threat Categories", len(model.classes_) if model else 0)
with col3:
    st.metric("Model Status", "🟢 Active")

st.markdown("---")
st.caption("🛡️ Developed by **Ali Derouiche**")
st.caption("⚠️ This tool provides automated assessments. Always exercise caution online.")