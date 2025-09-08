
import base64, hashlib, datetime as dt, sqlite3, mimetypes, secrets, zipfile
from pathlib import Path
from io import BytesIO
import pandas as pd
import streamlit as st

APP_TITLE = "HR Document Portal"

# ------------------------------ CSS & UI Helpers ------------------------------

def load_css():
    """Blue content area + GREEN navigation/buttons. Hide form 'Press Enter' hint."""
    base_css = """
    :root {
      --blue:#3333FF;
      --blue-10:#3333FF1A;
      --blue-20:#3333FF33;
      --blue-30:#3333FF4D;
      --white:#FFFFFF;
      --green:#16A34A;        /* sidebar & primary buttons */
      --green-20:#16A34A33;
    }
    html, body, [data-testid="stAppViewContainer"] {
      background: var(--white) !important;
    }
    .block-container { padding-top: 0.75rem; padding-bottom: 3rem; }
    .subtle { color: var(--blue); opacity: .65; }

    /* Header block remains blue */
    .custom-header{
        background: var(--blue);
        color: var(--white); border-radius:16px; padding:22px 22px; margin:8px 0 18px;
        box-shadow: 0 12px 24px var(--blue-20);
    }
    .custom-header h1 { margin:0 0 4px; font-size:1.5rem; }
    .custom-header p { margin:0; opacity:.92 }

    /* Sidebar: green with clear contrast */
    section[data-testid="stSidebar"] {
        background: var(--green) !important; color: var(--white) !important;
    }
    section[data-testid="stSidebar"] .block-container { padding-top:1rem; }
    section[data-testid="stSidebar"] * { color: var(--white) !important; }
    .role-pill { display:inline-block;padding:.15rem .5rem;border-radius:9999px;background:var(--white);
                 color:var(--green);font-size:.75rem;margin-top:.25rem }

    /* Nav radio as cards with strong selected state */
    .stRadio > div[role="radiogroup"] > label {
        background:var(--white); border:1px solid #ffffff; border-radius:14px; padding:.55rem .85rem; margin:.35rem 0;
        display:flex; gap:.5rem; align-items:center; box-shadow:0 4px 10px rgba(0,0,0,.08);
        color:#000;
    }
    /* Make radio bullets green */
    .stRadio [data-baseweb="radio"] > div:first-child { border-color: var(--green) !important; }
    .stRadio [data-baseweb="radio"] > div:first-child > div { background-color: var(--green) !important; }

    /* Highlight the active nav item (checked) */
    .stRadio [data-baseweb="radio"] input:checked + div { 
        border-color: var(--green) !important;
        box-shadow: 0 0 0 6px var(--green-20) inset !important;
    }
    .stRadio [data-baseweb="radio"] input:checked ~ div:last-child {
        color: var(--white) !important;
    }
    .stRadio > div[role="radiogroup"] > label:has(input:checked) {
        background: rgba(255,255,255,.15) !important;
        border-color: var(--white) !important;
    }

    /* Inputs / selects light blue borders (content area remains blue/white) */
    .stTextInput input, .stTextArea textarea, .stNumberInput input, .stDateInput input {
        background:var(--white) !important; border:1px solid var(--blue-20) !important;
    }
    .stSelectbox [data-baseweb="select"] > div {
        background:var(--white) !important; border:1px solid var(--blue-20) !important;
    }
    .stFileUploader div[data-testid="stFileUploaderDropzone"] {
        background:var(--white) !important; border:1px dashed var(--blue-30) !important;
    }

    /* Buttons -> GREEN primary to eliminate red appearances */
    .stButton > button, .stDownloadButton > button, [data-testid="stFormSubmitButton"] button {
        background: var(--green) !important; color:var(--white) !important; border:1px solid var(--green) !important;
        border-radius: 9999px !important; padding:.55rem 1rem !important; box-shadow: 0 4px 12px var(--green-20) !important;
    }
    .stButton > button:hover, .stDownloadButton > button:hover, [data-testid="stFormSubmitButton"] button:hover { filter:brightness(1.05) !important; }

    /* Dataframe links as blue pills */
    [data-testid="stDataFrame"] a, [data-testid="stDataEditor"] a, [data-testid="stTable"] a {
      text-decoration:none;border:1px solid var(--blue-20);padding:.25rem .65rem;border-radius:9999px;
      background:var(--white);color:var(--blue);display:inline-block;
    }

    /* Status badge single style */
    .status-badge{border-radius:9999px;font-size:.75rem;padding:.15rem .5rem;font-weight:600;
                  border:1px solid var(--blue); color:var(--blue); background:var(--white)}

    /* Alerts blue/white only */
    .stAlert { background: var(--white) !important; border:1px solid var(--blue) !important; color: var(--blue) !important; }
    .stAlert [data-testid="stMarkdown"] p, .stAlert p, .stAlert div { color: var(--blue) !important; }

    /* Hide Streamlit form hint "Press Enter to submit" */
    [data-testid="stFormSubmitterMessage"] { display: none !important; }

    /* Hide default chrome */
    header[data-testid="stHeader"] { background: var(--white); }
    footer { visibility:hidden; }
    #MainMenu, .stDeployButton { visibility:hidden; }
    """
    try:
        with open("style.css", "r", encoding="utf-8") as f:
            st.markdown(f"<style>{f.read()}</style>", unsafe_allow_html=True)
    except Exception:
        pass
    st.markdown(f"<style>{base_css}</style>", unsafe_allow_html=True)

def create_header(title="HR Document Portal", subtitle="Streamlined document & contract management"):
    st.markdown(f"""
    <div class="custom-header">
      <h1>{title}</h1>
      <p>{subtitle}</p>
    </div>
    """, unsafe_allow_html=True)

def create_status_badge(status):
    return f'<span class="status-badge">{status}</span>'

# ------------------------------ (rest of file unchanged from previous blue build) ------------------------------

# To keep this patch focused on styling/behavior you asked for, we import the rest from the existing file.
from importlib import reload
import types, sys

# Dynamically load the previous module code (already written to /mnt/data/app.py)
# and reuse all functions/logic except the ones we just redefined (load_css, create_header, create_status_badge).
spec = types.ModuleType("old_app_impl")
code = Path("/mnt/data/app.py").read_text(encoding="utf-8")
exec(compile(code, "old_app_impl", "exec"), spec.__dict__)

# Bring over everything else
globals_to_copy = [k for k in spec.__dict__.keys() if k not in globals() or k in {"main"}]
for k in globals_to_copy:
    if k not in {"load_css","create_header","create_status_badge"}:
        globals()[k] = spec.__dict__[k]

if __name__ == "__main__":
    main()
