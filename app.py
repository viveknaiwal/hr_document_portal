# app.py
# ------------------------------------------------------------------
# HR Document Portal — Streamlit Cloud + Dropbox persistence (with refresh-token support)
# ------------------------------------------------------------------

import base64, hashlib, datetime as dt, sqlite3, mimetypes, secrets, zipfile, os
from pathlib import Path
from io import BytesIO
import pandas as pd
import streamlit as st

# ------------- Branding / Title
APP_TITLE = "HR Document Portal"

# ------------- Local fallback storage (used on your laptop if no Dropbox)
LOCAL_STORAGE_DIR = Path("storage/HR_Documents_Portal")
LOCAL_DB_PATH = Path("storage/hr_docs.db")
LOCAL_STORAGE_DIR.mkdir(parents=True, exist_ok=True)
LOCAL_DB_PATH.parent.mkdir(parents=True, exist_ok=True)

# ===================================================================
#                        DROPBOX CONFIG
# ===================================================================
USE_DROPBOX = False
dbx = None

try:
    import dropbox

    if "DROPBOX_REFRESH_TOKEN" in st.secrets:
        # ✅ Preferred method (never expires)
        dbx = dropbox.Dropbox(
            oauth2_refresh_token=st.secrets["DROPBOX_REFRESH_TOKEN"],
            app_key=st.secrets["DROPBOX_APP_KEY"],
            app_secret=st.secrets["DROPBOX_APP_SECRET"],
        )
        USE_DROPBOX = True
    elif "DROPBOX_ACCESS_TOKEN" in st.secrets and st.secrets["DROPBOX_ACCESS_TOKEN"].strip():
        # ⚠️ Fallback (short-lived, may expire)
        DBX_TOKEN = st.secrets["DROPBOX_ACCESS_TOKEN"].strip()
        dbx = dropbox.Dropbox(DBX_TOKEN)
        USE_DROPBOX = True
    else:
        st.warning("⚠️ No Dropbox credentials found, falling back to local storage only.")
except Exception as e:
    st.error(f"Dropbox import/init failed: {e}")
    USE_DROPBOX = False

DBX_ROOT = st.secrets.get("DROPBOX_ROOT", "/HR_Documents_Portal").rstrip("/")

# ===================================================================
#                          DROPBOX HELPERS
# ===================================================================
def dbx_path(*parts) -> str:
    return DBX_ROOT + "/" + "/".join(str(p).strip("/").replace("\\", "/") for p in parts)

def dbx_ensure_folder(path: str):
    try:
        dbx.files_get_metadata(path)
    except Exception:
        try:
            dbx.files_create_folder_v2(path)
        except Exception:
            pass

def dbx_upload_bytes(path: str, data: bytes):
    dbx_ensure_folder("/".join(path.split("/")[:-1]))
    dbx.files_upload(data, path, mode=dropbox.files.WriteMode("overwrite"))

def dbx_download_bytes(path: str) -> bytes | None:
    try:
        _, res = dbx.files_download(path)
        return res.content
    except Exception:
        return None

def dbx_exists(path: str) -> bool:
    try:
        dbx.files_get_metadata(path)
        return True
    except Exception:
        return False

# Convenience wrappers to support both local and Dropbox paths
def is_dbx_path(p: str) -> bool:
    return p.startswith("dbx:/")

def to_display_name(p: str) -> str:
    return Path(p.split(":", 1)[1] if is_dbx_path(p) else p).name

def write_bytes_return_ref(data: bytes, *, doc_type: str, name: str, version: int, filename: str) -> str:
    safe_name = "".join(c for c in name if c.isalnum() or c in (" ", "_", "-")).strip().replace(" ", "_")
    if USE_DROPBOX:
        remote_dir = dbx_path(doc_type, safe_name, f"v{version}")
        remote_file = remote_dir + "/" + filename
        dbx_upload_bytes(remote_file, data)
        return "dbx:" + remote_file
    # local fallback
    subdir = LOCAL_STORAGE_DIR / doc_type / safe_name / f"v{version}"
    subdir.mkdir(parents=True, exist_ok=True)
    local_file = subdir / filename
    local_file.write_bytes(data)
    return "local:" + str(local_file)

def read_ref_bytes(ref: str) -> bytes | None:
    if is_dbx_path(ref):
        return dbx_download_bytes(ref.split(":", 1)[1])
    p = Path(ref.split(":", 1)[1])
    return p.read_bytes() if p.exists() else None

def ref_exists(ref: str) -> bool:
    if is_dbx_path(ref):
        return dbx_exists(ref.split(":", 1)[1])
    return Path(ref.split(":", 1)[1]).exists()

# ===================================================================
# EVERYTHING ELSE (DB helpers, app helpers, pages, main, etc.)
# ===================================================================
# 👇 Paste your full existing code here (unchanged from your last version)
#   - RAW_USERS
#   - _hash, load_users, authenticate
#   - init_db, backup_db_to_dropbox, insert_audit
#   - ensure_tokens, open_in_new_tab_link, make_zip
#   - page_upload, versions_with_links, page_documents, page_deleted, page_audit
#   - main()

# ... (keep your full implementation as you had it) ...

if __name__ == "__main__":
    main()
