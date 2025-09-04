# app.py
# ------------------------------------------------------------------
# HR Document Portal — Streamlit
# - Users, roles, audit log
# - SOP/BRD/Policy + Contract Management (versioned, view links)
# - Storage backends (priority): Google Drive -> Dropbox -> Local
# - 30-day "stay signed in" token via URL ?auth=... (survives reload)
# - Robust PDF viewer with base64 <object>/<embed> + download fallback
# ------------------------------------------------------------------

import base64, hashlib, datetime as dt, sqlite3, mimetypes, secrets, zipfile
from pathlib import Path
from io import BytesIO
import pandas as pd
import streamlit as st

APP_TITLE = "HR Document Portal"

# ---------------- Local storage (fallback when no cloud available)
LOCAL_STORAGE_DIR = Path("storage/HR_Documents_Portal")
LOCAL_DB_PATH = Path("storage/hr_docs.db")
LOCAL_STORAGE_DIR.mkdir(parents=True, exist_ok=True)
LOCAL_DB_PATH.parent.mkdir(parents=True, exist_ok=True)

# (Dropbox / GDrive code omitted for brevity — same as previous version)
# ===================================================================
#                                DB
# ===================================================================
def _hash(pw):
    return hashlib.sha256(pw.encode()).hexdigest()

def init_db():
    con = sqlite3.connect(LOCAL_DB_PATH, check_same_thread=False)
    cur = con.cursor()
    cur.executescript(
        """
        CREATE TABLE IF NOT EXISTS documents (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            doc_type TEXT,
            name TEXT,
            created_date TEXT,
            upload_date TEXT,
            approved_by TEXT,
            file_path TEXT,
            email_path TEXT,
            version INTEGER,
            uploaded_by TEXT,
            hash_sha256 TEXT,
            is_deleted INTEGER DEFAULT 0,
            file_token TEXT,
            email_token TEXT,
            remarks TEXT
        );
        CREATE TABLE IF NOT EXISTS contracts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT,
            vendor TEXT,
            owner TEXT,
            status TEXT,
            start_date TEXT,
            end_date TEXT,
            renewal_notice_days INTEGER,
            created_date TEXT,
            upload_date TEXT,
            uploaded_by TEXT,
            file_path TEXT,
            email_path TEXT,
            version INTEGER,
            hash_sha256 TEXT,
            is_deleted INTEGER DEFAULT 0,
            file_token TEXT,
            email_token TEXT,
            remarks TEXT
        );
        CREATE TABLE IF NOT EXISTS audit_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ts TEXT,
            actor TEXT,
            action TEXT,
            doc_id INTEGER,
            details TEXT,
            reason TEXT
        );
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT UNIQUE,
            password_sha256 TEXT,
            role TEXT,
            created_date TEXT
        );
        CREATE TABLE IF NOT EXISTS auth_tokens (
            token TEXT PRIMARY KEY,
            email TEXT,
            expires TEXT
        );
        """
    )
    con.commit()
    return con

def insert_audit(con, actor, action, doc_id=None, details="", reason=""):
    con.execute(
        "INSERT INTO audit_log(ts,actor,action,doc_id,details,reason) VALUES (?,?,?,?,?,?)",
        (dt.datetime.utcnow().isoformat(), actor, action, doc_id, details, reason),
    )
    con.commit()

# ===================================================================
#                        HELPERS
# ===================================================================
def title_case_role(val: str) -> str:
    return {"admin": "Admin", "editor": "Editor", "viewer": "Viewer"}.get(str(val).lower(), str(val).title())

def _days_to_expiry(end_series):
    end_dt = pd.to_datetime(end_series, errors="coerce")
    today_ts = pd.Timestamp(dt.date.today())
    return (end_dt - today_ts).dt.days

# Delete / Restore
def soft_delete_record(con, table: str, row_id: int, actor: str, reason: str):
    con.execute(f"UPDATE {table} SET is_deleted=1 WHERE id=?", (row_id,))
    con.commit()
    action = "DELETE_CONTRACT" if table == "contracts" else "DELETE_DOC"
    insert_audit(con, actor, action, row_id, f"table={table};id={row_id}", reason)

def restore_record(con, table: str, row_id: int, actor: str, reason: str):
    con.execute(f"UPDATE {table} SET is_deleted=0 WHERE id=?", (row_id,))
    con.commit()
    action = "RESTORE_CONTRACT" if table == "contracts" else "RESTORE_DOC"
    insert_audit(con, actor, action, row_id, f"table={table};id={row_id}", reason)

# ===================================================================
#                                PAGES
# ===================================================================
def delete_version_ui(*, entity: str, table: str, versions_df: pd.DataFrame, con, user):
    st.markdown("#### Delete")
    sel_v = st.selectbox("Version to delete", versions_df["version"].tolist(), key=f"del_{entity}_v")
    reason = st.text_area("Reason (required)", key=f"del_{entity}_reason")
    if st.button("Delete Version", key=f"btn_del_{entity}"):
        if not reason.strip():
            st.error("Please enter a reason before deleting.")
            return
        row_id = int(versions_df.loc[versions_df["version"] == sel_v, "id"].iloc[0])
        soft_delete_record(con, table, row_id, user["username"], reason.strip())
        st.success(f"{entity.capitalize()} version {sel_v} moved to Deleted Files")
        st.rerun()

def page_contracts(con, user):
    st.subheader("Contract Management")

    can_upload = user["role"] in {"admin", "editor"}
    if can_upload:
        with st.form("contract_form", clear_on_submit=True):
            c1, c2 = st.columns(2)
            with c1:
                name   = st.text_input("Contract Name *")
                vendor = st.text_input("Vendor *")
                owner  = st.text_input("Internal Owner / POC")
                status = st.selectbox("Status", ["Active", "Under review", "Expired"])
            with c2:
                start  = st.date_input("Start Date *", dt.date.today())
                end    = st.date_input("End Date *", dt.date.today())
            remarks = st.text_area("Remarks / Context *", height=100)
            doc  = st.file_uploader("Contract File (PDF/Doc) *")
            email = st.file_uploader("Approval/Email Attachment (optional)")
            ok = st.form_submit_button("Upload Contract")

        if ok:
            if not name or not vendor or not doc or not remarks.strip():
                st.error("Please fill Contract Name, Vendor, Contract file, and Remarks / Context."); return
            data = doc.read()
            # auto-calc renewal
            renewal = (end - start).days

            cur = con.execute("SELECT MAX(version) FROM contracts WHERE name=? AND vendor=?", (name, vendor))
            maxv = cur.fetchone()[0]
            version = (maxv + 1) if maxv else 1

            file_ref = "local:dummy"  # stub for brevity
            ft, et = "tok", None
            con.execute(
                """INSERT INTO contracts
                   (name,vendor,owner,status,start_date,end_date,renewal_notice_days,
                    created_date,upload_date,uploaded_by,file_path,email_path,version,hash_sha256,
                    is_deleted,file_token,email_token,remarks)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,0,?,?,?)""",
                (name, vendor, owner, status, str(start), str(end), int(renewal),
                 str(start), dt.datetime.utcnow().isoformat(), user["username"],
                 file_ref, "", version, "sha256", ft, et, remarks.strip())
            )
            con.commit()
            insert_audit(con, user["username"], "CONTRACT_UPLOAD", details=f"{vendor}/{name} v{version}", reason=remarks.strip())
            st.success(f"Contract uploaded as version {version}")

def page_audit(con, user=None):
    st.subheader("Audit Logs")
    df = pd.read_sql("SELECT * FROM audit_log ORDER BY ts DESC", con)
    if df.empty:
        st.info("No logs"); return

    df = df.rename(columns={"ts": "Timestamp (UTC)", "actor": "User", "action": "Action", "doc_id": "Record ID", "details": "Details", "reason": "Reason"})
    st.dataframe(df, use_container_width=True)

# ===================================================================
#                                MAIN
# ===================================================================
def main():
    st.set_page_config(APP_TITLE, layout="wide")
    con = init_db()

    # Simplified demo login
    user = {"username": "admin@cars24.com", "role": "admin"}

    tabs = ["Documents", "Document Management", "Contract Management", "Deleted Files", "Audit Logs", "User Management"]

    st.markdown("""
    <style>
    .stTabs [data-baseweb="tab-highlight"] { background-color: #2563EB !important; }
    .stTabs [role="tab"][aria-selected="true"] p { color: #2563EB !important; }
    .stTabs [role="tab"]:not([aria-selected="true"]) p { transition: color .15s ease; }
    .stTabs [role="tab"]:not([aria-selected="true"]):hover p,
    .stTabs [role="tab"]:not([aria-selected="true"]):focus p { color: #2563EB !important; }
    </style>
    """, unsafe_allow_html=True)

    t = st.tabs(tabs)
    with t[2]:
        page_contracts(con, user)
    with t[4]:
        page_audit(con, user)

if __name__ == "__main__":
    main()
