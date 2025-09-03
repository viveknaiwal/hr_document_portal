# app.py
# ------------------------------------------------------------------
# HR Document Portal — Streamlit Cloud + Dropbox persistence
# ------------------------------------------------------------------

import base64, hashlib, datetime as dt, sqlite3, mimetypes, secrets, zipfile, os
from pathlib import Path
from io import BytesIO
import pandas as pd
import streamlit as st

# ------------- Branding / Title
APP_TITLE = "HR Document Portal"

# ------------- Local fallback storage
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
    st.error(f"Dropbox init failed: {e}")
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

# Convenience wrappers
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
#                          DB HELPERS
# ===================================================================
RAW_USERS = {
    "admin@cars24.com": {"password": "admin123", "role": "admin"},
    "editor@cars24.com": {"password": "editor123", "role": "editor"},
    "viewer@cars24.com": {"password": "viewer123", "role": "viewer"},
}

def _hash(pw): return hashlib.sha256(pw.encode()).hexdigest()

def load_users():
    csv_path = Path("users.csv")
    users = {}
    if csv_path.exists():
        try:
            df = pd.read_csv(csv_path)
            for _, r in df.iterrows():
                email = str(r.get("email", "")).strip().lower()
                pwd = str(r.get("password", "")).strip()
                role = str(r.get("role", "")).strip().lower()
                if email and pwd and role in {"admin", "editor", "viewer"}:
                    users[email] = {"password_sha256": _hash(pwd), "role": role}
        except Exception as e:
            st.warning(f"CSV error: {e}")
    if not users:
        for email, rec in RAW_USERS.items():
            users[email.lower()] = {"password_sha256": _hash(rec["password"]), "role": rec["role"]}
    return users

def authenticate(username, password):
    rec = load_users().get(username.strip().lower())
    if rec and _hash(password) == rec["password_sha256"]:
        return {"username": username.strip().lower(), "role": rec["role"]}
    return None

def init_db():
    if USE_DROPBOX:
        dbx_db_path = dbx_path("db", "hr_docs.db")
        data = dbx_download_bytes(dbx_db_path)
        if data:
            LOCAL_DB_PATH.parent.mkdir(parents=True, exist_ok=True)
            LOCAL_DB_PATH.write_bytes(data)
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
            email_token TEXT
        );
        CREATE TABLE IF NOT EXISTS audit_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ts TEXT,
            actor TEXT,
            action TEXT,
            doc_id INTEGER,
            details TEXT
        );
        """
    )
    con.commit()
    return con

def backup_db_to_dropbox():
    if USE_DROPBOX and LOCAL_DB_PATH.exists():
        dbx_upload_bytes(dbx_path("db", "hr_docs.db"), LOCAL_DB_PATH.read_bytes())

def insert_audit(con, actor, action, doc_id=None, details=""):
    con.execute(
        "INSERT INTO audit_log(ts,actor,action,doc_id,details) VALUES (?,?,?,?,?)",
        (dt.datetime.utcnow().isoformat(), actor, action, doc_id, details),
    )
    con.commit()
    backup_db_to_dropbox()

# ===================================================================
#                        APP HELPERS
# ===================================================================
def sha256_bytes(b): h = hashlib.sha256(); h.update(b); return h.hexdigest()
def gen_token(): return secrets.token_urlsafe(16)

def ensure_tokens(con, row_id, email_exists):
    cur = con.execute("SELECT file_token,email_token FROM documents WHERE id=?", (row_id,))
    row = cur.fetchone()
    if not row: return None, None
    ft, et = row
    if not ft:
        ft = gen_token()
        con.execute("UPDATE documents SET file_token=? WHERE id=?", (ft, row_id))
    if email_exists and not et:
        et = gen_token()
        con.execute("UPDATE documents SET email_token=? WHERE id=?", (et, row_id))
    con.commit()
    backup_db_to_dropbox()
    return ft, et

def open_in_new_tab_link(token, label):
    href = f"/?serve={token}"
    st.markdown(f'<a href="{href}" target="_blank">{label}</a>', unsafe_allow_html=True)

def make_zip(refs: list) -> bytes:
    buf = BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        for ref in refs:
            if ref and ref_exists(ref):
                data = read_ref_bytes(ref)
                if data is not None:
                    zf.writestr(to_display_name(ref), data)
    return buf.getvalue()

# ===================================================================
#                               PAGES
# ===================================================================
def page_upload(con, user):
    if user["role"] not in {"admin", "editor"}:
        st.info("You have viewer access — uploads are disabled.")
        return
    st.subheader("Upload Document")
    with st.form("upf", clear_on_submit=True):
        doc_type = st.selectbox("Document Type", ["SOP", "BRD", "Policy"])
        name = st.text_input("Name")
        created_date = st.date_input("Created", dt.date.today())
        approved_by = st.text_input("Approved by")
        doc = st.file_uploader("Key Document *")
        email = st.file_uploader("Approval/email attachment (optional)")
        ok = st.form_submit_button("Upload")
    if ok and doc:
        data = doc.read()
        cur = con.execute("SELECT MAX(version) FROM documents WHERE name=? AND doc_type=?", (name, doc_type))
        maxv = cur.fetchone()[0]
        version = (maxv + 1) if maxv else 1

        file_ref = write_bytes_return_ref(data, doc_type=doc_type, name=name, version=version, filename=doc.name)
        email_ref = ""
        if email:
            email_ref = write_bytes_return_ref(email.read(), doc_type=doc_type, name=name, version=version,
                                               filename="email_" + email.name)

        ft, et = gen_token(), gen_token() if email_ref else None
        con.execute(
            """INSERT INTO documents
               (doc_type,name,created_date,upload_date,approved_by,file_path,email_path,version,uploaded_by,hash_sha256,is_deleted,file_token,email_token)
               VALUES (?,?,?,?,?,?,?,?,?,?,0,?,?)""",
            (
                doc_type, name, str(created_date), dt.datetime.utcnow().isoformat(),
                approved_by, file_ref, email_ref, version, user["username"], sha256_bytes(data), ft, et
            ),
        )
        con.commit()
        insert_audit(con, user["username"], "UPLOAD")
        backup_db_to_dropbox()
        st.success(f"Uploaded as version {version}")

def versions_with_links(con, versions_df):
    df = versions_df.copy()
    view_doc, view_email = [], []
    for r in df.itertuples():
        ft, et = ensure_tokens(con, getattr(r, "id"), bool(getattr(r, "email_path")))
        view_doc.append(f"/?serve={ft}" if ft else "—")
        view_email.append(f"/?serve={et}" if et and getattr(r, "email_path") else "—")
    df["View (doc)"] = view_doc
    df["View (email)"] = view_email
    return df

def page_documents(con, user):
    st.subheader("Browse Documents")
    df = pd.read_sql("SELECT * FROM documents WHERE is_deleted=0", con)
    if df.empty:
        st.info("No documents available"); return

    col1, col2, col3 = st.columns(3)
    with col1: t = st.selectbox("Type", ["All"] + sorted(df["doc_type"].unique().tolist()))
    with col2: name_q = st.text_input("Search name")
    with col3: appr_q = st.text_input("Approved by")

    f = df.copy()
    if t != "All": f = f[f["doc_type"] == t]
    if name_q:     f = f[f["name"].str.contains(name_q, case=False, na=False)]
    if appr_q:     f = f[f["approved_by"].str.contains(appr_q, case=False, na=False)]

    if f.empty:
        st.info("No matching documents"); return

    f["version"] = f["version"].astype(int)
    latest_flags = f.groupby(["doc_type", "name"])["version"].transform("max")
    f["is_latest"] = f["version"] == latest_flags

    st.dataframe(
        f[["doc_type", "name", "version", "is_latest", "created_date", "upload_date", "approved_by", "uploaded_by"]],
        use_container_width=True
    )

def page_deleted(con, user):
    st.subheader("Deleted Versions")
    df = pd.read_sql("SELECT * FROM documents WHERE is_deleted=1", con)
    if df.empty:
        st.info("None"); return
    st.dataframe(df[["id", "doc_type", "name", "version", "uploaded_by"]], use_container_width=True)
    sel = st.selectbox("Restore ID", df["id"])
    if st.button("Restore"):
        con.execute("UPDATE documents SET is_deleted=0 WHERE id=?", (sel,))
        con.commit()
        insert_audit(con, user["username"], "RESTORE", sel)
        backup_db_to_dropbox()
        st.success("Restored"); st.rerun()

def page_audit(con, user=None):
    st.subheader("Audit Log")
    df = pd.read_sql("SELECT * FROM audit_log ORDER BY ts DESC", con)
    if df.empty:
        st.info("No logs"); return
    st.download_button("⬇️ Export CSV", df.to_csv(index=False).encode(), "audit.csv")
    buf = BytesIO(); df.to_excel(buf, index=False)
    st.download_button("⬇️ Export Excel", buf.getvalue(), "audit.xlsx")
    st.dataframe(df, use_container_width=True)

# ===================================================================
#                                MAIN
# ===================================================================
def main():
    st.set_page_config(APP_TITLE, layout="wide")
    con = st.session_state.get("con") or init_db()
    st.session_state["con"] = con

    user = st.session_state.get("user")
    if not user:
        st.title(APP_TITLE)
        u = st.text_input("Email")
        p = st.text_input("Password", type="password")
        if st.button("Login"):
            auth = authenticate(u, p)
            if auth:
                st.session_state["user"] = auth
                insert_audit(con, u, "LOGIN")
                st.rerun()
            else:
                st.error("Invalid credentials")
                return
    else:
        st.sidebar.write(f"Signed in as {user['username']} ({user['role']})")
        if st.sidebar.button("Logout"):
            insert_audit(con, user["username"], "LOGOUT")
            st.session_state.pop("user")
            st.rerun()

        tabs = ["Documents", "Upload"]
        if user["role"] == "viewer":
            tabs = ["Documents"]
        if user["role"] == "admin":
            tabs += ["Deleted", "Audit"]

        t = st.tabs(tabs)
        with t[0]:
            page_documents(con, user)
        if "Upload" in tabs:
            with t[tabs.index("Upload")]:
                page_upload(con, user)
        if "Deleted" in tabs:
            with t[tabs.index("Deleted")]:
                page_deleted(con, user)
        if "Audit" in tabs:
            with t[tabs.index("Audit")]:
                page_audit(con)

if __name__ == "__main__":
    main()
