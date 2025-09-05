
# app.py
# ------------------------------------------------------------------
# HR Document Portal — Streamlit (enhanced with Dashboard & Compliance)
# - Users, roles, audit log
# - SOP/BRD/Policy + Contract Management (versioned, view links)
# - Storage backends (priority): Google Drive -> Dropbox -> Local
# - 30-day "stay signed in" token via URL ?auth=... (survives reload)
# - Robust PDF viewer with base64 <object>/<embed> + download fallback
# - New: Dashboard, Integrity checks, Token health, Audit Pack generator
# ------------------------------------------------------------------

import base64, hashlib, datetime as dt, sqlite3, mimetypes, secrets, zipfile, json
from pathlib import Path
from io import BytesIO
import pandas as pd
import streamlit as st

APP_TITLE = "HR Document Portal"

import os

# 🔵 Load CSS (Figma export) — tolerant if file missing
def load_css():
    try:
        with open("style.css") as f:
            st.markdown(f"<style>{f.read()}</style>", unsafe_allow_html=True)
    except FileNotFoundError:
        pass

# ---------------- Local storage (fallback when no cloud available)
LOCAL_STORAGE_DIR = Path("storage/HR_Documents_Portal")
LOCAL_DB_PATH = Path("storage/hr_docs.db")
LOCAL_STORAGE_DIR.mkdir(parents=True, exist_ok=True)
LOCAL_DB_PATH.parent.mkdir(parents=True, exist_ok=True)

# ===================================================================
#                         DROPBOX (optional)
# ===================================================================
USE_DROPBOX = False
dbx = None
DBX_ROOT = None
try:
    import dropbox
    if "DROPBOX_REFRESH_TOKEN" in st.secrets:
        dbx = dropbox.Dropbox(
            oauth2_refresh_token=st.secrets["DROPBOX_REFRESH_TOKEN"],
            app_key=st.secrets["DROPBOX_APP_KEY"],
            app_secret=st.secrets["DROPBOX_APP_SECRET"],
        )
        USE_DROPBOX = True
    elif "DROPBOX_ACCESS_TOKEN" in st.secrets and st.secrets["DROPBOX_ACCESS_TOKEN"].strip():
        dbx = dropbox.Dropbox(st.secrets["DROPBOX_ACCESS_TOKEN"].strip())
        USE_DROPBOX = True
    DBX_ROOT = st.secrets.get("DROPBOX_ROOT", "/HR_Documents_Portal").rstrip("/")
except Exception:
    USE_DROPBOX = False
    DBX_ROOT = "/HR_Documents_Portal"

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

# ===================================================================
#                       GOOGLE DRIVE (optional)
# ===================================================================
USE_GDRIVE = False
gdrive_service = None
GDRIVE_ROOT_ID = None

try:
    if st.secrets.get("GDRIVE_ENABLED", False):
        from google.oauth2.service_account import Credentials
        from googleapiclient.discovery import build

        creds = Credentials.from_service_account_info(
            st.secrets["GDRIVE_SERVICE_ACCOUNT_JSON"],
            scopes=["https://www.googleapis.com/auth/drive"]
        )
        gdrive_service = build("drive", "v3", credentials=creds)
        GDRIVE_ROOT_ID = st.secrets["GDRIVE_ROOT_FOLDER_ID"]
        USE_GDRIVE = True
except Exception as e:
    st.warning(f"Google Drive not configured: {e}")
    USE_GDRIVE = False

def gdrive_get_or_create_folder(parent_id: str, name: str) -> str:
    q = f"'{parent_id}' in parents and name='{name}' and mimeType='application/vnd.google-apps.folder' and trashed=false"
    res = gdrive_service.files().list(q=q, fields="files(id,name)").execute()
    files = res.get("files", [])
    if files:
        return files[0]["id"]
    meta = {"name": name, "mimeType": "application/vnd.google-apps.folder", "parents": [parent_id]}
    folder = gdrive_service.files().create(body=meta, fields="id").execute()
    return folder["id"]

def gdrive_upload_bytes(parts: list[str], filename: str, data: bytes) -> str:
    parent = GDRIVE_ROOT_ID
    for p in parts:
        parent = gdrive_get_or_create_folder(parent, p)
    from googleapiclient.http import MediaIoBaseUpload  # import inside to avoid top-level dep if disabled
    media = MediaIoBaseUpload(BytesIO(data), mimetype=mimetypes.guess_type(filename)[0] or "application/octet-stream")
    meta = {"name": filename, "parents": [parent]}
    f = gdrive_service.files().create(body=meta, media_body=media, fields="id").execute()
    return f["id"]

def gdrive_download_bytes(file_id: str) -> bytes | None:
    try:
        req = gdrive_service.files().get_media(fileId=file_id)
        buf = BytesIO()
        from googleapiclient.http import MediaIoBaseDownload
        downloader = MediaIoBaseDownload(buf, req)
        done = False
        while not done:
            _, done = downloader.next_chunk()
        return buf.getvalue()
    except Exception:
        return None

def gdrive_exists(file_id: str) -> bool:
    try:
        gdrive_service.files().get(fileId=file_id, fields="id").execute()
        return True
    except Exception:
        return False

# ===================================================================
#                             STORAGE API
# Priority: Google Drive -> Dropbox -> Local
# ===================================================================
def is_dbx_path(p: str) -> bool:
    return p.startswith("dbx:/")

def to_display_name(p: str) -> str:
    if p.startswith("gdrive:"):
        parts = p.split(":", 2)
        return parts[2] if len(parts) > 2 else "file"
    return Path(p.split(":", 1)[1] if is_dbx_path(p) else p).name

def write_bytes_return_ref(data: bytes, *, doc_type: str, name: str, version: int, filename: str) -> str:
    safe_name = "".join(c for c in name if c.isalnum() or c in (" ", "_", "-")).strip().replace(" ", "_")
    if USE_GDRIVE:
        file_id = gdrive_upload_bytes([doc_type, safe_name, f"v{version}"], filename, data)
        return f"gdrive:{file_id}:{filename}"
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
    if ref.startswith("gdrive:"):
        file_id = ref.split(":", 2)[1]
        return gdrive_download_bytes(file_id)
    if is_dbx_path(ref):
        return dbx_download_bytes(ref.split(":", 1)[1])
    p = Path(ref.split(":", 1)[1])
    return p.read_bytes() if p.exists() else None

def ref_exists(ref: str) -> bool:
    if ref.startswith("gdrive:"):
        file_id = ref.split(":", 2)[1]
        return gdrive_exists(file_id)
    if is_dbx_path(ref):
        return dbx_exists(ref.split(":", 1)[1])
    return Path(ref.split(":", 1)[1]).exists()

# ===================================================================
#                                DB
# ===================================================================
def _hash(pw):
    return hashlib.sha256(pw.encode()).hexdigest()

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
            details TEXT
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

    # Ensure default admin
    cur.execute("SELECT COUNT(*) FROM users WHERE role='admin'")
    if cur.fetchone()[0] == 0:
        default_admin = st.secrets.get("DEFAULT_ADMIN_EMAIL", "admin@cars24.com").lower()
        default_pwd = st.secrets.get("DEFAULT_ADMIN_PASSWORD", "admin123")
        cur.execute(
            "INSERT OR IGNORE INTO users (email,password_sha256,role,created_date) VALUES (?,?,?,?)",
            (default_admin, _hash(default_pwd), "admin", dt.datetime.utcnow().isoformat()),
        )
        con.commit()

    # --- Non-breaking schema adds ---
    alters = [
        # existing from earlier
        "ALTER TABLE documents ADD COLUMN remarks TEXT",
        "ALTER TABLE contracts ADD COLUMN remarks TEXT",
        "ALTER TABLE contracts ADD COLUMN renewal_notice_days INTEGER",
        # new: documents
        "ALTER TABLE documents ADD COLUMN classification TEXT",
        "ALTER TABLE documents ADD COLUMN owner_email TEXT",
        "ALTER TABLE documents ADD COLUMN retention_policy TEXT",
        "ALTER TABLE documents ADD COLUMN legal_hold INTEGER DEFAULT 0",
        "ALTER TABLE documents ADD COLUMN file_token_expires TEXT",
        "ALTER TABLE documents ADD COLUMN email_token_expires TEXT",
        # new: contracts
        "ALTER TABLE contracts ADD COLUMN risk_rating TEXT",
        "ALTER TABLE contracts ADD COLUMN auto_renew INTEGER DEFAULT 0",
        "ALTER TABLE contracts ADD COLUMN currency TEXT",
        "ALTER TABLE contracts ADD COLUMN annual_value REAL",
        "ALTER TABLE contracts ADD COLUMN file_token_expires TEXT",
        "ALTER TABLE contracts ADD COLUMN email_token_expires TEXT",
        # new: audit_log
        "ALTER TABLE audit_log ADD COLUMN ip TEXT",
        "ALTER TABLE audit_log ADD COLUMN user_agent TEXT",
        "ALTER TABLE audit_log ADD COLUMN token TEXT",
        "ALTER TABLE audit_log ADD COLUMN table_name TEXT",
    ]
    for stmt in alters:
        try:
            cur.execute(stmt)
        except sqlite3.OperationalError:
            pass

    # Helpful indexes
    indexes = [
        "CREATE INDEX IF NOT EXISTS idx_docs_type_name_version ON documents(doc_type, name, version)",
        "CREATE INDEX IF NOT EXISTS idx_contracts_vendor_name_version ON contracts(vendor, name, version)",
        "CREATE INDEX IF NOT EXISTS idx_audit_ts_action ON audit_log(ts, action)",
        "CREATE INDEX IF NOT EXISTS idx_audit_actor ON audit_log(actor)",
    ]
    for ix in indexes:
        try:
            cur.execute(ix)
        except sqlite3.OperationalError:
            pass

    con.commit()
    return con

def backup_db_to_dropbox():
    if USE_DROPBOX and LOCAL_DB_PATH.exists():
        dbx_upload_bytes(dbx_path("db", "hr_docs.db"), LOCAL_DB_PATH.read_bytes())

def insert_audit(con, actor, action, doc_id=None, details="", token=None, table_name=None, ip=None, user_agent=None):
    con.execute(
        "INSERT INTO audit_log(ts,actor,action,doc_id,details,token,table_name,ip,user_agent) VALUES (?,?,?,?,?,?,?,?,?)",
        (dt.datetime.utcnow().isoformat(), actor, action, doc_id, details, token, table_name, ip, user_agent),
    )
    con.commit()
    backup_db_to_dropbox()

def authenticate(username, password, con):
    cur = con.execute("SELECT email,password_sha256,role FROM users WHERE email=?", (username.strip().lower(),))
    row = cur.fetchone()
    if row and _hash(password) == row[1]:
        return {"username": row[0], "role": row[2]}
    return None

# ---------- login-token helpers (URL ?auth=...) ----------
def new_auth_token(con, email, days=30):
    token = secrets.token_urlsafe(24)
    exp = (dt.datetime.utcnow() + dt.timedelta(days=days)).isoformat()
    con.execute("INSERT OR REPLACE INTO auth_tokens (token,email,expires) VALUES (?,?,?)", (token, email, exp))
    con.commit(); backup_db_to_dropbox()
    return token

def validate_auth_token(con, token) -> dict | None:
    cur = con.execute("SELECT email,expires FROM auth_tokens WHERE token=?", (token,))
    r = cur.fetchone()
    if not r:
        return None
    email, expires = r
    if dt.datetime.fromisoformat(expires) < dt.datetime.utcnow():
        con.execute("DELETE FROM auth_tokens WHERE token=?", (token,))
        con.commit(); backup_db_to_dropbox()
        return None
    cur = con.execute("SELECT role FROM users WHERE email=?", (email,))
    row = cur.fetchone()
    if not row:
        return None
    return {"username": email, "role": row[0]}

def delete_auth_token(con, token):
    con.execute("DELETE FROM auth_tokens WHERE token=?", (token,))
    con.commit(); backup_db_to_dropbox()

# ===================================================================
#                        APP HELPERS
# ===================================================================
def sha256_bytes(b):
    h = hashlib.sha256(); h.update(b); return h.hexdigest()

def gen_token():
    return secrets.token_urlsafe(16)

def _default_token_expiry(days=7):
    return (dt.datetime.utcnow() + dt.timedelta(days=days)).isoformat()

def ensure_tokens(con, row_id, email_exists, days=7):
    # Ensure tokens and expiries exist
    cur = con.execute("SELECT file_token,email_token,file_token_expires,email_token_expires FROM documents WHERE id=?", (row_id,))
    row = cur.fetchone()
    if not row:
        return None, None
    ft, et, fexp, eexp = row
    changed = False
    if not ft:
        ft = gen_token(); changed = True
        con.execute("UPDATE documents SET file_token=? WHERE id=?", (ft, row_id))
    if not fexp:
        fexp = _default_token_expiry(days); changed = True
        con.execute("UPDATE documents SET file_token_expires=? WHERE id=?", (fexp, row_id))
    if email_exists and not et:
        et = gen_token(); changed = True
        con.execute("UPDATE documents SET email_token=? WHERE id=?", (et, row_id))
    if email_exists and not eexp:
        eexp = _default_token_expiry(days); changed = True
        con.execute("UPDATE documents SET email_token_expires=? WHERE id=?", (eexp, row_id))
    if changed:
        con.commit(); backup_db_to_dropbox()
    return ft, et

def ensure_tokens_generic(con, table, row_id, email_exists, days=7):
    cur = con.execute(f"SELECT file_token,email_token,file_token_expires,email_token_expires FROM {table} WHERE id=?", (row_id,))
    row = cur.fetchone()
    if not row:
        return None, None
    ft, et, fexp, eexp = row; changed = False
    if not ft:
        ft = gen_token(); changed = True
        con.execute(f"UPDATE {table} SET file_token=? WHERE id=?", (ft, row_id))
    if not fexp:
        fexp = _default_token_expiry(days); changed = True
        con.execute(f"UPDATE {table} SET file_token_expires=? WHERE id=?", (fexp, row_id))
    if email_exists and not et:
        et = gen_token(); changed = True
        con.execute(f"UPDATE {table} SET email_token=? WHERE id=?", (et, row_id))
    if email_exists and not eexp:
        eexp = _default_token_expiry(days); changed = True
        con.execute(f"UPDATE {table} SET email_token_expires=? WHERE id=?", (eexp, row_id))
    if changed:
        con.commit(); backup_db_to_dropbox()
    return ft, et

def make_zip(refs: list) -> bytes:
    buf = BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        for ref in refs:
            if ref and ref_exists(ref):
                data = read_ref_bytes(ref)
                if data is not None:
                    zf.writestr(to_display_name(ref), data)
    return buf.getvalue()

def _days_to_expiry(end_series):
    end_dt = pd.to_datetime(end_series, errors="coerce")
    today_ts = pd.Timestamp(dt.date.today())
    return (end_dt - today_ts).dt.days

def soft_delete_record(con, table: str, row_id: int, actor: str, reason: str = ""):
    con.execute(f"UPDATE {table} SET is_deleted=1 WHERE id=?", (row_id,))
    con.commit()
    action = "DELETE_CONTRACT" if table == "contracts" else "DELETE_DOC"
    insert_audit(con, actor, action, row_id, details=f"table={table};id={row_id};reason={reason}", table_name=table)
    backup_db_to_dropbox()

def restore_record(con, table: str, row_id: int, actor: str, reason: str = ""):
    con.execute(f"UPDATE {table} SET is_deleted=0 WHERE id=?", (row_id,))
    con.commit()
    action = "RESTORE_CONTRACT" if table == "contracts" else "RESTORE_DOC"
    det = f"table={table};id={row_id}"
    if reason:
        det += f";reason={reason}"
    insert_audit(con, actor, action, row_id, details=det, table_name=table)
    backup_db_to_dropbox()

def last_delete_info(con, table: str, row_id: int):
    act = "DELETE_CONTRACT" if table == "contracts" else "DELETE_DOC"
    row = con.execute(
        "SELECT actor, ts FROM audit_log WHERE action=? AND doc_id=? ORDER BY ts DESC LIMIT 1",
        (act, row_id)
    ).fetchone()
    return row if row else ("", "")

# ---------- Display helpers ----------
def title_case_role(val: str) -> str:
    return {"admin": "Admin", "editor": "Editor", "viewer": "Viewer"}.get(str(val).lower(), str(val).title())

def rename_columns(df: pd.DataFrame, mapping: dict) -> pd.DataFrame:
    return df.rename(columns=mapping)

def _latest_versions_df(con, doc_type):
    q = """
    SELECT * FROM documents d
    WHERE d.is_deleted=0 AND d.doc_type=?
      AND d.version = (
        SELECT MAX(version) FROM documents d2
        WHERE d2.is_deleted=0 AND d2.doc_type=d.doc_type AND d2.name=d.name
      )
    ORDER BY name COLLATE NOCASE
    """
    df = pd.read_sql(q, con, params=(doc_type,))
    if df.empty:
        return df
    return versions_with_links(con, df)


# ===================================================================
#                                PAGES
# ===================================================================
def versions_with_links(con, versions_df):
    df = versions_df.copy()
    view_doc, view_email = [], []
    for r in df.itertuples():
        ft, et = ensure_tokens(con, getattr(r, "id"), bool(getattr(r, "email_path")))
        view_doc.append(f"/?serve={ft}" if ft else "—")
        view_email.append(f"/?serve={et}" if et and getattr(r, "email_path") else "—")
    df["Document Link"] = view_doc
    df["Approval Link"] = view_email
    return df

def versions_with_links_contracts(con, versions_df):
    df = versions_df.copy()
    view_doc, view_email = [], []
    for r in df.itertuples():
        ft, et = ensure_tokens_generic(con, "contracts", getattr(r, "id"), bool(getattr(r, "email_path")))
        view_doc.append(f"/?serve={ft}" if ft else "—")
        view_email.append(f"/?serve={et}" if et and getattr(r, "email_path") else "—")
    df["Document Link"] = view_doc
    df["Approval Link"] = view_email
    return df

# --- Delete UI helper (Reason required; button below Reason) ---
def delete_version_ui(*, entity: str, table: str, versions_df: pd.DataFrame, con, user):
    st.markdown("#### Delete")
    sel_v = st.selectbox(
        "Version to delete",
        versions_df["version"].tolist(),
        key=f"del_{entity}_v"
    )
    reason = st.text_input(
        "Reason (required)",
        key=f"del_{entity}_reason",
        help="Add a short justification; it will be recorded in the Audit Logs."
    )
    if st.button("Delete Version", key=f"btn_del_{entity}"):
        if not reason.strip():
            st.error("Please enter a reason.")
            return
        row_id = int(versions_df.loc[versions_df["version"] == sel_v, "id"].iloc[0])
        soft_delete_record(con, table, row_id, user["username"], reason.strip())
        st.success(f"{entity.capitalize()} version {sel_v} moved to Deleted Files")
        st.rerun()

def page_upload(con, user):
    st.subheader("Document Management")

    if user["role"] not in {"admin", "editor"}:
        st.info("You have viewer access — uploads are disabled.")
        return

    with st.form("upf", clear_on_submit=True):
        doc_type = st.selectbox("Document Type", ["SOP", "BRD", "Policy"])
        name = st.text_input("Name")
        created_date = st.date_input("Created On", dt.date.today())
        approved_by = st.text_input("Approved By")
        remarks = st.text_area("Remarks / Context *", height=100)
        doc = st.file_uploader("Key Document *")
        email = st.file_uploader("Approval/Email Attachment (optional)")
        ok = st.form_submit_button("Upload")

    if ok:
        if not name or not doc or not remarks.strip():
            st.error("Please provide Name, Key Document, and Remarks / Context.")
            return

        data = doc.read()
        cur = con.execute("SELECT MAX(version) FROM documents WHERE name=? AND doc_type=?", (name, doc_type))
        maxv = cur.fetchone()[0]
        version = (maxv + 1) if maxv else 1

        file_ref = write_bytes_return_ref(data, doc_type=doc_type, name=name, version=version, filename=doc.name)
        email_ref = ""
        if email:
            email_ref = write_bytes_return_ref(email.read(), doc_type=doc_type, name=name, version=version,
                                               filename="email_" + email.name)

        ft, et = gen_token(), (gen_token() if email_ref else None)
        fexp = _default_token_expiry(7)
        eexp = _default_token_expiry(7) if email_ref else None

        con.execute(
            """INSERT INTO documents
               (doc_type,name,created_date,upload_date,approved_by,file_path,email_path,version,uploaded_by,hash_sha256,
                is_deleted,file_token,email_token,remarks,file_token_expires,email_token_expires)
               VALUES (?,?,?,?,?,?,?,?,?,?,0,?,?,?, ?, ?)""",
            (
                doc_type, name, str(created_date), dt.datetime.utcnow().isoformat(),
                approved_by, file_ref, email_ref, version, user["username"], sha256_bytes(data),
                ft, et, remarks.strip(), fexp, eexp
            ),
        )
        con.commit()
        insert_audit(con, user["username"], "UPLOAD",
                     details=f"Uploaded doc_type={doc_type};name={name};v={version};approved_by='{approved_by}';remarks='{remarks.strip()}'",
                     table_name="documents")
        backup_db_to_dropbox()
        st.success(f"Uploaded as version {version}")

def page_documents(con, user):
    st.subheader("Browse Documents")

    docs = pd.read_sql("SELECT * FROM documents WHERE is_deleted=0", con)

    # Contracts appear here as "Contract"
    c = pd.read_sql(
        """SELECT id, 'Contract' AS doc_type, name,
                  start_date AS created_date, upload_date,
                  vendor AS approved_by, uploaded_by, version, remarks, vendor
           FROM contracts WHERE is_deleted=0""",
        con
    )

    d = docs[["id","doc_type","name","created_date","upload_date","approved_by",
              "uploaded_by","version","remarks"]].copy()
    d["vendor"] = ""
    f = pd.concat([d, c], ignore_index=True)

    if f.empty:
        st.info("No documents available"); return

    col1, col2, col3 = st.columns(3)
    with col1: t = st.selectbox("File Type", ["All"] + sorted(f["doc_type"].unique().tolist()), key="docs_filter_type")
    with col2: name_q = st.text_input("Search Name", key="docs_filter_name")
    with col3: apr_vendor_q = st.text_input("Approved By / Vendor", key="docs_filter_appr")

    g = f.copy()
    if t != "All": g = g[g["doc_type"] == t]
    if name_q:     g = g[g["name"].str.contains(name_q, case=False, na=False)]
    if apr_vendor_q:
        g = g[g["approved_by"].str.contains(apr_vendor_q, case=False, na=False)]

    if g.empty:
        st.info("No matching documents"); return

    g["version"] = pd.to_numeric(g["version"], errors="coerce").fillna(0).astype(int)
    latest_flags = g.groupby(["doc_type", "name"])["version"].transform("max")
    g["is_latest"] = g["version"] == latest_flags

    g_display = rename_columns(
        g[["doc_type", "name", "version", "is_latest", "created_date", "upload_date",
           "approved_by", "uploaded_by", "remarks"]],
        {
            "doc_type": "Document Type",
            "name": "Name",
            "version": "Version",
            "is_latest": "Is Latest",
            "created_date": "Created On",
            "upload_date": "Uploaded On",
            "approved_by": "Approved By",
            "uploaded_by": "Uploaded By",
            "remarks": "Remarks",
        }
    )
    st.dataframe(g_display, use_container_width=True)

    st.markdown("---")
    st.markdown("### Document Versions")
    groups = g.drop_duplicates(subset=["doc_type", "name", "vendor"])
    labels = [f"{r.doc_type} — {r.name}" for r in groups.itertuples()]
    if not labels: return

    pick = st.selectbox("Select Document", labels, key="docs_group_pick")
    if not pick: return
    sel_group = groups.iloc[labels.index(pick)]

    # -------- CONTRACTS branch --------
    if sel_group["doc_type"] == "Contract":
        versions = pd.read_sql(
            "SELECT * FROM contracts WHERE name=? AND vendor=? AND is_deleted=0 ORDER BY version DESC",
            con, params=(sel_group["name"], sel_group["vendor"])
        )
        v_table = versions_with_links_contracts(con, versions)
        v_show = v_table[["version","upload_date","uploaded_by","status",
                          "start_date","end_date","remarks","Document Link","Approval Link"]]
        v_show = rename_columns(
            v_show,
            {
                "version": "Version",
                "upload_date": "Uploaded On",
                "uploaded_by": "Uploaded By",
                "status": "Status",
                "start_date": "Start Date",
                "end_date": "End Date",
                "remarks": "Remarks",
            }
        )
        st.data_editor(
            v_show, use_container_width=True, disabled=True,
            key=f"docs_contracts_versions_{sel_group['vendor']}_{sel_group['name']}",
            column_config={
                "Document Link": st.column_config.LinkColumn("Document Link"),
                "Approval Link": st.column_config.LinkColumn("Approval Link"),
            }
        )

        if user["role"] in {"admin", "editor"} and not versions.empty:
            delete_version_ui(entity="contract", table="contracts", versions_df=versions, con=con, user=user)

    # -------- DOCUMENTS branch --------
    else:
        versions = pd.read_sql(
            "SELECT * FROM documents WHERE doc_type=? AND name=? AND is_deleted=0 ORDER BY version DESC",
            con, params=(sel_group["doc_type"], sel_group["name"])
        )
        v_table = versions_with_links(con, versions)
        v_show = v_table[["version","upload_date","uploaded_by","approved_by",
                          "is_latest","remarks","Document Link","Approval Link"]]
        v_show = rename_columns(
            v_show,
            {
                "version": "Version",
                "upload_date": "Uploaded On",
                "uploaded_by": "Uploaded By",
                "approved_by": "Approved By",
                "is_latest": "Is Latest",
                "remarks": "Remarks",
            }
        )
        st.data_editor(
            v_show, use_container_width=True, disabled=True,
            key=f"docs_versions_{sel_group['doc_type']}_{sel_group['name']}",
            column_config={
                "Document Link": st.column_config.LinkColumn("Document Link"),
                "Approval Link": st.column_config.LinkColumn("Approval Link"),
            }
        )

        if user["role"] in {"admin", "editor"} and not versions.empty:
            delete_version_ui(entity="document", table="documents", versions_df=versions, con=con, user=user)

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
                renewal = st.number_input("Renewal Notice (days)", min_value=0, value=60, step=5)
            remarks = st.text_area("Remarks / Context *", height=100)
            doc  = st.file_uploader("Contract File (PDF/Doc) *")
            email = st.file_uploader("Approval/Email Attachment (optional)")
            ok = st.form_submit_button("Upload Contract")

        if ok:
            if not name or not vendor or not doc or not remarks.strip():
                st.error("Please fill Contract Name, Vendor, Contract file, and Remarks / Context."); return
            data = doc.read()

            cur = con.execute("SELECT MAX(version) FROM contracts WHERE name=? AND vendor=?", (name, vendor))
            maxv = cur.fetchone()[0]
            version = (maxv + 1) if maxv else 1

            file_ref = write_bytes_return_ref(data, doc_type="Contract", name=name, version=version, filename=doc.name)
            email_ref = ""
            if email:
                email_ref = write_bytes_return_ref(email.read(), doc_type="Contract", name=name, version=version,
                                                   filename="email_" + email.name)

            ft, et = gen_token(), (gen_token() if email_ref else None)
            fexp = _default_token_expiry(7)
            eexp = _default_token_expiry(7) if email_ref else None

            con.execute(
                """INSERT INTO contracts
                   (name,vendor,owner,status,start_date,end_date,renewal_notice_days,
                    created_date,upload_date,uploaded_by,file_path,email_path,version,hash_sha256,
                    is_deleted,file_token,email_token,remarks,file_token_expires,email_token_expires)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,0,?,?,?, ?, ?)""",
                (name, vendor, owner, status, str(start), str(end), int(renewal),
                 str(start), dt.datetime.utcnow().isoformat(), user["username"],
                 file_ref, email_ref, version, sha256_bytes(data), ft, et, remarks.strip(), fexp, eexp)
            )
            con.commit()
            insert_audit(con, user["username"], "CONTRACT_UPLOAD",
                         details=f"Uploaded vendor={vendor};name={name};v={version};status={status};"
                                 f"start={start};end={end};remarks='{remarks.strip()}'",
                         table_name="contracts")
            backup_db_to_dropbox()
            st.success(f"Contract uploaded as version {version}")

    st.markdown("---")
    df = pd.read_sql("SELECT * FROM contracts WHERE is_deleted=0", con)
    if df.empty:
        st.info("No contracts yet."); return

    df["days_to_expiry"] = _days_to_expiry(df["end_date"])

    c1, c2, c3, c4 = st.columns(4)
    with c1: v_q = st.text_input("Search Vendor", key="contracts_filter_vendor")
    with c2: o_q = st.text_input("Search Owner", key="contracts_filter_owner")
    with c3: s_q = st.selectbox("Status", ["All", "Active", "Under review", "Expired"],
                                key="contracts_filter_status")
    with c4: exp_days = st.selectbox("Expiring In", ["All", 30, 60, 90], key="contracts_filter_exp")

    f = df.copy()
    if v_q: f = f[f["vendor"].str.contains(v_q, case=False, na=False)]
    if o_q: f = f[f["owner"].str.contains(o_q, case=False, na=False)]
    if s_q != "All": f = f[f["status"] == s_q]
    if exp_days != "All":
        f = f[(f["days_to_expiry"] >= 0) & (f["days_to_expiry"] <= int(exp_days))]

    if f.empty:
        st.info("No matching contracts"); return

    f["version"] = pd.to_numeric(f["version"], errors="coerce").fillna(0).astype(int)
    latest_flags = f.groupby(["vendor", "name"])["version"].transform("max")
    f["is_latest"] = f["version"] == latest_flags

    f_display = rename_columns(
        f[["vendor","name","status","start_date","end_date","days_to_expiry",
           "version","is_latest","uploaded_by","remarks"]],
        {
            "vendor": "Vendor",
            "name": "Name",
            "status": "Status",
            "start_date": "Start Date",
            "end_date": "End Date",
            "days_to_expiry": "Days to Expiry",
            "version": "Version",
            "is_latest": "Is Latest",
            "uploaded_by": "Uploaded By",
            "remarks": "Remarks",
        }
    )
    st.dataframe(f_display, use_container_width=True)

    st.markdown("### Version History")
    groups = f.drop_duplicates(subset=["vendor","name"])
    labels = [f"{r.vendor} — {r.name}" for r in groups.itertuples()]
    if labels:
        pick = st.selectbox("Select Contract", labels, key="contracts_group_pick")
        if pick:
            sel_group = groups.iloc[labels.index(pick)]
            versions = f[(f["vendor"] == sel_group["vendor"]) & (f["name"] == sel_group["name"])]\
                .sort_values("version", ascending=False)
            v_table = versions_with_links_contracts(con, versions)
            v_show = v_table[["version","upload_date","uploaded_by","status",
                              "start_date","end_date","remarks","Document Link","Approval Link"]]
            v_show = rename_columns(
                v_show,
                {
                    "version": "Version",
                    "upload_date": "Uploaded On",
                    "uploaded_by": "Uploaded By",
                    "status": "Status",
                    "start_date": "Start Date",
                    "end_date": "End Date",
                    "remarks": "Remarks",
                }
            )
            st.data_editor(
                v_show, use_container_width=True, disabled=True,
                key=f"contracts_versions_{sel_group['vendor']}_{sel_group['name']}",
                column_config={
                    "Document Link": st.column_config.LinkColumn("Document Link"),
                    "Approval Link": st.column_config.LinkColumn("Approval Link")
                }
            )

# ---------------- Deleted / Audit / Users ----------------
def page_deleted(con, user):
    st.subheader("Deleted Files")

    tab_docs, tab_contracts = st.tabs(["Documents", "Contracts"])

    with tab_docs:
        df = pd.read_sql("SELECT * FROM documents WHERE is_deleted=1 ORDER BY upload_date DESC", con)
        if df.empty:
            st.info("No deleted documents.")
        else:
            deleted_by, deleted_at = [], []
            for rid in df["id"].tolist():
                who, when = last_delete_info(con, "documents", int(rid))
                deleted_by.append(who); deleted_at.append(when)
            df["deleted_by"] = deleted_by
            df["deleted_at"] = deleted_at
            df_display = rename_columns(
                df[["id","doc_type","name","version","uploaded_by","deleted_by","deleted_at","remarks"]],
                {
                    "id": "ID",
                    "doc_type": "Document Type",
                    "name": "Name",
                    "version": "Version",
                    "uploaded_by": "Uploaded By",
                    "deleted_by": "Deleted By (User)",
                    "deleted_at": "Deleted At (UTC)",
                    "remarks": "Remarks",
                }
            )
            st.dataframe(df_display, use_container_width=True)
            if user["role"] == "admin":
                sel = st.selectbox("Restore Document ID", df["id"], key="docs_restore_id")
                restore_reason = st.text_input("Restore Reason (optional)", key="docs_restore_reason")
                if st.button("Restore", key="docs_restore_btn"):
                    restore_record(con, "documents", int(sel), user["username"], restore_reason.strip())
                    st.success("Restored"); st.rerun()

    with tab_contracts:
        dfc = pd.read_sql("SELECT * FROM contracts WHERE is_deleted=1 ORDER BY upload_date DESC", con)
        if dfc.empty:
            st.info("No deleted contracts.")
        else:
            deleted_by, deleted_at = [], []
            for rid in dfc["id"].tolist():
                who, when = last_delete_info(con, "contracts", int(rid))
                deleted_by.append(who); deleted_at.append(when)
            dfc["deleted_by"] = deleted_by
            dfc["deleted_at"] = deleted_at
            dfc_display = rename_columns(
                dfc[["id","vendor","name","version","uploaded_by","deleted_by","deleted_at","remarks"]],
                {
                    "id": "ID",
                    "vendor": "Vendor",
                    "name": "Name",
                    "version": "Version",
                    "uploaded_by": "Uploaded By",
                    "deleted_by": "Deleted By (User)",
                    "deleted_at": "Deleted At (UTC)",
                    "remarks": "Remarks",
                }
            )
            st.dataframe(dfc_display, use_container_width=True)
            if user["role"] == "admin":
                selc = st.selectbox("Restore Contract ID", dfc["id"], key="contracts_restore_id")
                restore_reason_c = st.text_input("Restore Reason (optional)", key="contracts_restore_reason")
                if st.button("Restore Contract", key="contracts_restore_btn"):
                    restore_record(con, "contracts", int(selc), user["username"], restore_reason_c.strip())
                    st.success("Restored"); st.rerun()

def page_audit(con, user=None):
    st.subheader("Audit Logs")
    df = pd.read_sql("SELECT * FROM audit_log ORDER BY ts DESC", con)
    if df.empty:
        st.info("No logs"); return

    # Friendly display names
    df_display = rename_columns(
        df.rename(columns={"actor": "User"}),
        {"ts": "Timestamp (UTC)", "action": "Action", "doc_id": "Record ID", "details": "Details",
         "ip": "IP", "user_agent": "User Agent", "token": "Token", "table_name": "Table"}
    )

    col1, col2 = st.columns([2, 3])
    with col1:
        pick_actions = st.multiselect(
            "Filter Actions",
            sorted(df_display["Action"].unique().tolist()),
            default=[]
        )
    with col2:
        q = st.text_input("Search User/Details")

    f = df_display.copy()
    if pick_actions:
        f = f[f["Action"].isin(pick_actions)]
    if q:
        ql = q.lower()
        f = f[f["User"].str.lower().str.contains(ql) | f["Details"].str.lower().str.contains(ql)]

    st.download_button("⬇️ Export CSV", f.to_csv(index=False).encode(), "audit_logs.csv")
    buf = BytesIO(); f.to_excel(buf, index=False)
    st.download_button("⬇️ Export Excel", buf.getvalue(), "audit_logs.xlsx")
    st.dataframe(f, use_container_width=True)

def page_manage_users(con, user):
    if user["role"] != "admin":
        st.error("Access denied"); return

    st.subheader("User Management")
    with st.form("add_user", clear_on_submit=True):
        email = st.text_input("User Email")
        pwd = st.text_input("Password", type="password")
        role = st.selectbox("Role", ["Admin", "Editor", "Viewer"])
        ok = st.form_submit_button("Add User")
    if ok:
        if not email or not pwd:
            st.error("Email and Password are required.")
        else:
            db_role_val = role.lower()  # store normalized
            try:
                con.execute(
                    "INSERT INTO users (email,password_sha256,role,created_date) VALUES (?,?,?,?)",
                    (email.strip().lower(), _hash(pwd), db_role_val, dt.datetime.utcnow().isoformat()),
                )
                con.commit()
                insert_audit(con, user["username"], "ADD_USER", details=f"email={email.strip().lower()};role={role}")
                backup_db_to_dropbox()
                st.success("User added")
            except sqlite3.IntegrityError:
                st.error("User already exists")

    df = pd.read_sql("SELECT id,email,role,created_date FROM users ORDER BY id DESC", con)
    if not df.empty:
        df["role"] = df["role"].apply(title_case_role)
    df = rename_columns(df, {"id": "ID", "email": "Email", "role": "Role", "created_date": "Created On"})
    st.dataframe(df, use_container_width=True)

    if not df.empty:
        del_id = st.selectbox("Delete User ID", df["ID"])
        if st.button("Delete User"):
            target_email = df[df["ID"] == del_id]["Email"].iloc[0]
            if target_email == user["username"]:
                st.error("You cannot delete yourself.")
            else:
                con.execute("DELETE FROM users WHERE id=?", (int(del_id),))
                con.commit()
                insert_audit(con, user["username"], "DELETE_USER", details=f"email={target_email}")
                backup_db_to_dropbox()
                st.success("User deleted"); st.rerun()

# ============== New: Dashboard, Compliance (Integrity, Tokens, Audit Pack) ==============



def page_dashboard(con, user):
    st.subheader("Overview")

    # Load data
    docs = pd.read_sql("SELECT * FROM documents WHERE is_deleted=0", con)
    contracts = pd.read_sql("SELECT * FROM contracts WHERE is_deleted=0", con)
    logs = pd.read_sql("SELECT ts,actor,action,doc_id,details FROM audit_log ORDER BY ts DESC", con)

    # UTC-safe timestamps
    now_utc = pd.Timestamp.now(tz="UTC")
    last30_utc = now_utc - pd.Timedelta(days=30)

    # Robust parsing
    docs_up = pd.to_datetime(docs.get("upload_date"), utc=True, errors="coerce")
    cons_up = pd.to_datetime(contracts.get("upload_date"), utc=True, errors="coerce")

    # Top-level metrics
    colA, colB, colC, colD = st.columns(4)
    colA.metric("Documents (all versions)", int(len(docs)))
    colB.metric("Contracts (all versions)", int(len(contracts)))
    colC.metric("Unique docs", int(docs[["doc_type","name"]].drop_duplicates().shape[0]))
    colD.metric("New last 30 days", int((docs_up >= last30_utc).sum() + (cons_up >= last30_utc).sum()))

    # Counts by type (distinct names)
    distinct_docs = docs[["doc_type","name"]].drop_duplicates()
    counts = distinct_docs["doc_type"].value_counts().to_dict()
    sops = counts.get("SOP", 0); brds = counts.get("BRD", 0); polic = counts.get("Policy", 0)

    c1, c2, c3 = st.columns(3)
    c1.metric("SOPs", int(sops))
    c2.metric("BRDs", int(brds))
    c3.metric("Policies", int(polic))

    # Uploads over time
    def _bucket(df, label):
        if df.empty: return pd.DataFrame(columns=["date","type","count"])
        tmp = df.copy()
        tmp_dates = pd.to_datetime(tmp["upload_date"], utc=True, errors="coerce").dt.tz_convert(None).dt.date
        tmp = tmp.assign(date=tmp_dates).groupby(["date"]).size().reset_index(name="count")
        tmp["type"] = label
        return tmp

    up_docs = _bucket(docs, "Documents")
    up_cons = _bucket(contracts, "Contracts")
    trend = pd.concat([up_docs, up_cons], ignore_index=True)
    if not trend.empty:
        st.markdown("### Uploads over time")
        st.line_chart(trend.pivot_table(index="date", columns="type", values="count", fill_value=0))

    # Expiring soon
    contracts["days_to_expiry"] = _days_to_expiry(contracts["end_date"])
    exp_60 = contracts[(contracts["days_to_expiry"] >= 0) & (contracts["days_to_expiry"] <= 60)]
    with st.expander("Contracts expiring in the next 60 days", expanded=False):
        st.dataframe(exp_60[["vendor","name","end_date","days_to_expiry","status","uploaded_by"]],
                     use_container_width=True)

    # Most viewed docs (last 30 days)
    log_ts = pd.to_datetime(logs.get("ts"), utc=True, errors="coerce")
    last30_logs = logs[log_ts >= last30_utc]
    top_views = (last30_logs[last30_logs["action"]=="VIEW"]
                 .groupby("doc_id").size().reset_index(name="views")
                 .sort_values("views", ascending=False).head(10))
    with st.expander("Most viewed items (last 30 days)", expanded=False):
        st.dataframe(top_views, use_container_width=True)

    # By document type with full "view all" lists (latest version only)
    st.markdown("### By document type")
    tabs = st.tabs(["SOPs", "BRDs", "Policies"])
    # SOPs
    with tabs[0]:
        df = _latest_versions_df(con, "SOP")
        if df.empty:
            st.info("No SOPs found.")
        else:
            show = df[["name","version","approved_by","upload_date","uploaded_by","remarks","Document Link","Approval Link"]]
            show = rename_columns(show, {
                "name":"Name","version":"Version","approved_by":"Approved By","upload_date":"Uploaded On",
                "uploaded_by":"Uploaded By","remarks":"Remarks"
            })
            st.data_editor(
                show, use_container_width=True, disabled=True,
                column_config={"Document Link": st.column_config.LinkColumn("Document Link"),
                               "Approval Link": st.column_config.LinkColumn("Approval Link")}
            )
    # BRDs
    with tabs[1]:
        df = _latest_versions_df(con, "BRD")
        if df.empty:
            st.info("No BRDs found.")
        else:
            show = df[["name","version","approved_by","upload_date","uploaded_by","remarks","Document Link","Approval Link"]]
            show = rename_columns(show, {
                "name":"Name","version":"Version","approved_by":"Approved By","upload_date":"Uploaded On",
                "uploaded_by":"Uploaded By","remarks":"Remarks"
            })
            st.data_editor(
                show, use_container_width=True, disabled=True,
                column_config={"Document Link": st.column_config.LinkColumn("Document Link"),
                               "Approval Link": st.column_config.LinkColumn("Approval Link")}
            )
    # Policies
    with tabs[2]:
        df = _latest_versions_df(con, "Policy")
        if df.empty:
            st.info("No Policies found.")
        else:
            show = df[["name","version","approved_by","upload_date","uploaded_by","remarks","Document Link","Approval Link"]]
            show = rename_columns(show, {
                "name":"Name","version":"Version","approved_by":"Approved By","upload_date":"Uploaded On",
                "uploaded_by":"Uploaded By","remarks":"Remarks"
            })
            st.data_editor(
                show, use_container_width=True, disabled=True,
                column_config={"Document Link": st.column_config.LinkColumn("Document Link"),
                               "Approval Link": st.column_config.LinkColumn("Approval Link")}
            )


def _parse_retention_to_days(val: str) -> int | None:
    if not val: return None
    try:
        v = val.strip().lower()
        if v.endswith("y"): return int(v[:-1]) * 365
        if v.endswith("m"): return int(v[:-1]) * 30
        if v.endswith("d"): return int(v[:-1])
        return int(v)  # bare days
    except Exception:
        return None

def verify_integrity(con):
    problems = []
    for table in ["documents", "contracts"]:
        rows = con.execute(f"SELECT id, file_path, hash_sha256 FROM {table} WHERE is_deleted=0").fetchall()
        for rid, ref, expected in rows:
            data = read_ref_bytes(ref)
            if data is None:
                problems.append({"table": table, "id": rid, "issue": "Missing file"})
                continue
            actual = sha256_bytes(data)
            if actual != expected:
                problems.append({"table": table, "id": rid, "issue": "Hash mismatch"})
    return pd.DataFrame(problems)

def token_health(con):
    recs = []
    now = dt.datetime.utcnow()
    for table in ["documents", "contracts"]:
        rows = pd.read_sql(f"SELECT id,name,COALESCE(vendor,'') as vendor,file_token,email_token,file_token_expires,email_token_expires FROM {table} WHERE is_deleted=0", con)
        for r in rows.itertuples():
            for kind, tok, exp in [("file", r.file_token, r.file_token_expires), ("email", r.email_token, r.email_token_expires)]:
                if not tok: continue
                status = "ok"
                if not exp:
                    status = "no-expiry"
                else:
                    try:
                        exp_dt = dt.datetime.fromisoformat(exp)
                        if exp_dt < now: status = "expired"
                        elif exp_dt - now <= dt.timedelta(days=3): status = "expiring-soon"
                    except Exception:
                        status = "bad-expiry"
                recs.append({
                    "table": table, "id": r.id, "name": r.name, "vendor": r.vendor if hasattr(r,'vendor') else "",
                    "token_type": kind, "status": status, "expires": exp or ""
                })
    return pd.DataFrame(recs)

def retention_exceptions(con):
    docs = pd.read_sql("SELECT id,name,doc_type,created_date,retention_policy,legal_hold FROM documents WHERE is_deleted=0", con)
    if docs.empty: return pd.DataFrame(columns=["id","name","doc_type","created_date","retention_policy","legal_hold","days_over"])
    docs["created_date"] = pd.to_datetime(docs["created_date"], errors="coerce")
    out = []
    today = pd.Timestamp.today()
    for r in docs.itertuples():
        if getattr(r, "legal_hold", 0) == 1:  # skip
            continue
        days = _parse_retention_to_days(getattr(r, "retention_policy", ""))
        if not days: 
            continue
        if pd.isna(r.created_date):
            continue
        age_days = (today - r.created_date).days
        if age_days > days:
            out.append({
                "id": r.id, "name": r.name, "doc_type": r.doc_type,
                "created_date": str(r.created_date.date()), "retention_policy": r.retention_policy,
                "legal_hold": r.legal_hold, "days_over": age_days - days
            })
    return pd.DataFrame(out)

def generate_audit_pack(con, start, end):
    # 1) Logs
    df = pd.read_sql(
        "SELECT * FROM audit_log WHERE ts BETWEEN ? AND ? ORDER BY ts ASC",
        con, params=(start.isoformat(), end.isoformat()))
    buf_logs = BytesIO(); df.to_csv(buf_logs, index=False); buf_logs.seek(0)

    # 2) Current metadata snapshots
    docs = pd.read_sql("SELECT * FROM documents WHERE is_deleted=0", con)
    cons = pd.read_sql("SELECT * FROM contracts WHERE is_deleted=0", con)
    buf_docs, buf_cons = BytesIO(), BytesIO()
    docs.to_csv(buf_docs, index=False); buf_docs.seek(0)
    cons.to_csv(buf_cons, index=False); buf_cons.seek(0)

    # 3) Zip
    zbuf = BytesIO()
    with zipfile.ZipFile(zbuf, "w", compression=zipfile.ZIP_DEFLATED) as z:
        z.writestr("logs/audit_log.csv", buf_logs.getvalue())
        z.writestr("snapshots/documents.csv", buf_docs.getvalue())
        z.writestr("snapshots/contracts.csv", buf_cons.getvalue())
        z.writestr("readme.txt", b"Audit Pack: logs + current metadata snapshots. Generated by HR Document Portal.")
    return zbuf.getvalue()

def page_compliance(con, user):
    st.subheader("Compliance & Integrity")

    c1, c2 = st.columns(2)
    with c1:
        if st.button("Verify hashes now"):
            out = verify_integrity(con)
            if out.empty:
                st.success("All good. No mismatches.")
            else:
                st.error(f"{len(out)} issues found")
                st.dataframe(out, use_container_width=True)
    with c2:
        s = st.session_state.get("last_audit_pack_status", "")
        if s: st.info(s)

    st.markdown("### Token Health")
    th = token_health(con)
    if th.empty:
        st.info("No tokens found.")
    else:
        st.dataframe(th, use_container_width=True)

    st.markdown("### Retention Exceptions (eligible to purge)")
    rx = retention_exceptions(con)
    if rx.empty:
        st.success("No retention exceptions.")
    else:
        st.dataframe(rx, use_container_width=True)

    st.markdown("### Audit Pack")
    cc1, cc2 = st.columns(2)
    with cc1: start = st.date_input("Start", dt.date.today().replace(day=1))
    with cc2: end = st.date_input("End", dt.date.today())
    if st.button("Generate Audit Pack"):
        data = generate_audit_pack(con, pd.Timestamp(start), pd.Timestamp(end))
        st.download_button("⬇️ Download Audit Pack", data, file_name=f"audit_pack_{start}_{end}.zip")
        st.session_state["last_audit_pack_status"] = f"Generated for {start} to {end}"

# ===================================================================
#                         LOGIN UI (NEW) — ONLY HEADER HIDDEN
# ===================================================================
def style_login():
    """CSS scoped to the login page."""
    st.markdown("""
    <style>
      header[data-testid="stHeader"] { display:none !important; }
      #MainMenu, .stDeployButton, footer { visibility:hidden; }
    </style>
    """, unsafe_allow_html=True)

def login_view():
    """Render login form and return (submitted, email, password, keep)."""
    style_login()
    col_l, col_c, col_r = st.columns([1, 1, 1])
    with col_c:
        with st.form("login_form", clear_on_submit=False):
            st.title(APP_TITLE)
            u = st.text_input("Email", key="login_email")
            p = st.text_input("Password", type="password", key="login_pwd")
            keep = st.checkbox("Keep me signed in on this device", value=True)
            submitted = st.form_submit_button("Login", use_container_width=True)
    return submitted, u, p, keep

# ===================================================================
#                           SERVE MODE HANDLER
# ===================================================================
def _get_client_info():
    # Streamlit doesn't expose headers reliably; store placeholders
    return {"ip": st.session_state.get("_client_ip",""), "ua": st.session_state.get("_client_ua","")}

def handle_serve_mode():
    if "serve" not in st.query_params:
        return False
    token = st.query_params["serve"]
    con = init_db()

    target_ref = None
    found_table, found_id = None, None

    def _not_expired(exp):
        if not exp: return True  # tolerate if missing
        try:
            return dt.datetime.fromisoformat(exp) >= dt.datetime.utcnow()
        except Exception:
            return True

    for rid, fp, ep, ft, et, fexp, eexp in con.execute(
        "SELECT id,file_path,email_path,file_token,email_token,file_token_expires,email_token_expires FROM documents WHERE is_deleted=0"
    ).fetchall():
        if token == ft and _not_expired(fexp): target_ref, found_table, found_id = fp, "documents", rid
        if token == et and _not_expired(eexp): target_ref, found_table, found_id = ep, "documents", rid

    if not target_ref:
        for rid, fp, ep, ft, et, fexp, eexp in con.execute(
            "SELECT id,file_path,email_path,file_token,email_token,file_token_expires,email_token_expires FROM contracts WHERE is_deleted=0"
        ).fetchall():
            if token == ft and _not_expired(fexp): target_ref, found_table, found_id = fp, "contracts", rid
            if token == et and _not_expired(eexp): target_ref, found_table, found_id = ep, "contracts", rid

    if not target_ref or not ref_exists(target_ref):
        st.error("File not found or link expired"); st.stop()

    actor = (st.session_state.get("user") or {}).get("username", "public")
    ci = _get_client_info()
    insert_audit(con, actor, "VIEW", found_id, f"{found_table}:{to_display_name(target_ref)}",
                 token=token, table_name=found_table, ip=ci["ip"], user_agent=ci["ua"])

    data = read_ref_bytes(target_ref)
    name = to_display_name(target_ref)
    mime, _ = mimetypes.guess_type(name)

    st.markdown(f"### {name}")

    if name.lower().endswith(".pdf") and data:
        if len(data) <= 30_000_000:
            b64 = base64.b64encode(data).decode()
            html = f"""
            <object data="data:application/pdf;base64,{b64}#toolbar=1&navpanes=0&view=FitH"
                    type="application/pdf" width="100%" height="820">
              <embed src="data:application/pdf;base64,{b64}#toolbar=1&navpanes=0&view=FitH"
                     type="application/pdf" />
              <p>PDF preview failed. <a href="data:application/pdf;base64,{b64}" download="{name}">Download</a>.</p>
            </object>
            """
            st.components.v1.html(html, height=840, scrolling=False)
        else:
            st.info("Large PDF — preview disabled. Use Download below.")
        st.download_button("⬇️ Download", data, name, mime or "application/pdf")
        st.stop()

    if name.lower().endswith((".png", ".jpg", ".jpeg")) and data:
        st.image(data, use_container_width=True)
    elif name.lower().endswith(".txt") and data:
        st.text(data.decode(errors="replace")[:5000])
    else:
        st.info("Preview not supported inline. Use Download below.")
    st.download_button("⬇️ Download", data, name, mime or "application/octet-stream")
    st.stop()

# ===================================================================
#                                MAIN
# ===================================================================
def main():
    st.set_page_config(APP_TITLE, layout="wide")

    # ✅ Apply Figma CSS styles
    load_css()

    # If in serve mode, render file and stop
    if handle_serve_mode():
        return  # (handle_serve_mode calls st.stop())

    con = st.session_state.get("con") or init_db()
    st.session_state["con"] = con

    # Auto-login via ?auth=
    token_param = st.query_params.get("auth", None)
    if not st.session_state.get("user") and token_param:
        user_from_token = validate_auth_token(con, token_param)
        if user_from_token:
            st.session_state["user"] = user_from_token

    user = st.session_state.get("user")
    if not user:
        submitted, u, p, keep = login_view()
        if submitted:
            auth = authenticate(u, p, con)
            if auth:
                st.session_state["user"] = auth
                insert_audit(con, u, "LOGIN")
                if keep:
                    tok = new_auth_token(con, auth["username"], days=30)
                    st.query_params["auth"] = tok
                st.rerun()
            else:
                st.error("Invalid credentials")
                return
    else:
        role_label = title_case_role(user["role"])
        st.sidebar.write(f"Signed in as {user['username']} ({role_label})")
        if st.sidebar.button("Logout"):
            tok = st.query_params.get("auth", None)
            if tok: delete_auth_token(con, tok)
            if "auth" in st.query_params:
                del st.query_params["auth"]
            insert_audit(con, user["username"], "LOGOUT")
            st.session_state.pop("user")
            st.rerun()

        # Tab labels per request
        tabs = ["Dashboard", "Documents", "Document Management", "Contract Management"]
        if role_label == "Viewer":
            tabs = ["Dashboard", "Documents", "Contract Management"]
        if user["role"] == "admin":
            tabs += ["Deleted Files", "Audit Logs", "Compliance", "User Management"]

        # 🔵 Make tabs blue (active + hover)
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
        with t[0]:
            page_dashboard(con, user)
        with t[tabs.index("Documents")]:
            page_documents(con, user)
        if "Document Management" in tabs:
            with t[tabs.index("Document Management")]:
                page_upload(con, user)
        if "Contract Management" in tabs:
            with t[tabs.index("Contract Management")]:
                page_contracts(con, user)
        if "Deleted Files" in tabs:
            with t[tabs.index("Deleted Files")]:
                page_deleted(con, user)
        if "Audit Logs" in tabs:
            with t[tabs.index("Audit Logs")]:
                page_audit(con)
        if "Compliance" in tabs:
            with t[tabs.index("Compliance")]:
                page_compliance(con, user)
        if "User Management" in tabs:
            with t[tabs.index("User Management")]:
                page_manage_users(con, user)

if __name__ == "__main__":
    main()
