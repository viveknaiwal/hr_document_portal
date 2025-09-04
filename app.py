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

import os

# 🔵 Load CSS (Figma export)
def load_css():
    css_files = ["index.css", "globals.css"]
    for css_file in css_files:
        if os.path.exists(css_file):
            with open(css_file) as f:
                st.markdown(f"<style>{f.read()}</style>", unsafe_allow_html=True)


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

    cur.execute("SELECT COUNT(*) FROM users WHERE role='admin'")
    if cur.fetchone()[0] == 0:
        default_admin = st.secrets.get("DEFAULT_ADMIN_EMAIL", "admin@cars24.com").lower()
        default_pwd = st.secrets.get("DEFAULT_ADMIN_PASSWORD", "admin123")
        cur.execute(
            "INSERT OR IGNORE INTO users (email,password_sha256,role,created_date) VALUES (?,?,?,?)",
            (default_admin, _hash(default_pwd), "admin", dt.datetime.utcnow().isoformat()),
        )
        con.commit()

    # non-breaking schema adds
    for stmt in [
        "ALTER TABLE documents ADD COLUMN remarks TEXT",
        "ALTER TABLE contracts ADD COLUMN remarks TEXT",
        "ALTER TABLE contracts ADD COLUMN renewal_notice_days INTEGER",
    ]:
        try:
            cur.execute(stmt)
        except sqlite3.OperationalError:
            pass

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

def ensure_tokens(con, row_id, email_exists):
    cur = con.execute("SELECT file_token,email_token FROM documents WHERE id=?", (row_id,))
    row = cur.fetchone()
    if not row:
        return None, None
    ft, et = row
    changed = False
    if not ft:
        ft = gen_token(); changed = True
        con.execute("UPDATE documents SET file_token=? WHERE id=?", (ft, row_id))
    if email_exists and not et:
        et = gen_token(); changed = True
        con.execute("UPDATE documents SET email_token=? WHERE id=?", (et, row_id))
    if changed:
        con.commit(); backup_db_to_dropbox()
    return ft, et

def ensure_tokens_generic(con, table, row_id, email_exists):
    cur = con.execute(f"SELECT file_token,email_token FROM {table} WHERE id=?", (row_id,))
    row = cur.fetchone()
    if not row:
        return None, None
    ft, et = row; changed = False
    if not ft:
        ft = gen_token(); changed = True
        con.execute(f"UPDATE {table} SET file_token=? WHERE id=?", (ft, row_id))
    if email_exists and not et:
        et = gen_token(); changed = True
        con.execute(f"UPDATE {table} SET email_token=? WHERE id=?", (et, row_id))
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
    insert_audit(con, actor, action, row_id, details=f"table={table};id={row_id};reason={reason}")
    backup_db_to_dropbox()

def restore_record(con, table: str, row_id: int, actor: str, reason: str = ""):
    con.execute(f"UPDATE {table} SET is_deleted=0 WHERE id=?", (row_id,))
    con.commit()
    action = "RESTORE_CONTRACT" if table == "contracts" else "RESTORE_DOC"
    det = f"table={table};id={row_id}"
    if reason:
        det += f";reason={reason}"
    insert_audit(con, actor, action, row_id, details=det)
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

        con.execute(
            """INSERT INTO documents
               (doc_type,name,created_date,upload_date,approved_by,file_path,email_path,version,uploaded_by,hash_sha256,is_deleted,file_token,email_token,remarks)
               VALUES (?,?,?,?,?,?,?,?,?,?,0,?,?,?)""",
            (
                doc_type, name, str(created_date), dt.datetime.utcnow().isoformat(),
                approved_by, file_ref, email_ref, version, user["username"], sha256_bytes(data), ft, et, remarks.strip()
            ),
        )
        con.commit()
        insert_audit(con, user["username"], "UPLOAD",
                     details=f"Uploaded doc_type={doc_type};name={name};v={version};approved_by='{approved_by}';remarks='{remarks.strip()}'")
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

            con.execute(
                """INSERT INTO contracts
                   (name,vendor,owner,status,start_date,end_date,renewal_notice_days,
                    created_date,upload_date,uploaded_by,file_path,email_path,version,hash_sha256,
                    is_deleted,file_token,email_token,remarks)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,0,?,?,?)""",
                (name, vendor, owner, status, str(start), str(end), int(renewal),
                 str(start), dt.datetime.utcnow().isoformat(), user["username"],
                 file_ref, email_ref, version, sha256_bytes(data), ft, et, remarks.strip())
            )
            con.commit()
            insert_audit(con, user["username"], "CONTRACT_UPLOAD",
                         details=f"Uploaded vendor={vendor};name={name};v={version};status={status};"
                                 f"start={start};end={end};remarks='{remarks.strip()}'")
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
        {"ts": "Timestamp (UTC)", "action": "Action", "doc_id": "Record ID", "details": "Details"}
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
def handle_serve_mode():
    if "serve" not in st.query_params:
        return False
    token = st.query_params["serve"]
    con = init_db()

    target_ref = None
    found_table, found_id = None, None

    for rid, fp, ep, ft, et in con.execute(
        "SELECT id,file_path,email_path,file_token,email_token FROM documents WHERE is_deleted=0"
    ).fetchall():
        if token == ft: target_ref, found_table, found_id = fp, "documents", rid
        if token == et: target_ref, found_table, found_id = ep, "documents", rid

    if not target_ref:
        for rid, fp, ep, ft, et in con.execute(
            "SELECT id,file_path,email_path,file_token,email_token FROM contracts WHERE is_deleted=0"
        ).fetchall():
            if token == ft: target_ref, found_table, found_id = fp, "contracts", rid
            if token == et: target_ref, found_table, found_id = ep, "contracts", rid

    if not target_ref or not ref_exists(target_ref):
        st.error("File not found"); st.stop()

    actor = (st.session_state.get("user") or {}).get("username", "public")
    insert_audit(con, actor, "VIEW", found_id, f"{found_table}:{to_display_name(target_ref)}")

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
        tabs = ["Documents", "Document Management", "Contract Management"]
        if role_label == "Viewer":
            tabs = ["Documents", "Contract Management"]
        if user["role"] == "admin":
            tabs += ["Deleted Files", "Audit Logs", "User Management"]

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
        if "User Management" in tabs:
            with t[tabs.index("User Management")]:
                page_manage_users(con, user)

if __name__ == "__main__":
    main()
