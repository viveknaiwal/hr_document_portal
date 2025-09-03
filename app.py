# app.py
# ------------------------------------------------------------------
# HR Document Portal — Streamlit (Canva-style UI refresh)
# - Clean, friendly UI with soft cards, rounded corners, subtle shadows
# - Top navbar with page pills and quick actions
# - Compact filter bars, status chips, and improved empty states
# - Users, roles, audit log
# - SOP/BRD/Policy + Contract Management (versioned, view links)
# - Storage backends (priority): Google Drive -> Dropbox -> Local
# - 30-day "stay signed in" token via URL ?auth=... (survives reload)
# - Public view of files via /?serve=TOKEN (with inline PDF/image preview)
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
        from googleapiclient.http import MediaIoBaseUpload, MediaIoBaseDownload

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
    media = MediaIoBaseUpload(BytesIO(data), mimetype=mimetypes.guess_type(filename)[0] or "application/octet-stream")
    meta = {"name": filename, "parents": [parent]}
    f = gdrive_service.files().create(body=meta, media_body=media, fields="id").execute()
    return f["id"]


def gdrive_download_bytes(file_id: str) -> bytes | None:
    try:
        req = gdrive_service.files().get_media(fileId=file_id)
        buf = BytesIO()
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
    # Pull latest DB from Dropbox if available
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

    # bootstrap admin
    cur.execute("SELECT COUNT(*) FROM users WHERE role='admin'")
    if cur.fetchone()[0] == 0:
        default_admin = st.secrets.get("DEFAULT_ADMIN_EMAIL", "admin@cars24.com").lower()
        default_pwd = st.secrets.get("DEFAULT_ADMIN_PASSWORD", "admin123")
        cur.execute(
            "INSERT OR IGNORE INTO users (email,password_sha256,role,created_date) VALUES (?,?,?,?)",
            (default_admin, _hash(default_pwd), "admin", dt.datetime.utcnow().isoformat()),
        )
        con.commit()

    # non-breaking schema upgrades
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


# ===================================================================
#                           SERVE MODE (public preview)
# ===================================================================
if "serve" in st.query_params:
    token = st.query_params["serve"]
    con = init_db()

    target_ref = None
    found_table, found_id = None, None

    for rid, fp, ep, ft, et in con.execute(
        "SELECT id,file_path,email_path,file_token,email_token FROM documents WHERE is_deleted=0"
    ).fetchall():
        if token == ft:
            target_ref, found_table, found_id = fp, "documents", rid
        if token == et:
            target_ref, found_table, found_id = ep, "documents", rid

    if not target_ref:
        for rid, fp, ep, ft, et in con.execute(
            "SELECT id,file_path,email_path,file_token,email_token FROM contracts WHERE is_deleted=0"
        ).fetchall():
            if token == ft:
                target_ref, found_table, found_id = fp, "contracts", rid
            if token == et:
                target_ref, found_table, found_id = ep, "contracts", rid

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
#                             UI (Canva-style)
# ===================================================================

def inject_global_styles():
    st.markdown(
        """
        <style>
            :root {
              --brand: #6C63FF;         /* primary */
              --brand-2: #8A85FF;       /* accent */
              --ink: #1f2937;           /* text */
              --muted-ink: #6b7280;     /* secondary text */
              --card: #ffffff;          /* surfaces */
              --bg: #f6f7fb;            /* page background */
              --ring: rgba(108, 99, 255, .25);
              --ok: #22c55e; --warn: #f59e0b; --bad: #ef4444;
              --radius: 16px; --radius-sm: 12px; --radius-lg: 24px;
              --shadow: 0 10px 30px rgba(17, 24, 39, .08);
            }
            html, body, [data-testid="stAppViewContainer"] { background: var(--bg); }

            /* Use Inter */
            @import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap');
            * { font-family: 'Inter', ui-sans-serif, system-ui, -apple-system, Segoe UI, Roboto, Helvetica, Arial, 'Apple Color Emoji', 'Segoe UI Emoji'; }

            /* Buttons */
            .stButton > button {
              border-radius: var(--radius);
              padding: .6rem 1rem; border: 0; box-shadow: var(--shadow);
              background: linear-gradient(135deg, var(--brand), var(--brand-2));
              color: white; font-weight: 600;
            }
            .stButton > button:hover { filter: brightness(1.03); }
            .stButton.secondary > button { background: #ECECFE; color: #3f3aef; box-shadow: none; }

            /* Inputs */
            .stTextInput input, .stTextArea textarea, .stSelectbox [role="combobox"], .stNumberInput input, .stDateInput input {
              border-radius: 12px !important; border: 1px solid #e5e7eb; box-shadow: none;
            }
            .stTextInput input:focus, .stTextArea textarea:focus, .stSelectbox [role="combobox"]:focus, .stNumberInput input:focus, .stDateInput input:focus {
              outline: 0; ring: 0; box-shadow: 0 0 0 4px var(--ring);
            }

            /* Cards */
            .card {
              background: var(--card); border-radius: var(--radius); padding: 1rem 1.25rem; box-shadow: var(--shadow);
            }

            /* Navbar */
            .nav {
              position: sticky; top: 0; z-index: 50; margin-bottom: 1rem;
              background: linear-gradient(180deg, rgba(255,255,255,.85), rgba(255,255,255,.75));
              backdrop-filter: saturate(180%) blur(10px);
              border-bottom: 1px solid rgba(0,0,0,0.06);
              padding: .6rem .8rem; border-radius: 0 0 var(--radius) var(--radius);
            }
            .nav .pill {
              display: inline-flex; gap: .5rem; align-items: center; padding: .45rem .9rem; margin-right: .4rem;
              border-radius: 999px; background: #eef2ff; color: #3730a3; font-weight: 600; cursor: pointer; border: 1px solid #e5e7eb;
            }
            .nav .pill.active { background: #312e81; color: white; border-color: transparent; }

            /* Chips */
            .chip { display: inline-flex; align-items:center; gap:.35rem; padding:.2rem .55rem; border-radius:999px; font-size:.8rem; }
            .chip.ok{ background:#ecfdf5; color:#065f46; }
            .chip.warn{ background:#fffbeb; color:#92400e; }
            .chip.bad{ background:#fef2f2; color:#991b1b; }

            /* Tables */
            .blank-table { border-radius: var(--radius); overflow: hidden; }

            /* Login */
            .login-wrap { min-height: 90vh; display:flex; align-items:center; justify-content:center; }
            .login-card { width: 420px; background: var(--card); padding: 1.25rem 1.25rem 1.75rem; border-radius: var(--radius);
                          box-shadow: var(--shadow); text-align:center; }
            .brand {
              background: conic-gradient(from 180deg at 50% 50%, #dbeafe, #ede9fe, #fee2e2, #dcfce7, #dbeafe);
              height: 60px; width: 60px; border-radius: 16px; display:inline-grid; place-items:center; font-weight:800; color:#312e81;
            }

            /* Floating Action */
            .fab {
              position: fixed; right: 24px; bottom: 24px; border-radius: 999px; box-shadow: var(--shadow);
              background: linear-gradient(135deg, var(--brand), var(--brand-2)); color: white; padding: .85rem 1.1rem; font-weight:700;
            }
        </style>
        """,
        unsafe_allow_html=True,
    )


def app_header(user):
    with st.container():
        st.markdown(
            """
            <div class="nav">
                <div style="display:flex;align-items:center;gap:.75rem;">
                    <div class="brand">HR</div>
                    <div>
                        <div style="font-weight:800; font-size:1.05rem; color:#0f172a;">HR Document Portal</div>
                        <div style="color:#64748b; font-size:.85rem;">SOPs · BRDs · Policies · Contracts</div>
                    </div>
                </div>
            </div>
            """,
            unsafe_allow_html=True,
        )

    # Navbar pills
    pages = ["Documents", "Upload", "Contracts"]
    if user["role"] == "viewer":
        pages = ["Documents", "Contracts"]
    if user["role"] == "admin":
        pages += ["Deleted", "Audit", "Manage Users"]

    current = st.session_state.get("page") or st.query_params.get("page", pages[0])
    if current not in pages:
        current = pages[0]

    # Render pills
    pill_cols = st.columns(len(pages) + 2)
    for i, p in enumerate(pages):
        active = "active" if p == current else ""
        if pill_cols[i].button(p, key=f"nav_{p}"):
            st.session_state["page"] = p
            st.query_params["page"] = p
            st.rerun()
        pill_cols[i].markdown(f"<div class='pill {active}'></div>", unsafe_allow_html=True)

    with pill_cols[-2]:
        st.write("")
    with pill_cols[-1]:
        st.caption(f"Signed in as **{user['username']}** ({user['role']})")
        if st.button("Logout", type="secondary"):
            return "__logout__"

    return current


# ===================================================================
#                               PAGES
# ===================================================================

def stat_cards(con):
    c1, c2, c3 = st.columns(3)
    try:
        docs = con.execute("SELECT COUNT(*) FROM documents WHERE is_deleted=0").fetchone()[0]
        contracts = con.execute("SELECT COUNT(*) FROM contracts WHERE is_deleted=0").fetchone()[0]
        users = con.execute("SELECT COUNT(*) FROM users").fetchone()[0]
    except Exception:
        docs = contracts = users = 0
    with c1:
        st.markdown("<div class='card'><div style='font-size:13px;color:#6b7280'>Documents</div><div style='font-size:28px;font-weight:800'>%d</div></div>" % docs, unsafe_allow_html=True)
    with c2:
        st.markdown("<div class='card'><div style='font-size:13px;color:#6b7280'>Contracts</div><div style='font-size:28px;font-weight:800'>%d</div></div>" % contracts, unsafe_allow_html=True)
    with c3:
        st.markdown("<div class='card'><div style='font-size:13px;color:#6b7280'>Users</div><div style='font-size:28px;font-weight:800'>%d</div></div>" % users, unsafe_allow_html=True)


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
        remarks = st.text_area("Remarks / Context *", height=100)
        doc = st.file_uploader("Key Document *")
        email = st.file_uploader("Approval/email attachment (optional)")
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
                     details=f"Uploaded {doc_type}/{name} v{version}; approved_by='{approved_by}'; remarks='{remarks.strip()}'")
        backup_db_to_dropbox()
        st.toast(f"Uploaded as version {version}")


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


def versions_with_links_contracts(con, versions_df):
    df = versions_df.copy()
    view_doc, view_email = [], []
    for r in df.itertuples():
        ft, et = ensure_tokens_generic(con, "contracts", getattr(r, "id"), bool(getattr(r, "email_path")))
        view_doc.append(f"/?serve={ft}" if ft else "—")
        view_email.append(f"/?serve={et}" if et and getattr(r, "email_path") else "—")
    df["View (doc)"] = view_doc
    df["View (email)"] = view_email
    return df


def empty_state(title: str, hint: str = ""):
    svg = """
    <svg width="120" height="80" viewBox="0 0 200 140" fill="none" xmlns="http://www.w3.org/2000/svg">
      <rect x="20" y="20" width="160" height="100" rx="12" fill="#EEF2FF"/>
      <rect x="38" y="40" width="84" height="10" rx="5" fill="#C7D2FE"/>
      <rect x="38" y="58" width="124" height="10" rx="5" fill="#E0E7FF"/>
      <rect x="38" y="76" width="72" height="10" rx="5" fill="#E0E7FF"/>
    </svg>
    """
    st.markdown(
        f"""
        <div class='card' style='text-align:center;'>
          {svg}
          <div style='font-weight:800; font-size:1.05rem; margin-top:.5rem;'>{title}</div>
          <div style='color:#6b7280; font-size:.9rem;'>{hint}</div>
        </div>
        """,
        unsafe_allow_html=True,
    )


def page_documents(con, user):
    st.subheader("Documents")
    stat_cards(con)

    docs = pd.read_sql("SELECT * FROM documents WHERE is_deleted=0", con)

    # Also show Contracts inside the same browser as type "Contract"
    c = pd.read_sql(
        """
        SELECT id, 'Contract' AS doc_type, name,
               start_date AS created_date, upload_date,
               vendor AS approved_by, uploaded_by, version, remarks, vendor
        FROM contracts WHERE is_deleted=0
        """,
        con,
    )

    d = docs[["id","doc_type","name","created_date","upload_date","approved_by",
              "uploaded_by","version","remarks"]].copy()
    d["vendor"] = ""
    f = pd.concat([d, c], ignore_index=True)

    if f.empty:
        empty_state("No documents yet", "Upload the first SOP/BRD/Policy or add a Contract.")
        return

    with st.container():
        col1, col2, col3 = st.columns(3)
        with col1:
            t = st.selectbox("Type", ["All"] + sorted(f["doc_type"].unique().tolist()), key="docs_filter_type")
        with col2:
            name_q = st.text_input("Search name", key="docs_filter_name")
        with col3:
            apr_vendor_q = st.text_input("Approved by / Vendor", key="docs_filter_appr")

    g = f.copy()
    if t != "All":
        g = g[g["doc_type"] == t]
    if name_q:
        g = g[g["name"].str.contains(name_q, case=False, na=False)]
    if apr_vendor_q:
        g = g[g["approved_by"].str.contains(apr_vendor_q, case=False, na=False)]

    if g.empty:
        empty_state("No matching documents", "Try a different filter or clear the search.")
        return

    g["version"] = pd.to_numeric(g["version"], errors="coerce").fillna(0).astype(int)
    latest_flags = g.groupby(["doc_type", "name"]) ["version"].transform("max")
    g["is_latest"] = g["version"] == latest_flags

    st.dataframe(
        g[["doc_type", "name", "version", "is_latest", "created_date", "upload_date",
           "approved_by", "uploaded_by", "remarks"]],
        use_container_width=True,
    )

    st.markdown("---")
    st.markdown("### Open a document group")
    groups = g.drop_duplicates(subset=["doc_type", "name", "vendor"])
    labels = [f"{r.doc_type} — {r.name}" for r in groups.itertuples()]
    if not labels:
        return

    pick = st.selectbox("Select document", labels, key="docs_group_pick")
    if not pick:
        return
    sel_group = groups.iloc[labels.index(pick)]

    if sel_group["doc_type"] == "Contract":
        versions = pd.read_sql(
            "SELECT * FROM contracts WHERE name=? AND vendor=? AND is_deleted=0 ORDER BY version DESC",
            con, params=(sel_group["name"], sel_group["vendor"]),
        )
        v_table = versions_with_links_contracts(con, versions)
        v_show = v_table[["version","upload_date","uploaded_by","status",
                          "start_date","end_date","remarks","View (doc)","View (email)"]]
        st.data_editor(
            v_show, use_container_width=True, disabled=True,
            key=f"docs_contracts_versions_{sel_group['vendor']}_{sel_group['name']}",
            column_config={
                "View (doc)": st.column_config.LinkColumn("View (doc)"),
                "View (email)": st.column_config.LinkColumn("View (email)")
            }
        )
        # Download all versions in one zip
        if st.button("Download all versions (zip)"):
            refs = [r for r in versions["file_path"].tolist() + versions["email_path"].tolist() if r]
            z = make_zip(refs)
            st.download_button("⬇️ Download contracts.zip", z, "contracts.zip")
    else:
        versions = pd.read_sql(
            "SELECT * FROM documents WHERE doc_type=? AND name=? AND is_deleted=0 ORDER BY version DESC",
            con, params=(sel_group["doc_type"], sel_group["name"]),
        )
        v_table = versions_with_links(con, versions)
        v_show = v_table[["version","upload_date","uploaded_by","approved_by",
                          "is_latest","remarks","View (doc)","View (email)"]]
        st.data_editor(
            v_show, use_container_width=True, disabled=True,
            key=f"docs_versions_{sel_group['doc_type']}_{sel_group['name']}",
            column_config={
                "View (doc)": st.column_config.LinkColumn("View (doc)"),
                "View (email)": st.column_config.LinkColumn("View (email)")
            }
        )
        if st.button("Download all versions (zip)"):
            refs = [r for r in versions["file_path"].tolist() + versions["email_path"].tolist() if r]
            z = make_zip(refs)
            st.download_button("⬇️ Download documents.zip", z, "documents.zip")


def page_deleted(con, user):
    st.subheader("Deleted Versions")
    df = pd.read_sql("SELECT * FROM documents WHERE is_deleted=1", con)
    if df.empty:
        empty_state("No deleted items", "When you delete versions, they show up here for restore.")
        return
    st.dataframe(df[["id", "doc_type", "name", "version", "uploaded_by", "remarks"]], use_container_width=True)
    if user["role"] != "admin":
        return
    sel = st.selectbox("Restore ID", df["id"], key="docs_restore_id")
    if st.button("Restore", key="docs_restore_btn"):
        con.execute("UPDATE documents SET is_deleted=0 WHERE id=?", (sel,))
        con.commit()
        insert_audit(con, user["username"], "RESTORE", sel, f"Restored id={sel}")
        backup_db_to_dropbox()
        st.toast("Restored")
        st.rerun()


# -------------------- CONTRACTS PAGE --------------------

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
                start  = st.date_input("Start date *", dt.date.today())
                end    = st.date_input("End date *", dt.date.today())
                renewal = st.number_input("Renewal notice (days)", min_value=0, value=60, step=5)
            remarks = st.text_area("Remarks / Context *", height=100)
            doc  = st.file_uploader("Contract file (PDF/Doc) *")
            email = st.file_uploader("Approval/email attachment (optional)")
            ok = st.form_submit_button("Upload contract")

        if ok:
            if not name or not vendor or not doc or not remarks.strip():
                st.error("Please fill Contract Name, Vendor, Contract file, and Remarks."); return
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
                         details=f"{vendor}/{name} v{version}; status={status}; start={start}; end={end}; remarks='{remarks.strip()}'")
            backup_db_to_dropbox()
            st.toast(f"Contract uploaded as version {version}")

    st.markdown("---")
    df = pd.read_sql("SELECT * FROM contracts WHERE is_deleted=0", con)
    if df.empty:
        empty_state("No contracts yet", "Add your first contract above.")
        return

    df["days_to_expiry"] = _days_to_expiry(df["end_date"])

    c1, c2, c3, c4 = st.columns(4)
    with c1:
        v_q = st.text_input("Search vendor", key="contracts_filter_vendor")
    with c2:
        o_q = st.text_input("Search owner", key="contracts_filter_owner")
    with c3:
        s_q = st.selectbox("Status", ["All", "Active", "Under review", "Expired"], key="contracts_filter_status")
    with c4:
        exp_days = st.selectbox("Expiring in", ["All", 30, 60, 90], key="contracts_filter_exp")

    f = df.copy()
    if v_q:
        f = f[f["vendor"].str.contains(v_q, case=False, na=False)]
    if o_q:
        f = f[f["owner"].str.contains(o_q, case=False, na=False)]
    if s_q != "All":
        f = f[f["status"] == s_q]
    if exp_days != "All":
        f = f[(f["days_to_expiry"] >= 0) & (f["days_to_expiry"] <= int(exp_days))]

    if f.empty:
        empty_state("No matching contracts", "Try changing the filters above.")
        return

    f["version"] = pd.to_numeric(f["version"], errors="coerce").fillna(0).astype(int)
    latest_flags = f.groupby(["vendor", "name"]) ["version"].transform("max")
    f["is_latest"] = f["version"] == latest_flags

    # Visual status chips
    status_chip = f["status"].map({
        "Active": "<span class='chip ok'>● Active</span>",
        "Under review": "<span class='chip warn'>● Under review</span>",
        "Expired": "<span class='chip bad'>● Expired</span>",
    })
    f = f.assign(status_chip=status_chip)

    st.dataframe(
        f[["vendor","name","status_chip","start_date","end_date","days_to_expiry",
           "version","is_latest","uploaded_by","remarks"]] \
          .rename(columns={"status_chip":"status"}),
        use_container_width=True,
    )

    st.markdown("### Open a contract group")
    groups = f.drop_duplicates(subset=["vendor","name"])    
    labels = [f"{r.vendor} — {r.name}" for r in groups.itertuples()]
    if labels:
        pick = st.selectbox("Select contract", labels, key="contracts_group_pick")
        if pick:
            sel_group = groups.iloc[labels.index(pick)]
            versions = f[(f["vendor"] == sel_group["vendor"]) & (f["name"] == sel_group["name"])].sort_values("version", ascending=False)
            # Need the raw table again for refs
            raw_versions = pd.read_sql(
                "SELECT * FROM contracts WHERE vendor=? AND name=? AND is_deleted=0 ORDER BY version DESC",
                con, params=(sel_group["vendor"], sel_group["name"])
            )
            v_table = versions_with_links_contracts(con, raw_versions)
            v_show = v_table[["version","upload_date","uploaded_by","status",
                              "start_date","end_date","remarks","View (doc)","View (email)"]]
            st.data_editor(
                v_show, use_container_width=True, disabled=True,
                key=f"contracts_versions_{sel_group['vendor']}_{sel_group['name']}",
                column_config={
                    "View (doc)": st.column_config.LinkColumn("View (doc)"),
                    "View (email)": st.column_config.LinkColumn("View (email)")
                }
            )
            if st.button("Download all versions (zip)"):
                refs = [r for r in raw_versions["file_path"].tolist() + raw_versions["email_path"].tolist() if r]
                z = make_zip(refs)
                st.download_button("⬇️ Download contracts.zip", z, "contracts.zip")


def page_audit(con, user=None):
    st.subheader("Audit Log")
    df = pd.read_sql("SELECT * FROM audit_log ORDER BY ts DESC", con)
    if df.empty:
        empty_state("No logs yet", "Actions will show up here as you use the portal.")
        return
    st.download_button("⬇️ Export CSV", df.to_csv(index=False).encode(), "audit.csv")
    buf = BytesIO(); df.to_excel(buf, index=False)
    st.download_button("⬇️ Export Excel", buf.getvalue(), "audit.xlsx")
    st.dataframe(df, use_container_width=True)


def page_manage_users(con, user):
    if user["role"] != "admin":
        st.error("Access denied"); return

    st.subheader("Manage Users")
    with st.form("add_user", clear_on_submit=True):
        email = st.text_input("User Email")
        pwd = st.text_input("Password", type="password")
        role = st.selectbox("Role", ["admin", "editor", "viewer"])
        ok = st.form_submit_button("Add User")
    if ok:
        if not email or not pwd:
            st.error("Email and Password are required.")
        else:
            try:
                con.execute(
                    "INSERT INTO users (email,password_sha256,role,created_date) VALUES (?,?,?,?)",
                    (email.strip().lower(), _hash(pwd), role, dt.datetime.utcnow().isoformat()),
                )
                con.commit()
                insert_audit(con, user["username"], "ADD_USER", details=f"{email.strip().lower()} as {role}")
                backup_db_to_dropbox()
                st.toast("User added")
            except sqlite3.IntegrityError:
                st.error("User already exists")

    df = pd.read_sql("SELECT id,email,role,created_date FROM users ORDER BY id DESC", con)
    st.dataframe(df, use_container_width=True)

    if not df.empty:
        del_id = st.selectbox("Delete user ID", df["id"])    
        if st.button("Delete User"):
            target_email = df[df["id"] == del_id]["email"].iloc[0]
            if target_email == user["username"]:
                st.error("You cannot delete yourself.")
            else:
                con.execute("DELETE FROM users WHERE id=?", (del_id,))
                con.commit()
                insert_audit(con, user["username"], "DELETE_USER", details=str(target_email))
                backup_db_to_dropbox()
                st.toast("User deleted")
                st.rerun()


# ===================================================================
#                         LOGIN UI (refreshed)
# ===================================================================

def style_login():
    st.markdown(
        """
        <style>
          header[data-testid="stHeader"] { display:none !important; }
          #MainMenu, .stDeployButton, footer { visibility:hidden; }
        </style>
        """,
        unsafe_allow_html=True,
    )


def login_view():
    style_login()
    st.markdown("<div class='login-wrap'>", unsafe_allow_html=True)
    with st.container():
        st.markdown(
            """
            <div class="login-card">
              <div class="brand">HR</div>
              <h2 style="margin:.6rem 0 0;">HR Document Portal</h2>
              <p style="color:#6b7280; margin-top:.1rem;">Sign in to manage SOPs, Policies, and Contracts</p>
            </div>
            """,
            unsafe_allow_html=True,
        )
    st.markdown("</div>", unsafe_allow_html=True)
    # Actual form
    with st.form("login_form", clear_on_submit=False):
        u = st.text_input("Email", key="login_email")
        p = st.text_input("Password", type="password", key="login_pwd")
        keep = st.checkbox("Keep me signed in on this device", value=True)
        submitted = st.form_submit_button("Login", use_container_width=True)
    return submitted, u, p, keep


# ===================================================================
#                                MAIN
# ===================================================================

def main():
    st.set_page_config(APP_TITLE, layout="wide", page_icon="📄")
    inject_global_styles()

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
        # Header + Navbar
        current = app_header(user)
        if current == "__logout__":
            tok = st.query_params.get("auth", None)
            if tok:
                delete_auth_token(con, tok)
            if "auth" in st.query_params:
                del st.query_params["auth"]
            insert_audit(con, user["username"], "LOGOUT")
            st.session_state.pop("user")
            st.rerun()

        # Floating quick action
        if user["role"] in {"admin", "editor"} and current not in ("Upload",):
            st.markdown("""
                <a class='fab' href='?page=Upload'>+ Upload</a>
            """, unsafe_allow_html=True)

        # Route
        if current == "Documents":
            page_documents(con, user)
        elif current == "Upload":
            page_upload(con, user)
        elif current == "Contracts":
            page_contracts(con, user)
        elif current == "Deleted":
            page_deleted(con, user)
        elif current == "Audit":
            page_audit(con)
        elif current == "Manage Users":
            page_manage_users(con, user)


if __name__ == "__main__":
    main()
