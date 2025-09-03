# app.py
# ------------------------------------------------------------------
# HR Document Portal — Streamlit + Dropbox/local persistence
# Admin-managed users + mandatory remarks + full audit logging
# Polished UI (blue/white), header bar, styled tabs/buttons/cards
# ------------------------------------------------------------------

import base64, hashlib, datetime as dt, sqlite3, mimetypes, secrets, zipfile
from pathlib import Path
from io import BytesIO
import pandas as pd
import streamlit as st

# ------------- Branding / Title
APP_TITLE = "HR Document Portal"
UPLOAD_TAB = "Documents Upload"   # UI label (safe rename)

# ------------- Local fallback storage
LOCAL_STORAGE_DIR = Path("storage/HR_Documents_Portal")
LOCAL_DB_PATH = Path("storage/hr_docs.db")
LOCAL_STORAGE_DIR.mkdir(parents=True, exist_ok=True)
LOCAL_DB_PATH.parent.mkdir(parents=True, exist_ok=True)

# ===================================================================
#                         LIGHTWEIGHT DESIGN
# ===================================================================
def inject_css():
    st.markdown("""
    <style>
      .block-container { padding-top: 1.0rem; }

      /* Tabs */
      .stTabs [data-baseweb="tab-list"] { gap: 10px; }
      .stTabs [data-baseweb="tab"] {
        background: #F2F6FF;
        color: #0B2545;
        border-radius: 10px 10px 0 0;
        padding: 8px 14px;
        font-weight: 600;
        border: 1px solid #E5EDFF;
        border-bottom: 2px solid transparent;
      }
      .stTabs [aria-selected="true"] {
        background: #FFFFFF !important;
        color: #0056B3 !important;
        border-bottom: 2px solid #FF4B4B;
      }

      /* Buttons */
      .stButton>button {
        background:#0056B3; color:#fff; border:0; border-radius:10px;
        padding:10px 16px; font-weight:600;
      }
      .stButton>button:hover { filter:brightness(0.95); }

      /* Inputs */
      .stTextInput>div>div>input, .stSelectbox div[data-baseweb="select"]>div {
        border-radius: 10px;
      }

      /* Cards */
      .hr-card {
        background:#fff; border:1px solid #EEF2FF; border-radius:14px;
        padding:18px; box-shadow:0 6px 18px rgba(0,0,0,.04);
      }

      /* Small status pills */
      .pill { display:inline-block; padding:3px 10px; border-radius:999px;
              font-size:12px; font-weight:700; }
      .pill-green { background:#E8FFF2; color:#0A6F3C; }
      .pill-amber { background:#FFF8E6; color:#8A5B00; }
      .pill-red   { background:#FFECEC; color:#9C1C1C; }
    </style>
    """, unsafe_allow_html=True)

def render_topbar(user_email: str | None = None, logo_path: str | None = "C24-logo.png"):
    with st.container():
        c1, c2, c3 = st.columns([1, 6, 2], vertical_alignment="center")
        if logo_path:
            try:
                c1.image(logo_path, use_container_width=True)
            except Exception:
                c1.write("")
        c2.markdown(
            "<h2 style='margin:0; color:#0B2545;'>HR Document Portal</h2>",
            unsafe_allow_html=True
        )
        if user_email:
            c3.markdown(
                f"<div style='text-align:right;'><span class='pill pill-green'>Signed in</span>"
                f"<div style='font-size:12px;color:#64748B;'>{user_email}</div></div>",
                unsafe_allow_html=True
            )
        else:
            c3.markdown(
                "<div style='text-align:right; color:#94A3B8; font-size:12px;'>© 2025 CARS24 HR</div>",
                unsafe_allow_html=True
            )

def expiry_badge(days: int | float | None) -> str:
    try:
        d = int(days)
    except Exception:
        return ""
    if d < 0:
        return "❌ expired"
    if d <= 30:
        return "⚠️ due ≤30d"
    if d <= 60:
        return "🟡 due ≤60d"
    return "✅ ok"

# ===================================================================
#                        DROPBOX CONFIG
# ===================================================================
USE_DROPBOX = False
dbx = None

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
        DBX_TOKEN = st.secrets["DROPBOX_ACCESS_TOKEN"].strip()
        dbx = dropbox.Dropbox(DBX_TOKEN)
        USE_DROPBOX = True
    else:
        st.warning("No Dropbox credentials found, using local storage only.")
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

# Convenience wrappers (Dropbox or Local)
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
def _hash(pw): 
    return hashlib.sha256(pw.encode()).hexdigest()

def init_db():
    """On Cloud: pull latest DB from Dropbox into local file, then open."""
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
        """
    )

    # Bootstrap admin
    cur.execute("SELECT COUNT(*) FROM users WHERE role='admin'")
    if cur.fetchone()[0] == 0:
        default_admin = st.secrets.get("DEFAULT_ADMIN_EMAIL", "admin@cars24.com").lower()
        default_pwd = st.secrets.get("DEFAULT_ADMIN_PASSWORD", "admin123")
        cur.execute(
            "INSERT OR IGNORE INTO users (email,password_sha256,role,created_date) VALUES (?,?,?,?)",
            (default_admin, _hash(default_pwd), "admin", dt.datetime.utcnow().isoformat()),
        )
        con.commit()

    # Safe migration for remarks
    try:
        cur.execute("ALTER TABLE documents ADD COLUMN remarks TEXT")
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
#                               SERVE MODE
# ===================================================================
if "serve" in st.query_params:
    token = st.query_params["serve"]
    con = init_db()
    cur = con.execute("SELECT id,file_path,email_path,file_token,email_token FROM documents")
    target_ref = None
    for rid, fp, ep, ft, et in cur.fetchall():
        if token == ft: target_ref = fp
        if token == et: target_ref = ep
    if not target_ref or not ref_exists(target_ref):
        st.error("File not found"); st.stop()
    data = read_ref_bytes(target_ref)
    name = to_display_name(target_ref)
    mime, _ = mimetypes.guess_type(name)

    render_topbar(None)
    st.markdown(f"### {name}")
    if name.lower().endswith(".pdf") and data and len(data) < 15_000_000:
        b64 = base64.b64encode(data).decode()
        st.markdown(
            f'<iframe src="data:application/pdf;base64,{b64}" width="100%" height="700"></iframe>',
            unsafe_allow_html=True
        )
    elif name.lower().endswith((".png", ".jpg", ".jpeg")) and data:
        st.image(data, use_container_width=True)
    elif name.lower().endswith(".txt") and data:
        st.text(data.decode(errors="replace")[:5000])
    else:
        st.info("Preview not supported inline. Use Download below.")
    st.download_button("⬇️ Download", data, name, mime or "application/octet-stream", key="serve_dl")
    st.stop()

# ===================================================================
#                               PAGES
# ===================================================================
def page_upload(con, user):
    if user["role"] not in {"admin", "editor"}:
        st.info("You have viewer access — uploads are disabled.")
        return

    st.subheader("Documents Upload")
    st.markdown("<div class='hr-card'>", unsafe_allow_html=True)
    with st.form("upf", clear_on_submit=True):
        doc_type = st.selectbox("Document Type", ["SOP", "BRD", "Policy", "Contract"])
        name = st.text_input("Name")
        created_date = st.date_input("Created", dt.date.today())
        approved_by = st.text_input("Approved by")
        remarks = st.text_area("Remarks / Context *", help="Explain the context or purpose of this upload", height=100)
        doc = st.file_uploader("Key Document *")
        email = st.file_uploader("Approval/email attachment (optional)")
        ok = st.form_submit_button("Upload")

    st.markdown("</div>", unsafe_allow_html=True)

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
        insert_audit(con, user["username"], "UPLOAD", details=f"Uploaded {doc_type}/{name} v{version}; approved_by='{approved_by}'; remarks='{remarks.strip()}'")
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
    st.markdown("<div class='hr-card'>", unsafe_allow_html=True)

    if df.empty:
        st.info("No documents available")
        st.markdown("</div>", unsafe_allow_html=True)
        return

    col1, col2, col3 = st.columns(3)
    with col1: t = st.selectbox("Type", ["All"] + sorted(df["doc_type"].dropna().unique().tolist()))
    with col2: name_q = st.text_input("Search name")
    with col3: appr_q = st.text_input("Approved by")

    f = df.copy()
    if t != "All": f = f[f["doc_type"] == t]
    if name_q:     f = f[f["name"].str.contains(name_q, case=False, na=False)]
    if appr_q:     f = f[f["approved_by"].str.contains(appr_q, case=False, na=False)]

    if f.empty:
        st.info("No matching documents")
        st.markdown("</div>", unsafe_allow_html=True)
        return

    f["version"] = f["version"].astype(int)
    latest_flags = f.groupby(["doc_type", "name"])["version"].transform("max")
    f["is_latest"] = f["version"] == latest_flags

    st.dataframe(
        f[["doc_type", "name", "version", "is_latest", "created_date", "upload_date", "approved_by", "uploaded_by", "remarks"]],
        use_container_width=True
    )
    st.markdown("</div>", unsafe_allow_html=True)

    st.markdown("---")
    st.markdown("### Open a document group")
    groups = f.drop_duplicates(subset=["doc_type", "name"])
    labels = [f"{r.doc_type} — {r.name}" for r in groups.itertuples()]
    if not labels: return
    pick = st.selectbox("Select document", labels, key="doc_pick")
    if not pick: return
    sel_group = groups.iloc[labels.index(pick)]
    versions = f[(f["doc_type"] == sel_group["doc_type"]) & (f["name"] == sel_group["name"])]\
        .sort_values("version", ascending=False)
    v_table = versions_with_links(con, versions)
    v_show = v_table[["version", "upload_date", "uploaded_by", "approved_by", "is_latest", "remarks", "View (doc)", "View (email)"]]
    st.data_editor(
        v_show, use_container_width=True, disabled=True, key=f"versions_{sel_group['name']}",
        column_config={
            "View (doc)": st.column_config.LinkColumn("View (doc)"),
            "View (email)": st.column_config.LinkColumn("View (email)")
        }
    )

def page_deleted(con, user):
    st.subheader("Deleted Versions")
    df = pd.read_sql("SELECT * FROM documents WHERE is_deleted=1", con)
    st.markdown("<div class='hr-card'>", unsafe_allow_html=True)
    if df.empty:
        st.info("None")
        st.markdown("</div>", unsafe_allow_html=True)
        return
    st.dataframe(df[["id", "doc_type", "name", "version", "uploaded_by", "remarks"]], use_container_width=True)
    st.markdown("</div>", unsafe_allow_html=True)
    if user["role"] != "admin":
        return
    sel = st.selectbox("Restore ID", df["id"])
    if st.button("Restore"):
        con.execute("UPDATE documents SET is_deleted=0 WHERE id=?", (sel,))
        con.commit()
        insert_audit(con, user["username"], "RESTORE", sel, f"Restored id={sel}")
        backup_db_to_dropbox()
        st.success("Restored"); st.rerun()

def page_audit(con, user=None):
    st.subheader("Audit Log")
    df = pd.read_sql("SELECT * FROM audit_log ORDER BY ts DESC", con)
    st.markdown("<div class='hr-card'>", unsafe_allow_html=True)
    if df.empty:
        st.info("No logs")
        st.markdown("</div>", unsafe_allow_html=True)
        return
    st.download_button("⬇️ Export CSV", df.to_csv(index=False).encode(), "audit.csv", key="audit_csv")
    buf = BytesIO(); df.to_excel(buf, index=False)
    st.download_button("⬇️ Export Excel", buf.getvalue(), "audit.xlsx", key="audit_xlsx")
    st.dataframe(df, use_container_width=True)
    st.markdown("</div>", unsafe_allow_html=True)

def page_manage_users(con, user):
    if user["role"] != "admin":
        st.error("Access denied"); return

    st.subheader("Manage Users")
    st.markdown("<div class='hr-card'>", unsafe_allow_html=True)

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
                st.success(f"User {email} added as {role}")
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
                st.success("User deleted"); st.rerun()

    st.markdown("</div>", unsafe_allow_html=True)

def page_contracts(con, user):
    """Design-friendly contracts page. If table doesn't exist yet, show a note."""
    st.subheader("Contracts")
    st.markdown("<div class='hr-card'>", unsafe_allow_html=True)
    cur = con.cursor()
    cur.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='contracts'")
    if not cur.fetchone():
        st.info("Contracts table not found yet. Once contracts module is enabled, uploads will appear here.")
        st.markdown("</div>", unsafe_allow_html=True)
        return

    df = pd.read_sql("SELECT * FROM contracts WHERE is_deleted=0", con)
    if df.empty:
        st.info("No contracts yet.")
        st.markdown("</div>", unsafe_allow_html=True)
        return

    # Parse dates safely and add badge
    today = pd.Timestamp.today().normalize()
    for col in ["start_date", "end_date"]:
        if col in df.columns:
            df[col] = pd.to_datetime(df[col], errors="coerce")
    if "end_date" in df.columns:
        df["days_to_expiry"] = (df["end_date"] - today).dt.days
        df["Expiry"] = df["days_to_expiry"].apply(expiry_badge)

    cols = [c for c in ["vendor", "name", "status", "start_date", "end_date", "Expiry",
                        "version", "uploaded_by", "remarks"] if c in df.columns]
    st.dataframe(df[cols], use_container_width=True)
    st.markdown("</div>", unsafe_allow_html=True)

# ===================================================================
#                                MAIN
# ===================================================================
def main():
    st.set_page_config(APP_TITLE, layout="wide")
    inject_css()

    con = st.session_state.get("con") or init_db()
    st.session_state["con"] = con

    user = st.session_state.get("user")
    if not user:
        render_topbar(None)
        st.caption("Use your portal credentials. Need access? Contact HR IT.")
        u = st.text_input("Email", key="login_email")
        p = st.text_input("Password", type="password", key="login_pwd")
        if st.button("Login", key="login_btn"):
            auth = authenticate(u, p, con)
            if auth:
                st.session_state["user"] = auth
                insert_audit(con, u, "LOGIN")
                st.rerun()
            else:
                st.error("Invalid credentials")
                return
    else:
        render_topbar(user['username'])
        st.sidebar.write(f"Signed in as {user['username']} ({user['role']})")
        if st.sidebar.button("Logout"):
            insert_audit(con, user["username"], "LOGOUT")
            st.session_state.pop("user")
            st.rerun()

        tabs = ["Documents", UPLOAD_TAB, "Contracts"]
        if user["role"] == "viewer":
            tabs = ["Documents", "Contracts"]
        if user["role"] == "admin":
            tabs += ["Deleted", "Audit", "Manage Users"]

        t = st.tabs(tabs)
        with t[0]:
            page_documents(con, user)
        if UPLOAD_TAB in tabs:
            with t[tabs.index(UPLOAD_TAB)]:
                page_upload(con, user)
        if "Contracts" in tabs:
            with t[tabs.index("Contracts")]:
                page_contracts(con, user)
        if "Deleted" in tabs:
            with t[tabs.index("Deleted")]:
                page_deleted(con, user)
        if "Audit" in tabs:
            with t[tabs.index("Audit")]:
                page_audit(con)
        if "Manage Users" in tabs:
            with t[tabs.index("Manage Users")]:
                page_manage_users(con, user)

if __name__ == "__main__":
    main()
