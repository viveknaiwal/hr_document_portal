# app.py
# ------------------------------------------------------------------
# HR Document Portal — Streamlit + (optional) Dropbox persistence
# Admin-managed users + mandatory remarks + full audit logging
# Adds: Contract Management (upload, browse, versioning, audit)
# ------------------------------------------------------------------

import base64, hashlib, datetime as dt, sqlite3, mimetypes, secrets, zipfile
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
        # ⚠️ Fallback (short-lived)
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

        CREATE TABLE IF NOT EXISTS contracts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT,
            vendor TEXT,
            owner TEXT,
            status TEXT,
            start_date TEXT,
            end_date TEXT,
            value TEXT,
            renewal_notice_days INTEGER,
            auto_renew INTEGER DEFAULT 0,
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
        """
    )

    # Bootstrap: ensure at least one admin user exists
    cur.execute("SELECT COUNT(*) FROM users WHERE role='admin'")
    if cur.fetchone()[0] == 0:
        default_admin = st.secrets.get("DEFAULT_ADMIN_EMAIL", "admin@cars24.com").lower()
        default_pwd = st.secrets.get("DEFAULT_ADMIN_PASSWORD", "admin123")
        cur.execute(
            "INSERT OR IGNORE INTO users (email,password_sha256,role,created_date) VALUES (?,?,?,?)",
            (default_admin, _hash(default_pwd), "admin", dt.datetime.utcnow().isoformat()),
        )
        con.commit()

    # Safe migrations for old DBs (if they existed before these fields)
    try: cur.execute("ALTER TABLE documents ADD COLUMN remarks TEXT")
    except sqlite3.OperationalError: pass
    try: cur.execute("ALTER TABLE contracts ADD COLUMN remarks TEXT")
    except sqlite3.OperationalError: pass
    try: cur.execute("ALTER TABLE contracts ADD COLUMN value TEXT")
    except sqlite3.OperationalError: pass
    try: cur.execute("ALTER TABLE contracts ADD COLUMN renewal_notice_days INTEGER")
    except sqlite3.OperationalError: pass
    try: cur.execute("ALTER TABLE contracts ADD COLUMN auto_renew INTEGER DEFAULT 0")
    except sqlite3.OperationalError: pass

    con.commit()
    return con

def backup_db_to_dropbox():
    """Push the local sqlite DB to Dropbox after writes."""
    if USE_DROPBOX and LOCAL_DB_PATH.exists():
        dbx_upload_bytes(dbx_path("db", "hr_docs.db"), LOCAL_DB_PATH.read_bytes())

def insert_audit(con, actor, action, doc_id=None, details=""):
    con.execute(
        "INSERT INTO audit_log(ts,actor,action,doc_id,details) VALUES (?,?,?,?,?)",
        (dt.datetime.utcnow().isoformat(), actor, action, doc_id, details),
    )
    con.commit()
    backup_db_to_dropbox()

# Authentication using DB users
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

def ensure_tokens_generic(con, table, row_id, email_exists):
    cur = con.execute(f"SELECT file_token,email_token FROM {table} WHERE id=?", (row_id,))
    row = cur.fetchone()
    if not row:
        return None, None
    ft, et = row
    changed = False
    if not ft:
        ft = gen_token()
        con.execute(f"UPDATE {table} SET file_token=? WHERE id=?", (ft, row_id))
        changed = True
    if email_exists and not et:
        et = gen_token()
        con.execute(f"UPDATE {table} SET email_token=? WHERE id=?", (et, row_id))
        changed = True
    if changed:
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

    target_ref = None

    # search documents
    cur = con.execute("SELECT file_path,email_path,file_token,email_token FROM documents WHERE is_deleted=0")
    for fp, ep, ft, et in cur.fetchall():
        if token == ft: target_ref = fp
        if token == et: target_ref = ep

    # search contracts
    if not target_ref:
        cur2 = con.execute("SELECT file_path,email_path,file_token,email_token FROM contracts WHERE is_deleted=0")
        for fp, ep, ft, et in cur2.fetchall():
            if token == ft: target_ref = fp
            if token == et: target_ref = ep

    if not target_ref or not ref_exists(target_ref):
        st.error("File not found"); st.stop()
    data = read_ref_bytes(target_ref)
    name = to_display_name(target_ref)
    mime, _ = mimetypes.guess_type(name)
    st.markdown(f"### {name}")
    if name.lower().endswith(".pdf") and data and len(data) < 15_000_000:
        b64 = base64.b64encode(data).decode()
        st.markdown(f'<iframe src="data:application/pdf;base64,{b64}" width="100%" height="700"></iframe>',
                    unsafe_allow_html=True)
    elif name.lower().endswith((".png", ".jpg", ".jpeg")) and data:
        st.image(data, use_container_width=True)
    elif name.lower().endswith(".txt") and data:
        st.text(data.decode(errors="replace")[:5000])
    else:
        st.info("Preview not supported inline. Use Download below.")
    st.download_button("⬇️ Download", data, name, mime or "application/octet-stream")
    st.stop()

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
        remarks = st.text_area("Remarks / Context *", help="Explain the context or purpose of this upload", height=100)
        doc = st.file_uploader("Key Document *")
        email = st.file_uploader("Approval/email attachment (optional)")
        ok = st.form_submit_button("Upload")

    if ok:
        # Validate mandatory fields
        if not name or not doc or not remarks.strip():
            st.error("Please provide Name, Key Document, and Remarks / Context."); 
            return

        data = doc.read()

        # Compute next version
        cur = con.execute("SELECT MAX(version) FROM documents WHERE name=? AND doc_type=?", (name, doc_type))
        maxv = cur.fetchone()[0]
        version = (maxv + 1) if maxv else 1

        # Save files
        file_ref = write_bytes_return_ref(data, doc_type=doc_type, name=name, version=version, filename=doc.name)
        email_ref = ""
        if email:
            email_ref = write_bytes_return_ref(email.read(), doc_type=doc_type, name=name, version=version,
                                               filename="email_" + email.name)

        # Tokens for serving
        ft, et = gen_token(), (gen_token() if email_ref else None)

        # Insert into DB
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
        # Audit includes context
        details = f"Uploaded {doc_type}/{name} v{version}; approved_by='{approved_by}'; remarks='{remarks.strip()}'"
        insert_audit(con, user["username"], "UPLOAD", details=details)
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
        f[["doc_type", "name", "version", "is_latest", "created_date", "upload_date", "approved_by", "uploaded_by", "remarks"]],
        use_container_width=True
    )

    # Optional: quick open one group
    st.markdown("---")
    st.markdown("### Open a document group")
    groups = f.drop_duplicates(subset=["doc_type", "name"])
    labels = [f"{r.doc_type} — {r.name}" for r in groups.itertuples()]
    if not labels:
        return
    pick = st.selectbox("Select document", labels)
    if not pick: return
    sel_group = groups.iloc[labels.index(pick)]
    versions = f[(f["doc_type"] == sel_group["doc_type"]) & (f["name"] == sel_group["name"])]\
        .sort_values("version", ascending=False)
    v_table = versions_with_links(con, versions)
    v_show = v_table[["version", "upload_date", "uploaded_by", "approved_by", "is_latest", "remarks", "View (doc)", "View (email)"]]
    st.data_editor(
        v_show, use_container_width=True, disabled=True,
        column_config={
            "View (doc)": st.column_config.LinkColumn("View (doc)"),
            "View (email)": st.column_config.LinkColumn("View (email)")
        }
    )

    # Delete selected version (admin only)
    if user["role"] == "admin":
        choice = st.selectbox("Select version to delete", [f"v{r.version}" for r in versions.itertuples()])
        sel = versions.iloc[[f"v{r.version}" for r in versions.itertuples()].index(choice)]
        if st.button("Delete this version"):
            con.execute("UPDATE documents SET is_deleted=1 WHERE id=?", (int(sel["id"]),))
            con.commit()
            insert_audit(con, user["username"], "DELETE", sel["id"], f"Deleted {sel['doc_type']}/{sel['name']} v{sel['version']}")
            backup_db_to_dropbox()
            st.success("Deleted"); st.rerun()

def page_deleted(con, user):
    st.subheader("Deleted Versions")
    df = pd.read_sql("SELECT * FROM documents WHERE is_deleted=1", con)
    if df.empty:
        st.info("None"); return
    st.dataframe(df[["id", "doc_type", "name", "version", "uploaded_by", "remarks"]], use_container_width=True)
    if user["role"] != "admin":
        return
    sel = st.selectbox("Restore ID", df["id"])
    if st.button("Restore"):
        con.execute("UPDATE documents SET is_deleted=0 WHERE id=?", (sel,))
        con.commit()
        insert_audit(con, user["username"], "RESTORE", sel, f"Restored id={sel}")
        backup_db_to_dropbox()
        st.success("Restored"); st.rerun()

# -------------------- CONTRACTS --------------------
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

def page_contracts(con, user):
    st.subheader("Contract Management")

    # Upload
    can_upload = user["role"] in {"admin", "editor"}
    if can_upload:
        with st.form("contract_form", clear_on_submit=True):
            c1, c2 = st.columns(2)
            with c1:
                name   = st.text_input("Contract Name *")
                vendor = st.text_input("Vendor *")
                owner  = st.text_input("Internal Owner / POC")
                status = st.selectbox("Status", ["Active", "Under review", "Terminated", "Expired"])
                value  = st.text_input("Value / Amount")
            with c2:
                start  = st.date_input("Start date *", dt.date.today())
                end    = st.date_input("End date *", dt.date.today())
                renewal = st.number_input("Renewal notice (days)", min_value=0, value=60, step=5)
                auto    = st.checkbox("Auto-renew")
            remarks = st.text_area("Remarks / Context *", height=100)
            doc  = st.file_uploader("Contract file (PDF/Doc) *")
            email = st.file_uploader("Approval/email attachment (optional)")
            ok = st.form_submit_button("Upload contract")

        if ok:
            if not name or not vendor or not doc or not remarks.strip():
                st.error("Please fill Contract Name, Vendor, Contract file, and Remarks."); return
            data = doc.read()

            # version by (name + vendor)
            cur = con.execute("SELECT MAX(version) FROM contracts WHERE name=? AND vendor=?", (name, vendor))
            maxv = cur.fetchone()[0]
            version = (maxv + 1) if maxv else 1

            # save files (folder 'Contract/<name>/vX')
            file_ref = write_bytes_return_ref(data, doc_type="Contract", name=name, version=version, filename=doc.name)
            email_ref = ""
            if email:
                email_ref = write_bytes_return_ref(email.read(), doc_type="Contract", name=name, version=version,
                                                   filename="email_" + email.name)

            ft, et = gen_token(), (gen_token() if email_ref else None)

            con.execute(
                """INSERT INTO contracts
                   (name,vendor,owner,status,start_date,end_date,value,renewal_notice_days,auto_renew,
                    created_date,upload_date,uploaded_by,file_path,email_path,version,hash_sha256,
                    is_deleted,file_token,email_token,remarks)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,0,?,?,?)""",
                (name, vendor, owner, status, str(start), str(end), value, int(renewal), int(auto),
                 str(start), dt.datetime.utcnow().isoformat(), user["username"],
                 file_ref, email_ref, version, sha256_bytes(data), ft, et, remarks.strip())
            )
            con.commit()
            insert_audit(con, user["username"], "CONTRACT_UPLOAD",
                         details=f"{vendor}/{name} v{version}; status={status}; start={start}; end={end}; auto_renew={bool(auto)}; remarks='{remarks.strip()}'")
            backup_db_to_dropbox()
            st.success(f"Contract uploaded as version {version}")

    # Browse / filter
    st.markdown("---")
    df = pd.read_sql("SELECT * FROM contracts WHERE is_deleted=0", con)
    if df.empty:
        st.info("No contracts yet."); return

    today = dt.date.today()
    end_dt = pd.to_datetime(df["end_date"], errors="coerce")
    df["days_to_expiry"] = (end_dt.dt.date - today).dt.days

    c1, c2, c3, c4 = st.columns(4)
    with c1: v_q = st.text_input("Search vendor")
    with c2: o_q = st.text_input("Search owner")
    with c3: s_q = st.selectbox("Status", ["All", "Active", "Under review", "Terminated", "Expired"])
    with c4: exp_days = st.selectbox("Expiring in", ["All", 30, 60, 90])

    f = df.copy()
    if v_q: f = f[f["vendor"].str.contains(v_q, case=False, na=False)]
    if o_q: f = f[f["owner"].str.contains(o_q, case=False, na=False)]
    if s_q != "All": f = f[f["status"] == s_q]
    if exp_days != "All": f = f[(f["days_to_expiry"] >= 0) & (f["days_to_expiry"] <= int(exp_days))]

    if f.empty:
        st.info("No matching contracts"); return

    f["version"] = f["version"].astype(int)
    latest_flags = f.groupby(["vendor", "name"])["version"].transform("max")
    f["is_latest"] = f["version"] == latest_flags

    st.dataframe(
        f[["vendor","name","status","start_date","end_date","days_to_expiry","version","is_latest","uploaded_by","remarks"]],
        use_container_width=True
    )

    # Open a contract group
    st.markdown("### Open a contract group")
    groups = f.drop_duplicates(subset=["vendor","name"])
    labels = [f"{r.vendor} — {r.name}" for r in groups.itertuples()]
    if labels:
        pick = st.selectbox("Select contract", labels)
        if pick:
            sel_group = groups.iloc[labels.index(pick)]
            versions = f[(f["vendor"] == sel_group["vendor"]) & (f["name"] == sel_group["name"])]\
                .sort_values("version", ascending=False)
            v_table = versions_with_links_contracts(con, versions)
            v_show = v_table[["version","upload_date","uploaded_by","status","start_date","end_date","remarks","View (doc)","View (email)"]]
            st.data_editor(
                v_show, use_container_width=True, disabled=True,
                column_config={
                    "View (doc)": st.column_config.LinkColumn("View (doc)"),
                    "View (email)": st.column_config.LinkColumn("View (email)")
                }
            )

            # Delete (admin only)
            if user["role"] == "admin":
                choice = st.selectbox("Select version to delete", [f"v{r.version}" for r in versions.itertuples()])
                sel = versions.iloc[[f"v{r.version}" for r in versions.itertuples()].index(choice)]
                if st.button("Delete this version"):
                    con.execute("UPDATE contracts SET is_deleted=1 WHERE id=?", (int(sel["id"]),))
                    con.commit()
                    insert_audit(con, user["username"], "CONTRACT_DELETE", sel["id"],
                                 f"Deleted {sel['vendor']}/{sel['name']} v{sel['version']}")
                    backup_db_to_dropbox()
                    st.success("Deleted"); st.rerun()

    # Deleted contracts (admin) inside an expander
    st.markdown("---")
    with st.expander("Deleted contract versions (admin)"):
        if user["role"] == "admin":
            d = pd.read_sql("SELECT * FROM contracts WHERE is_deleted=1", con)
            if d.empty:
                st.info("None")
            else:
                st.dataframe(d[["id","vendor","name","version","uploaded_by","remarks"]], use_container_width=True)
                sel = st.selectbox("Restore contract ID", d["id"]) if not d.empty else None
                if sel and st.button("Restore selected contract"):
                    con.execute("UPDATE contracts SET is_deleted=0 WHERE id=?", (sel,))
                    con.commit()
                    insert_audit(con, user["username"], "CONTRACT_RESTORE", sel, f"Restored id={sel}")
                    backup_db_to_dropbox()
                    st.success("Restored"); st.rerun()

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
            auth = authenticate(u, p, con)
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

        # Tabs
        tabs = ["Documents", "Upload", "Contracts"]
        if user["role"] == "viewer":
            tabs = ["Documents", "Contracts"]
        if user["role"] == "admin":
            tabs += ["Deleted", "Audit", "Manage Users"]

        t = st.tabs(tabs)
        with t[0]:
            page_documents(con, user)
        if "Upload" in tabs:
            with t[tabs.index("Upload")]:
                page_upload(con, user)
        if "Contracts" in tabs:
            with t[tabs.index("Contracts")]:
                page_contracts(con, user)
        if "Deleted" in tabs:
            with t[tabs.index("Deleted")] :
                page_deleted(con, user)
        if "Audit" in tabs:
            with t[tabs.index("Audit")]:
                page_audit(con)
        if "Manage Users" in tabs:
            with t[tabs.index("Manage Users")]:
                page_manage_users(con, user)

# ---------------- existing Manage Users & Audit (unchanged) ----------------
def page_audit(con, user=None):
    st.subheader("Audit Log")
    df = pd.read_sql("SELECT * FROM audit_log ORDER BY ts DESC", con)
    if df.empty:
        st.info("No logs"); return
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

if __name__ == "__main__":
    main()
