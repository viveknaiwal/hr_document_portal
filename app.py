# app.py
# ------------------------------------------------------------------
# HR Document Portal — Final Stable Version (with role-based access)
# ------------------------------------------------------------------

import base64, hashlib, datetime as dt, sqlite3, mimetypes, secrets, zipfile
from pathlib import Path
from io import BytesIO
import pandas as pd
import streamlit as st

APP_TITLE = "HR Document Portal"
STORAGE_DIR = Path(r"G:\My Drive\HR_Documents_Portal")  # adjust if needed
DB_PATH = Path("storage/hr_docs.db")
STORAGE_DIR.mkdir(parents=True, exist_ok=True)
DB_PATH.parent.mkdir(parents=True, exist_ok=True)

# ==== fallback users ====
RAW_USERS = {
    "admin@cars24.com": {"password": "admin123", "role": "admin"},
    "editor@cars24.com": {"password": "editor123", "role": "editor"},
    "viewer@cars24.com": {"password": "viewer123", "role": "viewer"},
}

# ================= DB =================
def init_db():
    con = sqlite3.connect(DB_PATH, check_same_thread=False)
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
    for col in ["file_token", "email_token"]:
        try:
            cur.execute(f"ALTER TABLE documents ADD COLUMN {col} TEXT")
        except sqlite3.OperationalError:
            pass
    con.commit()
    return con

def insert_audit(con, actor, action, doc_id=None, details=""):
    con.execute(
        "INSERT INTO audit_log(ts,actor,action,doc_id,details) VALUES (?,?,?,?,?)",
        (dt.datetime.utcnow().isoformat(), actor, action, doc_id, details),
    )
    con.commit()

# ================= USERS =================
def _hash(pw): return hashlib.sha256(pw.encode()).hexdigest()

def load_users():
    csv_path = Path("users.csv"); users = {}
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
    users = load_users()
    rec = users.get(username.strip().lower())
    if rec and _hash(password) == rec["password_sha256"]:
        return {"username": username.strip().lower(), "role": rec["role"]}
    return None

# ================= HELPERS =================
def sha256_bytes(b): h = hashlib.sha256(); h.update(b); return h.hexdigest()
def safe_title(name): return "".join(c for c in name if c.isalnum() or c in (" ", "_", "-")).strip().replace(" ", "_")
def save_file(data, *, doc_type, name, version, filename):
    subdir = STORAGE_DIR / doc_type / safe_title(name) / f"v{version}"
    subdir.mkdir(parents=True, exist_ok=True)
    path = subdir / filename; path.write_bytes(data); return path
def gen_token(): return secrets.token_urlsafe(16)

def ensure_tokens(con, row_id, email_exists):
    cur = con.execute("SELECT file_token,email_token FROM documents WHERE id=?", (row_id,))
    result = cur.fetchone()
    if not result: return None, None
    ft, et = result
    if not ft:
        ft = gen_token(); con.execute("UPDATE documents SET file_token=? WHERE id=?", (ft, row_id))
    if email_exists and not et:
        et = gen_token(); con.execute("UPDATE documents SET email_token=? WHERE id=?", (et, row_id))
    con.commit(); return ft, et

def open_in_new_tab_link(token, label):
    href = f"/?serve={token}"
    st.markdown(f'<a href="{href}" target="_blank">{label}</a>', unsafe_allow_html=True)

def make_zip(paths: list) -> bytes:
    buf = BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        for p in paths:
            if p and Path(p).exists():
                zf.write(p, Path(p).name)
    return buf.getvalue()

# ================= SERVE MODE =================
if "serve" in st.query_params:
    token = st.query_params["serve"]
    con = init_db()
    cur = con.execute("SELECT id,file_path,email_path,file_token,email_token FROM documents")
    found = None
    for rid, fp, ep, ft, et in cur.fetchall():
        if token == ft: found = fp
        if token == et: found = ep
    if not found or not Path(found).exists():
        st.error("File not found"); st.stop()
    f = Path(found); mime, _ = mimetypes.guess_type(f.name)
    st.markdown(f"### {f.name}")
    data = f.read_bytes()
    if f.suffix.lower() == ".pdf" and f.stat().st_size < 15_000_000:
        b64 = base64.b64encode(data).decode()
        st.markdown(f'<iframe src="data:application/pdf;base64,{b64}" width="100%" height="700"></iframe>', unsafe_allow_html=True)
    elif f.suffix.lower() in {".png", ".jpg", ".jpeg"}:
        st.image(str(f), use_container_width=True)
    elif f.suffix.lower() == ".txt":
        st.text(f.read_text(errors="replace")[:5000])
    else:
        st.info("Preview not supported inline. Use Download below.")
    st.download_button("⬇️ Download", data, f.name, mime or "application/octet-stream")
    st.stop()

# ================= PAGES =================
def page_upload(con, user):
    if user["role"] not in ("admin", "editor"):
        st.warning("You don’t have permission to upload documents.")
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
        maxv = cur.fetchone()[0]; version = (maxv+1) if maxv else 1
        path = save_file(data, doc_type=doc_type, name=name, version=version, filename=doc.name)
        email_path = ""
        if email: email_path = save_file(email.read(), doc_type=doc_type, name=name, version=version, filename="email_"+email.name)
        ft, et = gen_token(), gen_token() if email_path else None
        con.execute("""INSERT INTO documents
            (doc_type,name,created_date,upload_date,approved_by,file_path,email_path,version,uploaded_by,hash_sha256,is_deleted,file_token,email_token)
            VALUES (?,?,?,?,?,?,?,?,?,?,0,?,?)""",
            (doc_type, name, str(created_date), dt.datetime.utcnow().isoformat(),
             approved_by, str(path), str(email_path), version, user["username"], sha256_bytes(data), ft, et))
        con.commit()
        insert_audit(con, user["username"], "UPLOAD")
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
    if df.empty: st.info("No documents available"); return

    col1, col2, col3 = st.columns(3)
    with col1: t = st.selectbox("Type", ["All"]+sorted(df["doc_type"].unique().tolist()))
    with col2: name_q = st.text_input("Search name")
    with col3: appr_q = st.text_input("Approved by")

    f = df.copy()
    if t != "All": f = f[f["doc_type"] == t]
    if name_q: f = f[f["name"].str.contains(name_q, case=False, na=False)]
    if appr_q: f = f[f["approved_by"].str.contains(appr_q, case=False, na=False)]
    if f.empty: st.info("No matching documents"); return

    f["version"] = f["version"].astype(int)
    latest_flags = f.groupby(["doc_type","name"])["version"].transform("max")
    f["is_latest"] = f["version"] == latest_flags

    st.dataframe(f[["doc_type","name","version","is_latest","created_date","upload_date","approved_by","uploaded_by"]],
                 use_container_width=True)

    st.markdown("### Open a document group")
    groups = f.drop_duplicates(subset=["doc_type","name"])
    labels = [f"{r.doc_type} — {r.name}" for r in groups.itertuples()]
    pick = st.selectbox("Select document", labels)
    if not pick: return
    sel_group = groups.iloc[labels.index(pick)]
    versions = f[(f["doc_type"]==sel_group["doc_type"]) & (f["name"]==sel_group["name"])].sort_values("version", ascending=False)

    v_table = versions_with_links(con, versions)
    v_show = v_table[["version","upload_date","uploaded_by","approved_by","is_latest","View (doc)","View (email)"]]
    st.data_editor(v_show, use_container_width=True, disabled=True,
                   column_config={
                       "View (doc)": st.column_config.LinkColumn("View (doc)"),
                       "View (email)": st.column_config.LinkColumn("View (email)")
                   })

    choice = st.selectbox("Select version", [f"v{r.version}" for r in versions.itertuples()])
    sel = versions.iloc[[f"v{r.version}" for r in versions.itertuples()].index(choice)]

    st.markdown("### Document actions")
    ft, et = ensure_tokens(con, sel["id"], bool(sel["email_path"]))

    doc_path = Path(sel["file_path"]) if sel["file_path"] else None
    if doc_path and doc_path.exists():
        c1, c2, c3 = st.columns(3)
        with c1: open_in_new_tab_link(ft,"🔍 View document (new tab)")
        with c2: st.download_button("⬇️ Download document", doc_path.read_bytes(), file_name=doc_path.name)
        with c3: st.download_button("⬇️ Download All (ZIP)",
            make_zip([sel["file_path"], sel["email_path"]]), file_name=f"{sel['name']}_v{sel['version']}.zip")

    if sel["email_path"]:
        email_path = Path(sel["email_path"])
        if email_path.exists():
            e1,e2 = st.columns(2)
            with e1:
                if et: open_in_new_tab_link(et,"🔍 View approval/email (new tab)")
            with e2:
                st.download_button("⬇️ Download approval/email", email_path.read_bytes(), file_name=email_path.name)

    st.markdown("---")
    if user["role"]=="admin" and st.button("Delete this version"):
        con.execute("UPDATE documents SET is_deleted=1 WHERE id=?",(int(sel["id"]),))
        con.commit(); insert_audit(con,user["username"],"DELETE",sel["id"]); st.success("Deleted"); st.rerun()

def page_deleted(con, user):
    if user["role"] != "admin":
        st.warning("Only admins can restore deleted documents.")
        return
    st.subheader("Deleted Versions")
    df = pd.read_sql("SELECT * FROM documents WHERE is_deleted=1", con)
    if df.empty: st.info("None"); return
    st.dataframe(df[["id","doc_type","name","version","uploaded_by"]], use_container_width=True)
    sel = st.selectbox("Restore ID", df["id"])
    if st.button("Restore"):
        con.execute("UPDATE documents SET is_deleted=0 WHERE id=?",(sel,))
        con.commit(); insert_audit(con,user["username"],"RESTORE",sel); st.success("Restored"); st.rerun()

def page_audit(con, user=None):
    if not user or user["role"] != "admin":
        st.warning("Only admins can view audit logs.")
        return
    st.subheader("Audit Log")
    df = pd.read_sql("SELECT * FROM audit_log ORDER BY ts DESC", con)
    if df.empty: st.info("No logs"); return
    st.download_button("⬇️ Export CSV", df.to_csv(index=False).encode(), "audit.csv")
    buf = BytesIO(); df.to_excel(buf, index=False)
    st.download_button("⬇️ Export Excel", buf.getvalue(), "audit.xlsx")
    st.dataframe(df, use_container_width=True)

# ================= MAIN =================
def main():
    st.set_page_config(APP_TITLE, layout="wide")
    con = st.session_state.get("con") or init_db(); st.session_state["con"] = con
    user = st.session_state.get("user")

    if not user:
        st.title(APP_TITLE)
        u = st.text_input("Email"); p = st.text_input("Password", type="password")
        if st.button("Login"):
            auth = authenticate(u, p)
            if auth: st.session_state["user"] = auth; insert_audit(con, u, "LOGIN"); st.rerun()
            else: st.error("Invalid"); return
    else:
        st.sidebar.write(f"Signed in as {user['username']} ({user['role']})")
        if st.sidebar.button("Logout"):
            insert_audit(con, user["username"], "LOGOUT")
            st.session_state.pop("user"); st.rerun()

        # Tabs by role
        tabs = ["Documents"]
        if user["role"] in ("admin", "editor"):
            tabs.append("Upload")
        if user["role"] == "admin":
            tabs += ["Deleted", "Audit"]

        t = st.tabs(tabs)
        with t[0]: page_documents(con, user)
        if "Upload" in tabs:
            with t[tabs.index("Upload")]: page_upload(con, user)
        if "Deleted" in tabs:
            with t[tabs.index("Deleted")]: page_deleted(con, user)
        if "Audit" in tabs:
            with t[tabs.index("Audit")]: page_audit(con, user)

if __name__ == "__main__": 
    main()
