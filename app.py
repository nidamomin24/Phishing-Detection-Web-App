# app.py - updated dashboard with search/filter/pagination, CSV & PDF export, delete (admin)
import os
import io
import joblib
import pymysql
pymysql.install_as_MySQLdb()

import MySQLdb.cursors
import pandas as pd
from datetime import datetime
from flask import Flask, render_template, request, redirect, url_for, jsonify, session, send_file, flash
from extract_features import extract_features
from dotenv import load_dotenv
from werkzeug.security import generate_password_hash, check_password_hash
from fpdf import FPDF

# load .env
load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv("FLASK_SECRET", "change_this_secret")

DB_HOST = os.getenv("DB_HOST", "localhost")
DB_USER = os.getenv("DB_USER", "root")
DB_PASS = os.getenv("DB_PASS", "nida")
DB_NAME = os.getenv("DB_NAME", "phishing_db")

def get_db_conn():
    return MySQLdb.connect(host=DB_HOST, user=DB_USER, passwd=DB_PASS, db=DB_NAME, cursorclass=MySQLdb.cursors.DictCursor)

# Model load (assumes phishing_model.pkl exists)
MODEL_PATH = 'phishing_model.pkl'
if not os.path.exists(MODEL_PATH):
    raise FileNotFoundError("phishing_model.pkl not found. Run training script first.")
model = joblib.load(MODEL_PATH)

# --- Basic auth helpers (same as before) --------
def get_user_by_username(username):
    conn = get_db_conn()
    cur = conn.cursor()
    cur.execute("SELECT * FROM users WHERE username=%s", (username,))
    user = cur.fetchone()
    cur.close(); conn.close()
    return user

def save_scan(url, prediction, confidence, vt):
    conn = get_db_conn()
    cur = conn.cursor()
    cur.execute("INSERT INTO scan_history (url, prediction, confidence, vt) VALUES (%s, %s, %s, %s)",
                (url, prediction, confidence, vt))
    conn.commit()
    cur.close(); conn.close()

# ---------------- API endpoints used by extension ----------------
@app.route('/api/predict', methods=['POST'])
def api_predict():
    data = request.get_json() or {}
    url = data.get('url','')
    if not url:
        return jsonify({"error":"no url provided"}), 400
    features = extract_features(url)
    pred = model.predict([features])[0]
    proba = model.predict_proba([features])[0][1] if hasattr(model, "predict_proba") else 0.0
    label = "Phishing" if int(pred)==1 else "Safe"
    confidence = round(float(proba*100),2)
    vt = "Not configured"
    save_scan(url, label, confidence, vt)
    return jsonify({"prediction":label, "confidence":confidence, "vt":vt})

@app.route('/api/log_action', methods=['POST'])
def api_log_action():
    data = request.get_json() or {}
    url = data.get('url','')
    action = data.get('action','')
    try:
        conn = get_db_conn()
        cur = conn.cursor()
        cur.execute("INSERT INTO scan_history (url, prediction, confidence, vt) VALUES (%s, %s, %s, %s)",
                    (url, f"User:{action}", 0, "action_logged"))
        conn.commit()
        cur.close(); conn.close()
        return jsonify({"ok": True}), 201
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500

# ---------------- Web UI routes ----------------
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/register', methods=['GET','POST'])
def register():
    if request.method == 'POST':
        username = request.form['username'].strip()
        password = request.form['password'].strip()
        role = request.form.get('role','user')
        if get_user_by_username(username):
            flash("Username exists", "danger")
            return redirect(url_for('register'))
        conn = get_db_conn()
        cur = conn.cursor()
        cur.execute("INSERT INTO users (username, password, role) VALUES (%s, %s, %s)",
                    (username, generate_password_hash(password), role))
        conn.commit(); cur.close(); conn.close()
        flash("Registered. Login now.", "success")
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/login', methods=['GET','POST'])
def login():
    if request.method == 'POST':
        username = request.form['username'].strip()
        password = request.form['password'].strip()
        user = get_user_by_username(username)
        if user and check_password_hash(user['password'], password):
            session['user'] = {'id': user['id'], 'username': user['username'], 'role': user['role']}
            flash("Logged in", "success")
            return redirect(url_for('dashboard') if user['role']=='admin' else url_for('index'))
        flash("Invalid credentials", "danger")
        return redirect(url_for('login'))
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.pop('user', None)
    flash("Logged out", "info")
    return redirect(url_for('index'))

# ---------------- Dashboard + filtering + pagination ----------------
def query_history(where_clause="", params=(), order_by="timestamp DESC", limit=None, offset=None):
    q = "SELECT * FROM scan_history"
    if where_clause:
        q += " WHERE " + where_clause
    q += f" ORDER BY {order_by}"
    if limit is not None:
        q += f" LIMIT %s"
        params = params + (limit,)
        if offset is not None:
            q += " OFFSET %s"
            params = params + (offset,)
    conn = get_db_conn()
    cur = conn.cursor()
    cur.execute(q, params)
    rows = cur.fetchall()
    cur.close(); conn.close()
    return rows

@app.route('/dashboard')
def dashboard():
    # admin only
    user = session.get('user')
    if not user or user.get('role') != 'admin':
        flash("Admin login required", "warning")
        return redirect(url_for('login'))

    # read filters from query params
    page = int(request.args.get('page', 1))
    per_page = int(request.args.get('per_page', 10))
    q_url = request.args.get('q_url', '').strip()
    q_pred = request.args.get('q_pred', '').strip()  # "Phishing" or "Safe" or empty
    q_from = request.args.get('q_from', '').strip()
    q_to = request.args.get('q_to', '').strip()

    where = []
    params = []

    if q_url:
        where.append("url LIKE %s")
        params.append(f"%{q_url}%")
    if q_pred:
        where.append("prediction = %s")
        params.append(q_pred)
    if q_from:
        where.append("timestamp >= %s")
        params.append(q_from + " 00:00:00")
    if q_to:
        where.append("timestamp <= %s")
        params.append(q_to + " 23:59:59")

    where_clause = " AND ".join(where)
    # count total matching
    count_q = "SELECT COUNT(*) as cnt FROM scan_history" + ((" WHERE " + where_clause) if where_clause else "")
    conn = get_db_conn()
    cur = conn.cursor()
    cur.execute(count_q, tuple(params))
    total = cur.fetchone().get('cnt', 0)
    cur.close(); conn.close()

    # pagination calculation
    offset = (page - 1) * per_page
    rows = query_history(where_clause, tuple(params), limit=per_page, offset=offset)

    # compute stats from full filtered set (but for performance we compute from DB)
    # For summary we query counts
    summary_q = "SELECT prediction, COUNT(*) as cnt FROM scan_history" + ((" WHERE " + where_clause) if where_clause else "") + " GROUP BY prediction"
    conn = get_db_conn()
    cur = conn.cursor()
    cur.execute(summary_q, tuple(params))
    summary_rows = cur.fetchall()
    cur.close(); conn.close()
    phishing = 0; safe = 0
    for r in summary_rows:
        if r['prediction'] == 'Phishing':
            phishing = r['cnt']
        elif r['prediction'] == 'Safe':
            safe = r['cnt']
    total_filtered = phishing + safe if (phishing + safe) > 0 else total

    # Convert rows to table-friendly list
    history = rows
    # render
    total_pages = (total + per_page - 1) // per_page if per_page > 0 else 1
    return render_template('dashboard.html',
                           history=history,
                           page=page,
                           per_page=per_page,
                           total=total,
                           total_pages=total_pages,
                           q_url=q_url, q_pred=q_pred, q_from=q_from, q_to=q_to,
                           phishing=phishing, safe=safe, phishing_ratio= round((phishing/total_filtered*100) if total_filtered>0 else 0,2))

# ---------------- Delete record (admin) ----------------
@app.route('/delete/<int:record_id>', methods=['POST'])
def delete_record(record_id):
    user = session.get('user')
    if not user or user.get('role') != 'admin':
        return jsonify({"ok": False, "error": "admin required"}), 403
    conn = get_db_conn()
    cur = conn.cursor()
    cur.execute("DELETE FROM scan_history WHERE id=%s", (record_id,))
    conn.commit()
    cur.close(); conn.close()
    return jsonify({"ok": True})

# ---------------- CSV export of current filter ----------------
@app.route('/export.csv')
def export_csv():
    user = session.get('user')
    if not user or user.get('role') != 'admin':
        flash("Admin required", "warning")
        return redirect(url_for('login'))

    q_url = request.args.get('q_url', '').strip()
    q_pred = request.args.get('q_pred', '').strip()
    q_from = request.args.get('q_from', '').strip()
    q_to = request.args.get('q_to', '').strip()

    where = []
    params = []

    if q_url:
        where.append("url LIKE %s"); params.append(f"%{q_url}%")
    if q_pred:
        where.append("prediction = %s"); params.append(q_pred)
    if q_from:
        where.append("timestamp >= %s"); params.append(q_from + " 00:00:00")
    if q_to:
        where.append("timestamp <= %s"); params.append(q_to + " 23:59:59")
    where_clause = " AND ".join(where)

    rows = query_history(where_clause, tuple(params), limit=None)
    df = pd.DataFrame(rows)
    if df.empty:
        # return empty CSV
        csv_bytes = "id,url,prediction,confidence,vt,timestamp\n".encode('utf-8')
        return send_file(io.BytesIO(csv_bytes), download_name="scan_report.csv", as_attachment=True, mimetype='text/csv')

    csv_bytes = df.to_csv(index=False).encode('utf-8')
    return send_file(io.BytesIO(csv_bytes), download_name="scan_report.csv", as_attachment=True, mimetype='text/csv')

# ---------------- PDF export (filtered) ----------------
@app.route('/export.pdf')
def export_pdf():
    user = session.get('user')
    if not user or user.get('role') != 'admin':
        flash("Admin required", "warning")
        return redirect(url_for('login'))

    q_url = request.args.get('q_url', '').strip()
    q_pred = request.args.get('q_pred', '').strip()
    q_from = request.args.get('q_from', '').strip()
    q_to = request.args.get('q_to', '').strip()

    where = []
    params = []

    if q_url:
        where.append("url LIKE %s"); params.append(f"%{q_url}%")
    if q_pred:
        where.append("prediction = %s"); params.append(q_pred)
    if q_from:
        where.append("timestamp >= %s"); params.append(q_from + " 00:00:00")
    if q_to:
        where.append("timestamp <= %s"); params.append(q_to + " 23:59:59")
    where_clause = " AND ".join(where)

    rows = query_history(where_clause, tuple(params), limit=None)
    df = pd.DataFrame(rows)

    pdf = FPDF()
    pdf.set_auto_page_break(auto=True, margin=15)
    pdf.add_page()
    pdf.set_font("Arial", size=12)
    pdf.cell(0, 10, f"Phishing Scan Report - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", ln=True)
    pdf.ln(5)
    pdf.cell(0,8, f"Total rows: {len(df)}", ln=True)
    pdf.ln(5)
    # table header
    pdf.set_font("Arial", "B", 10)
    pdf.cell(10,8,"ID",1)
    pdf.cell(80,8,"URL",1)
    pdf.cell(30,8,"Prediction",1)
    pdf.cell(20,8,"Conf",1)
    pdf.cell(40,8,"Time",1,ln=True)
    pdf.set_font("Arial", size=9)
    for r in rows:
        pdf.cell(10,8,str(r['id']),1)
        url_text = (r['url'][:60] + '...') if len(r['url'])>60 else r['url']
        pdf.cell(80,8,url_text,1)
        pdf.cell(30,8,str(r['prediction']),1)
        pdf.cell(20,8,str(r['confidence']),1)
        pdf.cell(40,8,str(r['timestamp']),1,ln=True)
    pdf_output = pdf.output(dest='S').encode('latin-1')
    return send_file(io.BytesIO(pdf_output), download_name="scan_report.pdf", as_attachment=True)

# ---------------- Data endpoint for charts ----------------
@app.route('/api/logs')
def api_logs():
    # return aggregated counts per day for last 30 days (for chart)
    conn = get_db_conn()
    cur = conn.cursor()
    cur.execute("""
        SELECT DATE(timestamp) as day,
               SUM(CASE WHEN prediction='Phishing' THEN 1 ELSE 0 END) AS phishing_count,
               SUM(CASE WHEN prediction='Safe' THEN 1 ELSE 0 END) AS safe_count
        FROM scan_history
        WHERE timestamp >= DATE_SUB(CURDATE(), INTERVAL 30 DAY)
        GROUP BY DATE(timestamp)
        ORDER BY DATE(timestamp) ASC
    """)
    rows = cur.fetchall()
    cur.close(); conn.close()
    # prepare arrays
    days = [r['day'].strftime("%Y-%m-%d") for r in rows]
    phishing_counts = [r['phishing_count'] for r in rows]
    safe_counts = [r['safe_count'] for r in rows]
    return jsonify({"days": days, "phishing": phishing_counts, "safe": safe_counts})
# add this to app.py
@app.route('/predict', methods=['POST'])
def predict_page():
    url = request.form.get('url','').strip()
    if not url:
        return redirect(url_for('index'))
    # use same feature + model logic as api_predict
    features = extract_features(url)
    pred = model.predict([features])[0]
    proba = model.predict_proba([features])[0][1] if hasattr(model, "predict_proba") else 0.0
    label = "Phishing" if int(pred) == 1 else "Safe"
    confidence = round(float(proba * 100), 2)
    vt = "Not configured"
    # save result to DB
    try:
        save_scan(url, label, confidence, vt)
    except Exception:
        pass
    # render index.html with result variables used in your template
    return render_template('index.html', url=url, prediction=label, confidence=confidence, vt=vt)


if __name__ == '__main__':
    app.run(debug=True)
