import subprocess, json, os, sqlite3
from datetime import datetime
from flask import Flask, render_template, request, redirect, url_for

app = Flask(__name__)
DB_FILE = 'scans.db'

# تحديد مسار المجلد الرئيسي (اللي فيه security_scan.py)
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
def init_db():
    with sqlite3.connect(DB_FILE) as conn:
        conn.execute('''CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            image TEXT,
            date TEXT,
            total INTEGER,
            critical INTEGER,
            high INTEGER,
            medium INTEGER,
            low INTEGER
        )''')

@app.route('/')
def index():
    init_db()
    with sqlite3.connect(DB_FILE) as conn:
        scans = conn.execute("SELECT * FROM scans ORDER BY id DESC").fetchall()
    return render_template('index.html', scans=scans)

@app.route('/scan', methods=['POST'])
def scan():
    image = request.form.get('image')
    if not image:
        return redirect(url_for('index'))
    
    print(f"Scanning {image}...")
    
    # مسار حفظ ملف الـ JSON في المجلد الرئيسي
    json_path = os.path.join(BASE_DIR, "report.json")
    
    # 1. تشغيل الفحص وحفظ النتيجة
    subprocess.run(["grype", image, "-o", "json", "--file", json_path])
    
    # 2. قراءة النتائج لحفظها في الداتا بيز
    if os.path.exists(json_path):
        with open(json_path, "r", encoding="utf-8") as f:
            data = json.load(f)
            
        matches = data.get("matches", [])
        count = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Negligible": 0}
        for m in matches:
            sev = m["vulnerability"]["severity"]
            count[sev] = count.get(sev, 0) + 1
            
        with sqlite3.connect(DB_FILE) as conn:
            conn.execute("INSERT INTO scans (image, date, total, critical, high, medium, low) VALUES (?, ?, ?, ?, ?, ?, ?)",
                         (image, datetime.now().strftime("%Y-%m-%d %H:%M"), len(matches), count["Critical"], count["High"], count["Medium"], count["Low"]))
        
        # 3. تشغيل سكربت التقرير وتمرير اسم التطبيق له
        scan_script_path = os.path.join(BASE_DIR, "security_scan.py")
        subprocess.run(["python", scan_script_path, image])
        
    return redirect(url_for('index'))

@app.route('/report')
def report():
    report_path = os.path.join(BASE_DIR, "security_report.html")
    if os.path.exists(report_path):
        with open(report_path, "r", encoding="utf-8") as f:
            return f.read()
    return "التقرير غير موجود. الرجاء إجراء فحص أولاً."

if __name__ == '__main__':
    init_db()
    app.run(debug=True, port=5000)