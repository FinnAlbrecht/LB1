"""
OWASP A03:2021 – Injection (SQL Injection)
==========================================
DEMO: VERWUNDBARE Applikation (NUR für Lernzwecke!)
Dieses Beispiel zeigt eine klassische SQL-Injection-Schwachstelle.

Starten: pip install flask && python vulnerable_app.py
Testen:  http://127.0.0.1:5001/login
"""

import sqlite3
import subprocess
import os
from flask import Flask, request, g, render_template_string

app = Flask(__name__)
DATABASE = "demo_vulnerable.db"


def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DATABASE)
    return g.db


@app.teardown_appcontext
def close_db(error):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db():
    """Datenbank mit Beispieldaten initialisieren."""
    db = sqlite3.connect(DATABASE)
    db.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id       INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            password TEXT NOT NULL,
            role     TEXT DEFAULT 'user'
        )
    """)
    db.execute("DELETE FROM users")
    db.execute("INSERT INTO users (username, password, role) VALUES ('admin', 'geheim123', 'admin')")
    db.execute("INSERT INTO users (username, password, role) VALUES ('alice', 'passwort1', 'user')")
    db.execute("INSERT INTO users (username, password, role) VALUES ('bob',   'passwort2', 'user')")
    db.commit()
    db.close()


# ──────────────────────────────────────────────────────────────────────────────
# SCHWACHSTELLE: Direktes Einfügen von Benutzereingaben in den SQL-String
# ──────────────────────────────────────────────────────────────────────────────
@app.route("/login", methods=["GET", "POST"])
def login_vulnerable():
    result = ""
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")

        # ⚠️ GEFÄHRLICH: String-Konkatenation – SQL Injection möglich!
        query = (
            f"SELECT * FROM users WHERE username = '{username}' "
            f"AND password = '{password}'"
        )
        print(f"[DEBUG] Ausgeführtes SQL: {query}")  # Zum Nachvollziehen

        db = get_db()
        rows = db.execute(query).fetchall()

        if rows:
            result = f"✅ Login erfolgreich als: {rows[0][1]} (Rolle: {rows[0][3]})"
        else:
            result = "❌ Login fehlgeschlagen."

    angriff_beispiele = [
        ("Bypass ohne Passwort",    "admin' --",      "egal"),
        ("Immer wahr (OR 1=1)",     "' OR '1'='1",   "' OR '1'='1"),
        ("Alle User auslesen",      "' OR 1=1 --",    "egal"),
    ]

    return f"""
    <html><head><title>⚠️ VERWUNDBAR – SQL Injection Demo</title>
    <style>
        body {{ font-family: monospace; max-width: 700px; margin: 40px auto; background: #1a1a1a; color: #eee; padding: 20px; }}
        h1 {{ color: #ff4444; }} input {{ width: 100%; padding: 8px; margin: 6px 0; background: #333; color: #fff; border: 1px solid #555; }}
        button {{ padding: 10px 20px; background: #cc3333; color: white; border: none; cursor: pointer; }}
        .result {{ margin-top: 16px; padding: 12px; background: #2a2a2a; border-left: 4px solid #ff4444; }}
        .tip {{ background: #2a1a00; border-left: 4px solid orange; padding: 10px; margin: 8px 0; font-size: 13px; }}
        table {{ width: 100%; border-collapse: collapse; margin-top: 10px; }}
        td, th {{ padding: 6px 10px; border: 1px solid #444; text-align: left; font-size: 13px; }}
        th {{ background: #333; }}
    </style></head><body>
    <h1>⚠️ VERWUNDBARE LOGIN-SEITE</h1>
    <p>Diese Seite ist absichtlich unsicher – nur für Demonstrationszwecke!</p>
    <form method="POST">
        <label>Benutzername:</label>
        <input name="username" value="{request.form.get('username','')}" placeholder="z.B. admin' --">
        <label>Passwort:</label>
        <input name="password" value="{request.form.get('password','')}" placeholder="z.B. egal">
        <button type="submit">Login</button>
    </form>
    <div class="result">{result if result else "Noch kein Login versucht."}</div>
    <h3>💡 Angriffs-Beispiele zum Ausprobieren:</h3>
    <table>
        <tr><th>Beschreibung</th><th>Benutzername</th><th>Passwort</th></tr>
        {''.join(f"<tr><td>{b}</td><td><code>{u}</code></td><td><code>{p}</code></td></tr>" for b,u,p in angriff_beispiele)}
    </table>
    </body></html>
    """
    


# ❌ VULNERABLE - user input passed directly into render_template_string
# /greet?name={{config.SECRET_KEY}} , config.items() etc.
@app.route("/greet")
def greet():
    name = request.args.get("name", "")
    template = f"<h1>Hello, {name}!</h1>"
    return render_template_string(template)




# ❌ VULNERABLE - shell=True with user input
@app.route("/ping")
def ping_host():
    hostname = request.args.get("host", "")
    result = subprocess.run(f"ping -c 1 {hostname}", shell=True, capture_output=True, text=True)
    return result.stdout

# ❌ ALSO VULNERABLE - os.system
def list_files(directory: str):
    os.system(f"ls {directory}")



if __name__ == "__main__":
    init_db()
    print("\n⚠️  ACHTUNG: Verwundbare Demo-App – NUR für lokale Tests!")
    print("   Öffne: http://127.0.0.1:5001/login\n")
    app.run(debug=True, port=5001)