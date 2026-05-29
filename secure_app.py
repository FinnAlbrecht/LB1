"""
OWASP A03:2021 – Injection (SQL Injection)
==========================================
SICHER: Gehärtete Version mit Gegenmassnahmen

Starten: pip install flask && python secure_app.py
Testen:  http://127.0.0.1:5002/login
"""

import sqlite3
import hashlib
import hmac
import os
import subprocess
import regex as re
from flask import Flask, request, g, render_template

app = Flask(__name__)
DATABASE = "demo_secure.db"
SECRET_KEY = os.urandom(32)  # Für HMAC-Passwort-Hashing


def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DATABASE)
    return g.db


@app.teardown_appcontext
def close_db(error):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def hash_password(password: str) -> str:
    """Passwort mit HMAC-SHA256 hashen (in Produktion: bcrypt/argon2 verwenden)."""
    return hmac.new(SECRET_KEY, password.encode(), hashlib.sha256).hexdigest()


def init_db():
    """Datenbank mit gehashten Passwörtern initialisieren."""
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
    # Passwörter werden gehasht gespeichert
    db.execute("INSERT INTO users (username, password, role) VALUES (?, ?, ?)",
               ("admin", hash_password("geheim123"), "admin"))
    db.execute("INSERT INTO users (username, password, role) VALUES (?, ?, ?)",
               ("alice", hash_password("passwort1"), "user"))
    db.execute("INSERT INTO users (username, password, role) VALUES (?, ?, ?)",
               ("bob",   hash_password("passwort2"), "user"))
    db.commit()
    db.close()


# ──────────────────────────────────────────────────────────────────────────────
# MASSNAHME 1: Parameterisierte Abfragen (Prepared Statements)
# Das ? ist ein Platzhalter – SQLite behandelt den Wert als Datum, NICHT als Code
# ──────────────────────────────────────────────────────────────────────────────
@app.route("/login", methods=["GET", "POST"])
def login_secure():
    result = ""
    result_style = "border-left: 4px solid #555;"

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "").strip()

        # MASSNAHME 1: Eingabevalidierung – leere Felder ablehnen
        if not username or not password:
            result = "❌ Benutzername und Passwort sind erforderlich."
            result_style = "border-left: 4px solid orange;"
        else:
            # MASSNAHME 2: Parameterisierte Abfrage – KEIN String-Zusammensetzen!
            # Der ?-Platzhalter verhindert, dass Eingaben als SQL interpretiert werden
            query = "SELECT * FROM users WHERE username = ?"
            db = get_db()
            rows = db.execute(query, (username,)).fetchall()  # ← Tupel mit Werten!

            # MASSNAHME 3: Passwort-Vergleich im Anwendungscode (nicht im SQL)
            if rows and hmac.compare_digest(rows[0][2], hash_password(password)):
                result = f"✅ Login erfolgreich! Willkommen, {rows[0][1]} (Rolle: {rows[0][3]})"
                result_style = "border-left: 4px solid #44bb44;"
            else:
                # MASSNAHME 4: Gleiche Fehlermeldung – kein Hinweis ob User existiert
                result = "❌ Ungültige Anmeldedaten."
                result_style = "border-left: 4px solid #cc3333;"

    massnahmen = [
        ("Parameterisierte Abfragen", "? statt String-Konkatenation", "SQL-Injection unmöglich"),
        ("Eingabevalidierung",        "Leere/zu lange Felder ablehnen", "Reduktion der Angriffsfläche"),
        ("Passwort-Hashing",          "HMAC-SHA256 (Prod: bcrypt)",   "Schutz bei DB-Leak"),
        ("Neutrale Fehlermeldungen",  "Kein Hinweis auf User-Existenz", "Verhindert User-Enumeration"),
    ]

    return f"""
    <html><head><title>✅ SICHER – Gehärtete Login-Seite</title>
    <style>
        body {{ font-family: monospace; max-width: 700px; margin: 40px auto; background: #0d1a0d; color: #eee; padding: 20px; }}
        h1 {{ color: #44cc44; }} input {{ width: 100%; padding: 8px; margin: 6px 0; background: #1a2a1a; color: #fff; border: 1px solid #336633; }}
        button {{ padding: 10px 20px; background: #226622; color: white; border: none; cursor: pointer; }}
        .result {{ margin-top: 16px; padding: 12px; background: #1a2a1a; {result_style} }}
        table {{ width: 100%; border-collapse: collapse; margin-top: 10px; }}
        td, th {{ padding: 6px 10px; border: 1px solid #335533; text-align: left; font-size: 13px; }}
        th {{ background: #1a2a1a; color: #88cc88; }}
    </style></head><body>
    <h1>✅ GEHÄRTETE LOGIN-SEITE</h1>
    <p>Korrekte Login-Daten: <code>admin / geheim123</code></p>
    <form method="POST">
        <label>Benutzername:</label>
        <input name="username" value="{request.form.get('username','')}" placeholder="admin">
        <label>Passwort:</label>
        <input name="password" type="text" placeholder="geheim123">
        <button type="submit">Login</button>
    </form>
    <div class="result">{result if result else "Noch kein Login versucht. Teste auch: admin' -- / egal"}</div>
    <h3>🛡️ Implementierte Gegenmassnahmen:</h3>
    <table>
        <tr><th>Massnahme</th><th>Implementierung</th><th>Schutzwirkung</th></tr>
        {''.join(f"<tr><td><b>{m}</b></td><td>{i}</td><td>{s}</td></tr>" for m,i,s in massnahmen)}
    </table>
    </body></html>
    """


# ✅ SAFE option 2 - use a .html template file (preferred)
@app.route("/greet")
def greet():
    name = request.args.get("name", "")
    return render_template("greet.html", name=name)

@app.route("/ping")
def ping():
    host = request.args.get("host", "")
    if not re.match(r'^[a-zA-Z0-9.\-]+$', host):
        return "Invalid host", 400
    result = subprocess.run(["ping", "-c", "1", host], capture_output=True, text=True)
    return result.stdout



if __name__ == "__main__":
    init_db()
    print("\n✅ Sichere Demo-App")
    print("   Öffne: http://127.0.0.1:5002/login\n")
    app.run(debug=True, port=5002)