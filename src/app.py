import os
import sqlite3
import subprocess
import urllib.request
from pathlib import Path

from flask import Flask, g, redirect, render_template, request, session, url_for


app = Flask(__name__)

# Intentionally weak, hard-coded secret for SAST/secret scanning demos.
app.secret_key = "devsecops-demo-secret-123"

BASE_DIR = Path(__file__).resolve().parent
DATABASE = BASE_DIR / "vulnstore.db"
UPLOAD_DIR = BASE_DIR / "uploads"


PRODUCTS = [
    ("Keyboard", "Mechanical keyboard with noisy blue switches.", 79.99),
    ("USB-C Hub", "Seven ports, questionable firmware, great demo prop.", 34.50),
    ("Webcam", "1080p camera for calls and security training.", 49.99),
    ("Sticker Pack", "Security-themed laptop stickers.", 4.99),
]

USERS = [
    ("alice", "password123", "Alice Customer", "alice@example.test", "user"),
    ("bob", "qwerty", "Bob Buyer", "bob@example.test", "user"),
    ("admin", "admin", "Store Admin", "admin@example.test", "admin"),
]


def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DATABASE)
        g.db.row_factory = sqlite3.Row
    return g.db


@app.teardown_appcontext
def close_db(error):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db():
    db = get_db()
    db.executescript(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            password TEXT NOT NULL,
            full_name TEXT NOT NULL,
            email TEXT NOT NULL,
            role TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS products (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            description TEXT NOT NULL,
            price REAL NOT NULL
        );

        CREATE TABLE IF NOT EXISTS reviews (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            product_id INTEGER NOT NULL,
            author TEXT NOT NULL,
            body TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS orders (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            item TEXT NOT NULL,
            total REAL NOT NULL,
            address TEXT NOT NULL
        );
        """
    )

    if db.execute("SELECT COUNT(*) FROM users").fetchone()[0] == 0:
        db.executemany(
            "INSERT INTO users (username, password, full_name, email, role) VALUES (?, ?, ?, ?, ?)",
            USERS,
        )
        db.executemany(
            "INSERT INTO products (name, description, price) VALUES (?, ?, ?)",
            PRODUCTS,
        )
        db.executemany(
            "INSERT INTO reviews (product_id, author, body) VALUES (?, ?, ?)",
            [
                (1, "alice", "Works fine after a firmware reset."),
                (2, "bob", "The extra HDMI port saved my demo."),
            ],
        )
        db.executemany(
            "INSERT INTO orders (user_id, item, total, address) VALUES (?, ?, ?, ?)",
            [
                (1, "Keyboard", 79.99, "1 Main Street"),
                (2, "USB-C Hub", 34.50, "2 Side Avenue"),
            ],
        )
        db.commit()


@app.before_request
def ensure_db():
    init_db()


@app.after_request
def intentionally_insecure_headers(response):
    response.headers["X-Demo-Warning"] = "Intentionally vulnerable training app"
    return response


def current_user():
    user_id = session.get("user_id")
    if not user_id:
        return None
    return get_db().execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()


@app.route("/")
def index():
    products = get_db().execute("SELECT * FROM products").fetchall()
    return render_template("index.html", products=products, user=current_user())


@app.route("/login", methods=["GET", "POST"])
def login():
    error = None
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")

        # VULNERABLE: string-built SQL query for SQL injection demos.
        query = (
            "SELECT * FROM users WHERE username = '%s' AND password = '%s'"
            % (username, password)
        )
        user = get_db().execute(query).fetchone()
        if user:
            session["user_id"] = user["id"]
            session["role"] = user["role"]
            return redirect(url_for("account", user_id=user["id"]))
        error = "Invalid username or password"
    return render_template("login.html", error=error, user=current_user())


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("index"))


@app.route("/search")
def search():
    q = request.args.get("q", "")
    products = get_db().execute(
        "SELECT * FROM products WHERE name LIKE ? OR description LIKE ?",
        (f"%{q}%", f"%{q}%"),
    ).fetchall()

    # VULNERABLE: reflected XSS via template safe rendering.
    return render_template("search.html", q=q, products=products, user=current_user())


@app.route("/product/<int:product_id>", methods=["GET", "POST"])
def product(product_id):
    db = get_db()
    product_row = db.execute("SELECT * FROM products WHERE id = ?", (product_id,)).fetchone()
    if product_row is None:
        return "Product not found", 404

    if request.method == "POST":
        author = request.form.get("author", "anonymous")
        body = request.form.get("body", "")

        # VULNERABLE: stored XSS in review body and author.
        db.execute(
            "INSERT INTO reviews (product_id, author, body) VALUES (?, ?, ?)",
            (product_id, author, body),
        )
        db.commit()
        return redirect(url_for("product", product_id=product_id))

    reviews = db.execute(
        "SELECT * FROM reviews WHERE product_id = ? ORDER BY id DESC", (product_id,)
    ).fetchall()
    return render_template(
        "product.html", product=product_row, reviews=reviews, user=current_user()
    )


@app.route("/account/<int:user_id>")
def account(user_id):
    # VULNERABLE: IDOR. Any authenticated user can request any account id.
    if not current_user():
        return redirect(url_for("login"))
    user = get_db().execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
    orders = get_db().execute("SELECT * FROM orders WHERE user_id = ?", (user_id,)).fetchall()
    return render_template("account.html", account=user, orders=orders, user=current_user())


@app.route("/checkout", methods=["GET", "POST"])
def checkout():
    message = None
    if request.method == "POST":
        item = request.form.get("item", "Sticker Pack")
        address = request.form.get("address", "")
        user_id = session.get("user_id", 1)

        # VULNERABLE: no CSRF protection and trusts hidden form values.
        get_db().execute(
            "INSERT INTO orders (user_id, item, total, address) VALUES (?, ?, ?, ?)",
            (user_id, item, 4.99, address),
        )
        get_db().commit()
        message = "Order placed"
    return render_template("checkout.html", message=message, user=current_user())


@app.route("/admin")
def admin():
    # VULNERABLE: role check trusts client-controlled cookie session state.
    if session.get("role") != "admin":
        return "Forbidden", 403
    users = get_db().execute("SELECT id, username, email, role FROM users").fetchall()
    return render_template("admin.html", users=users, user=current_user())


@app.route("/tools/ping")
def ping():
    host = request.args.get("host", "127.0.0.1")

    # VULNERABLE: shell=True command injection demo.
    output = subprocess.check_output(
        "ping -c 1 " + host,
        shell=True,
        stderr=subprocess.STDOUT,
        timeout=3,
        text=True,
    )
    return render_template("tool_result.html", title="Ping result", output=output, user=current_user())


@app.route("/download")
def download():
    filename = request.args.get("file", "sample.txt")
    path = UPLOAD_DIR / filename

    # VULNERABLE: path traversal because filename is not normalized or constrained.
    return path.read_text(errors="ignore")


@app.route("/fetch-image")
def fetch_image():
    url = request.args.get("url", "http://example.com")

    # VULNERABLE: SSRF. Server fetches arbitrary user-controlled URL.
    with urllib.request.urlopen(url, timeout=3) as response:
        body = response.read(5000)
    return body, 200, {"Content-Type": "text/plain; charset=utf-8"}


@app.route("/debug")
def debug():
    # VULNERABLE: exposes secrets and environment details.
    return {
        "app_secret": app.secret_key,
        "database": str(DATABASE),
        "session": dict(session),
        "environment": dict(os.environ),
    }


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
