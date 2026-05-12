import ipaddress
import os
import secrets
import socket
import sqlite3
import urllib.error
import urllib.request
from pathlib import Path
from urllib.parse import urlparse

from flask import (
    Flask,
    abort,
    g,
    jsonify,
    redirect,
    render_template,
    request,
    send_from_directory,
    session,
    url_for,
)
from werkzeug.security import check_password_hash, generate_password_hash


app = Flask(__name__, template_folder="secure_templates", static_folder="secure_static")
app.config.update(
    SECRET_KEY=os.getenv("FLASK_SECRET_KEY") or secrets.token_hex(32),
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=os.getenv("SESSION_COOKIE_SECURE", "0") == "1",
    MAX_CONTENT_LENGTH=1024 * 1024,
)

BASE_DIR = Path(__file__).resolve().parent
DATABASE = BASE_DIR / "vulnstore.db"
UPLOAD_DIR = BASE_DIR / "uploads"
ALLOWED_FETCH_HOSTS = {
    host.strip().lower()
    for host in os.getenv("FETCH_ALLOWLIST", "example.com,www.example.com").split(",")
    if host.strip()
}


PRODUCTS = [
    ("Keyboard", "Mechanical keyboard with noisy blue switches.", 79.99),
    ("USB-C Hub", "Seven ports, questionable firmware, great demo prop.", 34.50),
    ("Webcam", "1080p camera for calls and security training.", 49.99),
    ("Sticker Pack", "Security-themed laptop stickers.", 4.99),
]

USERS = [
    ("alice", "Alice-Store-2026!", "Alice Customer", "alice@example.test", "user"),
    ("bob", "Bob-Orders-2026!", "Bob Buyer", "bob@example.test", "user"),
    ("admin", "Admin-Control-2026!", "Store Admin", "admin@example.test", "admin"),
]


def hash_password(password):
    return generate_password_hash(password, method="pbkdf2:sha256", salt_length=16)


def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DATABASE)
        g.db.row_factory = sqlite3.Row
    return g.db


@app.teardown_appcontext
def close_db(error):
    del error
    db = g.pop("db", None)
    if db is not None:
        db.close()


def seed_users():
    return [
        (username, hash_password(password), full_name, email, role)
        for username, password, full_name, email, role in USERS
    ]


def normalize_user_passwords(db):
    users = db.execute("SELECT id, password FROM users").fetchall()
    changed = False
    for user in users:
        stored_password = user["password"]
        if stored_password.startswith(("pbkdf2:", "scrypt:")):
            continue
        db.execute(
            "UPDATE users SET password = ? WHERE id = ?",
            (hash_password(stored_password), user["id"]),
        )
        changed = True
    if changed:
        db.commit()


def init_db():
    db = get_db()
    db.executescript(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
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
            seed_users(),
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

    normalize_user_passwords(db)


@app.before_request
def ensure_db():
    init_db()


@app.after_request
def set_security_headers(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; img-src 'self' https: data:; "
        "style-src 'self' 'unsafe-inline'; form-action 'self'; base-uri 'self'; frame-ancestors 'none'"
    )
    return response


def get_csrf_token():
    token = session.get("csrf_token")
    if not token:
        token = secrets.token_urlsafe(32)
        session["csrf_token"] = token
    return token


@app.context_processor
def inject_template_helpers():
    return {"csrf_token": get_csrf_token()}


def require_csrf():
    token = request.form.get("csrf_token", "")
    if not token or token != session.get("csrf_token"):
        abort(400, description="Invalid CSRF token")


def current_user():
    user_id = session.get("user_id")
    if not user_id:
        return None
    return get_db().execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()


def require_login():
    user = current_user()
    if user is None:
        return None
    return user


def require_admin():
    user = require_login()
    if user is None:
        return None
    if user["role"] != "admin":
        abort(403)
    return user


def is_valid_host(host):
    if not host or len(host) > 253 or ".." in host:
        return False
    allowed = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-.")
    return all(char in allowed for char in host)


def resolve_public_ips(hostname):
    addresses = {
        ipaddress.ip_address(result[4][0])
        for result in socket.getaddrinfo(hostname, None, type=socket.SOCK_STREAM)
    }
    for address in addresses:
        if (
            address.is_private
            or address.is_loopback
            or address.is_link_local
            or address.is_multicast
            or address.is_reserved
        ):
            raise ValueError("Blocked private or reserved address")
    return sorted(str(address) for address in addresses)


@app.route("/")
def index():
    products = get_db().execute("SELECT * FROM products").fetchall()
    return render_template("index.html", products=products, user=current_user())


@app.route("/login", methods=["GET", "POST"])
def login():
    error = None
    if request.method == "POST":
        require_csrf()
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        user = get_db().execute(
            "SELECT * FROM users WHERE username = ?",
            (username,),
        ).fetchone()
        if user and check_password_hash(user["password"], password):
            session.clear()
            session["user_id"] = user["id"]
            session["csrf_token"] = secrets.token_urlsafe(32)
            return redirect(url_for("account", user_id=user["id"]))
        error = "Invalid username or password"
    return render_template("login.html", error=error, user=current_user())


@app.route("/logout", methods=["POST"])
def logout():
    require_csrf()
    session.clear()
    return redirect(url_for("index"))


@app.route("/search")
def search():
    q = request.args.get("q", "").strip()
    products = get_db().execute(
        "SELECT * FROM products WHERE name LIKE ? OR description LIKE ?",
        (f"%{q}%", f"%{q}%"),
    ).fetchall()
    return render_template("search.html", q=q, products=products, user=current_user())


@app.route("/product/<int:product_id>", methods=["GET", "POST"])
def product(product_id):
    db = get_db()
    product_row = db.execute("SELECT * FROM products WHERE id = ?", (product_id,)).fetchone()
    if product_row is None:
        return "Product not found", 404

    if request.method == "POST":
        require_csrf()
        author = request.form.get("author", "anonymous").strip() or "anonymous"
        body = request.form.get("body", "").strip()
        if not body:
            return render_template(
                "product.html",
                product=product_row,
                reviews=db.execute(
                    "SELECT * FROM reviews WHERE product_id = ? ORDER BY id DESC",
                    (product_id,),
                ).fetchall(),
                user=current_user(),
                error="Review body is required.",
            )

        db.execute(
            "INSERT INTO reviews (product_id, author, body) VALUES (?, ?, ?)",
            (product_id, author[:80], body[:1000]),
        )
        db.commit()
        return redirect(url_for("product", product_id=product_id))

    reviews = db.execute(
        "SELECT * FROM reviews WHERE product_id = ? ORDER BY id DESC", (product_id,)
    ).fetchall()
    return render_template(
        "product.html",
        product=product_row,
        reviews=reviews,
        user=current_user(),
        error=None,
    )


@app.route("/account/<int:user_id>")
def account(user_id):
    viewer = require_login()
    if viewer is None:
        return redirect(url_for("login"))
    if viewer["role"] != "admin" and viewer["id"] != user_id:
        abort(403)

    user = get_db().execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
    if user is None:
        abort(404)
    orders = get_db().execute("SELECT * FROM orders WHERE user_id = ?", (user_id,)).fetchall()
    return render_template("account.html", account=user, orders=orders, user=viewer)


@app.route("/checkout", methods=["GET", "POST"])
def checkout():
    user = require_login()
    if user is None:
        return redirect(url_for("login"))

    db = get_db()
    message = None
    error = None
    products = db.execute("SELECT * FROM products ORDER BY name").fetchall()

    if request.method == "POST":
        require_csrf()
        address = request.form.get("address", "").strip()
        try:
            product_id = int(request.form.get("product_id", "0"))
        except ValueError:
            product_id = 0

        product_row = db.execute("SELECT * FROM products WHERE id = ?", (product_id,)).fetchone()
        if product_row is None:
            error = "Please choose a valid product."
        elif not address:
            error = "Shipping address is required."
        else:
            db.execute(
                "INSERT INTO orders (user_id, item, total, address) VALUES (?, ?, ?, ?)",
                (user["id"], product_row["name"], product_row["price"], address[:200]),
            )
            db.commit()
            message = "Order placed"

    return render_template(
        "checkout.html",
        message=message,
        error=error,
        products=products,
        user=user,
    )


@app.route("/admin")
def admin():
    user = require_admin()
    if user is None:
        return redirect(url_for("login"))
    users = get_db().execute("SELECT id, username, email, role FROM users").fetchall()
    return render_template("admin.html", users=users, user=user)


@app.route("/tools/ping")
def ping():
    host = request.args.get("host", "example.com").strip()
    if not is_valid_host(host):
        abort(400, description="Invalid hostname")

    try:
        addresses = resolve_public_ips(host)
    except (OSError, ValueError):
        abort(400, description="Unable to resolve host safely")

    output = "\n".join(addresses) if addresses else "No public addresses found."
    return render_template(
        "tool_result.html",
        title=f"Host lookup for {host}",
        output=output,
        user=current_user(),
    )


@app.route("/download")
def download():
    filename = request.args.get("file", "sample.txt").strip()
    if not filename or filename != Path(filename).name:
        abort(400, description="Invalid filename")
    return send_from_directory(UPLOAD_DIR, filename, as_attachment=False)


@app.route("/fetch-image")
def fetch_image():
    raw_url = request.args.get("url", "https://www.example.com").strip()
    parsed = urlparse(raw_url)
    hostname = (parsed.hostname or "").lower()
    if parsed.scheme != "https" or not hostname or parsed.username or parsed.password:
        abort(400, description="Only HTTPS URLs without credentials are allowed")
    if hostname not in ALLOWED_FETCH_HOSTS:
        abort(400, description="Host is not in the allowlist")

    try:
        resolve_public_ips(hostname)
        request_obj = urllib.request.Request(
            raw_url,
            headers={"User-Agent": "VulnStore/secure-fetch"},
        )
        with urllib.request.urlopen(request_obj, timeout=3) as response:
            body = response.read(5000)
            content_type = response.headers.get_content_type()
    except (OSError, ValueError, urllib.error.URLError):
        abort(502, description="Unable to fetch the requested resource")

    if not content_type.startswith(("image/", "text/")):
        abort(400, description="Unsupported content type")

    headers = {"Content-Type": content_type}
    if content_type.startswith("text/"):
        headers["Content-Type"] = f"{content_type}; charset=utf-8"
    return body, 200, headers


@app.route("/debug")
def debug():
    user = require_admin()
    if user is None:
        return redirect(url_for("login"))
    return jsonify(
        {
            "status": "ok",
            "database": DATABASE.name,
            "current_user": user["username"],
        }
    )


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False)
