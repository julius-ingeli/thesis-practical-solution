from fastapi import FastAPI, Query
import sqlite3, os, uvicorn

app = FastAPI()

def init_db():
    conn = sqlite3.connect("data.db")
    cursor = conn.cursor()
    cursor.execute("CREATE TABLE IF NOT EXISTS items (id INTEGER PRIMARY KEY, name TEXT)")
    cursor.execute("INSERT OR IGNORE INTO items (id, name) VALUES (1, 'Secret-Gadget')")
    conn.commit()
    conn.close()

init_db()

# --- VULNERABILITY 1: HARDCODED SECRET (For Secret Scanning/Gitleaks) ---
# In a real app, this should be an environment variable.
AWS_SECRET_KEY = "AKIAIMNO78987EXAMPLE/SECRET/KEY/12345"

@app.get("/")
def home():
    return {"message": "Secure-Store API is running"}

# --- VULNERABILITY 2: SQL INJECTION (For SAST/Semgrep) ---
@app.get("/items/")
def read_items(name: str = Query(...)):
    # DANGEROUS: String formatting in SQL queries allows SQL Injection
    conn = sqlite3.connect("data.db")
    cursor = conn.cursor()
    query = f"SELECT * FROM items WHERE name = '{name}'" 
    cursor.execute(query)
    return {"results": cursor.fetchall()}

# --- VULNERABILITY 3: COMMAND INJECTION (For SAST/DAST/ZAP) ---
@app.get("/ping")
def ping_server(ip: str):
    # DANGEROUS: os.system with user input allows Command Injection
    # Example: /ping?ip=127.0.0.1; ls -la
    response = os.system(f"ping -c 1 {ip}")
    return {"status": "executed", "code": response}

if __name__ == "__main__":
    uvicorn.run(app, host="127.0.0.1", port=8000)