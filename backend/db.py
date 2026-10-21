
import sqlite3
import os

DB_DIR = os.path.join(os.path.dirname(__file__), "../data")
DB_PATH = os.path.join(DB_DIR, "trulens.db")

def init_db():
    """Initialize the SQLite database and create necessary tables."""
    os.makedirs(DB_DIR, exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    # 1. Blocklist table for known phishing/scam domains and URLs
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS blocklist (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            url_or_domain TEXT UNIQUE NOT NULL,
            source TEXT
        )
    """)

    # 2. API cache table to avoid redundant external calls
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS api_cache (
            url TEXT PRIMARY KEY,
            verdict TEXT,
            details TEXT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    """)

    # 3. Local feedback table for incorrect verdict reports (stores redacted info only)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS feedback (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            redacted_input TEXT,
            predicted_verdict TEXT,
            user_label TEXT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    """)

    conn.commit()
    conn.close()

def check_blocklist(url_or_domain: str) -> bool:
    """Check if a URL or domain exists in the local blocklist database."""
    if not os.path.exists(DB_PATH):
        init_db()
    
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    # Check exact match or domain match
    cursor.execute("SELECT 1 FROM blocklist WHERE ? LIKE '%' || url_or_domain || '%'", (url_or_domain,))
    match = cursor.fetchone()
    conn.close()
    return match is not None

def add_to_blocklist(url_or_domain: str, source: str = "manual"):
    """Add a domain/URL to the local SQLite blocklist."""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    try:
        cursor.execute("INSERT OR IGNORE INTO blocklist (url_or_domain, source) VALUES (?, ?)", (url_or_domain.lower(), source))
        conn.commit()
    except Exception:
        pass
    finally:
        conn.close()

def save_feedback(redacted_input: str, predicted_verdict: str, user_label: str):
    """Save user feedback securely (redacted content only)."""
    if not os.path.exists(DB_PATH):
        init_db()
        
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute(
        "INSERT INTO feedback (redacted_input, predicted_verdict, user_label) VALUES (?, ?, ?)",
        (redacted_input, predicted_verdict, user_label)
    )
    conn.commit()
    conn.close()

# Initialize DB on module import
init_db()
