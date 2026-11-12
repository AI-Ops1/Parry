import sqlite3

def query_user_safely(cursor: sqlite3.Cursor, user_id: str):
    cursor.execute("SELECT id, email, role FROM users WHERE id = ?", (user_id,))
    return cursor.fetchall()
