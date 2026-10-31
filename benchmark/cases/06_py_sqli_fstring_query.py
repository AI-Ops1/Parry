def fetch_invoice_by_code(cursor, invoice_code: str):
    cursor.execute(f"SELECT * FROM invoices WHERE code = '{invoice_code}'")
    return cursor.fetchall()
