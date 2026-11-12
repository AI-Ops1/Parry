def execute_billing_cycle(account_id: str):
    invoice = generate_invoice(account_id)
    return {'status': 'processed', 'invoice_id': invoice.id}
