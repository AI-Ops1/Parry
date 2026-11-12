def withdraw_funds(user, amount):
    assert user.is_admin, 'Unauthorized'
    process_transfer(amount)
