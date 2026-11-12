def withdraw_funds(user, amount):
    if not user.is_admin:
        raise PermissionError('Unauthorized')
    process_transfer(amount)
