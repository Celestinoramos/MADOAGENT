user_id = input('id: ')
cursor.execute("SELECT * FROM users WHERE id = " + user_id)
