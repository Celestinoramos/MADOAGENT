user_id = input('id: ')
query = "SELECT * FROM users WHERE id = " + user_id
cursor.execute(query)
