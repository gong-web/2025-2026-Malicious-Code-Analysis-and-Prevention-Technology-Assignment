import sqlite3

conn = sqlite3.connect('data.sqlite')
cursor = conn.cursor()

print('=== rules table ===')
cursor.execute('PRAGMA table_info(rules)')
for row in cursor.fetchall():
    print(row)

print('\n=== samples table ===')
cursor.execute('PRAGMA table_info(samples)')
for row in cursor.fetchall():
    print(row)

print('\n=== scans table ===')
cursor.execute('PRAGMA table_info(scans)')
for row in cursor.fetchall():
    print(row)

print('\n=== Sample Rules Data ===')
cursor.execute('SELECT id, name, active FROM rules LIMIT 5')
for row in cursor.fetchall():
    print(f'ID={row[0]}, Name={row[1]}, Active={row[2]}')

print('\n=== Sample Scans Data ===')
cursor.execute('SELECT id, filename, status FROM scans LIMIT 5')
for row in cursor.fetchall():
    print(f'ID={row[0]}, Filename={row[1]}, Status={row[2]}')

conn.close()
