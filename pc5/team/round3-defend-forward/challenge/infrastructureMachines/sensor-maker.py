#!/usr/bin/python3

# Copyright 2024 Carnegie Mellon University.
# Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
# root or contact permission@sei.cmu.edu for full terms.


from flask import Flask, request, jsonify
from flask_httpauth import HTTPBasicAuth
import sqlite3

app = Flask(__name__)
auth = HTTPBasicAuth()

# Define a simple user database (for demonstration purposes).
users = {
    'username': 'password',
}

# Create a decorator for protected routes
@auth.verify_password
def verify_password(username, password):
    if username in users and users[username] == password:
        return username

# Route to access the SQLite database
@app.route('/', methods=['GET'])
@auth.login_required
def get_database():
    # Connect to the SQLite database
    conn = sqlite3.connect('/home/user/pii_database.db')
    cursor = conn.cursor()

    # Execute SQL queries here (e.g., SELECT, INSERT, UPDATE, DELETE)

    # Close the database connection
    conn.close()

    return 'Database accessed successfully'

@app.route('/query', methods=['GET'])
@auth.login_required
def execute_query():
    query = request.args.get('query')
    if query:
        # Connect to the SQLite database
        conn = sqlite3.connect('/home/user/pii_database.db')
        cursor = conn.cursor()

        # Execute the user's query
        cursor.execute(query)
        results = cursor.fetchall()

        # Close the database connection
        conn.close()

        # Return the query results as JSON
        return jsonify({"results": results})
    else:
        return jsonify({"error": "Query parameter is missing"})

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5001, debug=True)
