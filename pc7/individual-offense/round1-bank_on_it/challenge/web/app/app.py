import hashlib
import pymysql
from flask import Flask, jsonify, request, redirect, url_for,  render_template, make_response
from tinydb import TinyDB, Query
import os
import logging
import time
from grader import check_transfers, DB_CONFIG 

logging.basicConfig(level=logging.INFO)

def get_db_connection():
    return pymysql.connect(
        host='database',           # match Docker service name
        user='user',
        password='password',
        database='trustfall',
        cursorclass=pymysql.cursors.DictCursor
    )

class TokenConfigError(Exception):
    """Raised when the token environment variable is missing or invalid."""


class DBSeedError(Exception):
    """Raised when we fail to update Bob's account in the database."""


def inject_token_account_name() -> None:
    token = os.environ.get("tokenBobAccount")
    if not token:
        raise TokenConfigError("The environment variable 'tokenBobAccount' has not been set")

    try:
        conn = get_db_connection()
        try:
            with conn.cursor() as cursor:
                cursor.execute("UPDATE accounts SET name = %s WHERE id = 4", (token,))
            conn.commit()
        finally:
            conn.close()

        logging.info("Account name for Bob's account updated to: %s", token)
    except Exception as exc:
        logging.error("Error updating token in Bob's account: %s", exc, exc_info=True)
        raise DBSeedError("Failed to update Bob's account in the database") from exc


app = Flask(__name__)

MAX_RETRIES = 10
RETRY_DELAY_SECONDS = 10

attempt = 0
while True:
    try:
        inject_token_account_name()
        break  # success
    except TokenConfigError as exc:
        logging.critical("Fatal configuration error: %s", exc)
        raise  # hard fail; app should not start
    except DBSeedError as exc:
        attempt += 1
        if attempt >= MAX_RETRIES:
            logging.critical(
                "Failed to seed Bob's token after %s attempts. Last error: %s",
                MAX_RETRIES,
                exc,
            )
            raise
        logging.warning(
            "Database not ready or seeding failed (attempt %s/%s). Retrying in %s seconds...",
            attempt,
            MAX_RETRIES,
            RETRY_DELAY_SECONDS,
        )
        time.sleep(RETRY_DELAY_SECONDS)

db = TinyDB('/tmp/session_store.json')
session_table = db.table('sessions')
meta_table = db.table('meta')

# Initialize counter and seed session if not present
if not meta_table.contains(Query().key == 'counter'):
    logging.info("Injecting admin session as MD5(1)")
    meta_table.insert({'key': 'counter', 'value': 1})
    session_table.insert({
        'sid': hashlib.md5(b'1').hexdigest(),
        'uid': -1
    })

def get_next_session_id():
    entry = meta_table.get(Query().key == 'counter')
    count = entry['value'] + 1
    session_id = hashlib.md5(str(count).encode()).hexdigest()
    meta_table.update({'value': count}, Query().key == 'counter')
    logging.info(f"Next id: {session_id}")
    return session_id, count

def get_logged_in_user():
    session_id = request.cookies.get('session_id')
    Session = Query()
    result = session_table.get(Session.sid == session_id)
    if not result:
        logging.info(f"Could not find session for {session_id}")
        return None
    
    if result['uid'] == -1:
        logging.info("Admin session found")
        return -1
    
    conn = get_db_connection()
    with conn.cursor() as cursor:
        cursor.execute(f"SELECT * FROM users WHERE id = {result['uid']}")
        user = cursor.fetchone()
    conn.close()
    
    logging.info(f"User login: {result['uid']} ({session_id})")
    
    return user

@app.route("/grade/account-drain")
def grade_account_drain():
    success, message = check_transfers(
        db_config=DB_CONFIG,
        token_env_var="tokenAccountDrain"
    )
    return jsonify({"success": success, "message": message}), (200 if success else 400)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        password_hash = hashlib.sha1(password.encode()).hexdigest()

        query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password_hash}'"
        try:
            conn = get_db_connection()
            with conn.cursor() as cursor:
                cursor.execute(query)
                user = cursor.fetchone()
            conn.close()
        except Exception as e:
            logging.warning(f"Potentially acceptable database error: {e}")
            return render_template('500.html', query=query, error=str(e)), 500

        if user:
            session_id, _ = get_next_session_id()
            session_table.insert({'sid': session_id, 'uid': user['id']})

            resp = make_response(redirect(url_for('dashboard')))
            resp.set_cookie('session_id', session_id)
            return resp

        return render_template('login.html', error='Invalid credentials')

    return render_template('login.html')

@app.route('/logout')
def logout():
    session_id = request.cookies.get('session_id')
    if session_id:
        Session = Query()
        session_table.remove(Session.sid == session_id)
        logging.info(f"Session logout: {session_id}")

    resp = make_response(redirect(url_for('login')))
    resp.set_cookie('session_id', '', expires=0)
    return resp

@app.route('/accounts')
def view_accounts():
    user = get_logged_in_user()
    if not user:
        return redirect(url_for('login'))
    
    if user == -1:
        return redirect(url_for('admin'))

    conn = get_db_connection()
    with conn.cursor() as cursor:
        cursor.execute(f"SELECT * FROM accounts WHERE user_id = {user["id"]}")
        accounts = cursor.fetchall()
    conn.close()

    accounts_by_type = {}
    for acc in accounts:
        acc_type = acc['type']
        accounts_by_type.setdefault(acc_type, []).append(acc)

    return render_template('accounts.html', user=user, accounts_by_type=accounts_by_type)

@app.route('/transfers')
def view_transfers():
    user = get_logged_in_user()
    if not user:
        return redirect(url_for('login'))

    if user == -1:
        return redirect(url_for('admin'))

    conn = get_db_connection()
    with conn.cursor() as cursor:
        query = f"""
            SELECT t.amount, t.timestamp,
                t.from_account_number AS from_account,
                t.to_account_number AS to_account
            FROM transfers t
            JOIN accounts a1 ON t.from_account_number = a1.account_number
            JOIN accounts a2 ON t.to_account_number = a2.account_number
            WHERE a1.user_id = {user["id"]} OR a2.user_id = {user["id"]}
            ORDER BY t.timestamp DESC
        """
        cursor.execute(query)
        transfers = cursor.fetchall()
    conn.close()

    return render_template('transfers.html', user=user, transfers=transfers)

@app.route('/accounts/new', methods=['GET', 'POST'])
def create_account():
    user = get_logged_in_user()
    if not user:
        return redirect(url_for('login'))
    
    if user == -1:
        return redirect(url_for('admin'))

    if request.method == 'POST':
        name = request.form.get('name')
        acc_type = request.form.get('type')
        account_number = os.urandom(4).hex().upper()
        
        # Ensure account number is unique
        conn = get_db_connection()
        with conn.cursor() as cursor:
            while True:
                account_number = os.urandom(4).hex().upper()
                cursor.execute(f"SELECT 1 FROM accounts WHERE account_number = '{account_number}'")
                if not cursor.fetchone():
                    break

        query = f"INSERT INTO accounts (user_id, name, type, account_number, balance) VALUES ({user["id"]}, '{name}', '{acc_type}', '{account_number}', 0.00)"
        try:
            conn = get_db_connection()
            with conn.cursor() as cursor:
                cursor.execute(query)
                conn.commit()
            conn.close()
            
            logging.info(f"New {acc_type} account {account_number} ({name}) for {user['id']}")
        except Exception as e:
            logging.warning(f"Potentially acceptable database error: {e}")
            return render_template('500.html', user=user,  query=query, error=str(e)), 500

        return redirect(url_for('view_accounts'))

    return render_template('newAccount.html', user=user)

@app.route('/transfers/new', methods=['GET', 'POST'])
def create_transfer():
    user = get_logged_in_user()
    if not user:
        return redirect(url_for('login'))
    
    if user == -1:
        return redirect(url_for('admin'))
    
    conn = get_db_connection()

    with conn.cursor() as cursor:
        cursor.execute(f"SELECT * FROM accounts WHERE user_id = {user["id"]}")
        accounts = cursor.fetchall()

    if request.method == 'POST':
        from_account = request.form.get('from_account')
        to_account = request.form.get('to_account')
        amount = request.form.get('amount')

        if from_account == to_account:
            conn.close()
            return render_template('newTransfer.html', user=user, accounts=accounts, error='Cannot transfer to the same account.')

        account_numbers = {str(acc['account_number']) for acc in accounts}

        if from_account not in account_numbers or to_account not in account_numbers:
            conn.close()
            return render_template('newTransfer.html', user=user, accounts=accounts, error='You can only transfer between your own accounts.')

        query = f"INSERT INTO transfers (from_account_number, to_account_number, amount) VALUES ('{from_account}', '{to_account}', {amount})"

        try:
            with conn.cursor() as cursor:
                cursor.execute(query)
                conn.commit()
            conn.close()
            logging.info(f"New transfer from {from_account} {to_account} for {amount}")
        except Exception as e:
            logging.warning(f"Potentially acceptable database error: {e}")
            return render_template('500.html', user=user, query=query, error=str(e)), 500

        return redirect(url_for('view_transfers'))

    conn.close()
    return render_template('newTransfer.html', user=user, accounts=accounts)

@app.route('/dashboard')
def dashboard():
    user = get_logged_in_user()
    if not user:
        return redirect(url_for('login'))
    
    if user == -1:
        return redirect(url_for('admin'))

    return render_template('dashboard.html', user=user)

@app.route('/admin')
def admin():
    user = get_logged_in_user()
    if not user:
        return redirect(url_for('login'))
    
    if user != -1:
        return redirect(url_for('login'))

    return render_template('admin.html', user=user)

@app.route('/')
def index():
    user = get_logged_in_user()
    
    if user == -1:
        return redirect(url_for('admin'))
    
    return render_template('index.html', user=user)

if __name__ == '__main__':
    app.run()