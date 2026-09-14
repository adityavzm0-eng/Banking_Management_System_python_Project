from flask import Flask, render_template, request, redirect, session, flash
import mysql.connector
from decimal import Decimal, InvalidOperation
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)

# Secret key for login session
app.secret_key = "mybank_secret_key"

# MySQL connection
db = mysql.connector.connect(
    host="localhost",
    user="root",
    password="Siddhu@143",
    database="banking_syste"
)


@app.route("/")
def home():
    return render_template("index.html")

# ================= REGISTER =================

@app.route("/register", methods=["GET", "POST"])
def register():

    if request.method == "POST":

        full_name = request.form["full_name"]
        email = request.form["email"]
        phone = request.form["phone"]
        account_number = request.form["account_number"]
        password = request.form["password"]
        confirm_password = request.form["confirm_password"]

        if password != confirm_password:
            flash("Passwords do not match.", "error")
            return redirect("/register")

        hashed_password = generate_password_hash(password)

        cursor = db.cursor()

        sql = """
        INSERT INTO users
        (full_name, email, phone, account_number, password)
        VALUES (%s, %s, %s, %s, %s)
        """

        values = (
            full_name,
            email,
            phone,
            account_number,
            hashed_password
        )

        try:
            cursor.execute(sql, values)
            db.commit()
        finally:
            cursor.close()

        flash("Account created successfully. Please log in.", "success")
        return redirect("/login")


    return render_template("register.html")


# ================= LOGIN =================

@app.route("/login", methods=["GET", "POST"])
def login():

    if request.method == "POST":

        email = request.form["email"].strip()
        password = request.form["password"]

        cursor = db.cursor(dictionary=True)

        sql = """
        SELECT * FROM users
        WHERE email = %s
        """

        try:
            cursor.execute(sql, (email,))
            user = cursor.fetchone()
        finally:
            cursor.close()

        valid_password = False
        legacy_password = False

        if user:
            stored_password = user["password"]

            if stored_password.startswith(("scrypt:", "pbkdf2:")):
                valid_password = check_password_hash(
                    stored_password,
                    password
                )
            else:
                # Support accounts created before password hashing was added.
                valid_password = user["password"] == password
                legacy_password = valid_password

        if user and valid_password:

            if legacy_password:
                upgrade_cursor = db.cursor()
                upgrade_cursor.execute(
                    "UPDATE users SET password = %s WHERE id = %s",
                    (
                        generate_password_hash(password),
                        user["id"]
                    )
                )
                db.commit()
                upgrade_cursor.close()

            session["user_id"] = user["id"]
            session["full_name"] = user["full_name"]

            flash("Login successful.", "success")
            return redirect("/dashboard")

        else:
            session.pop("_flashes", None)
            flash("Email or password is incorrect. Please try again.", "error")
            return redirect("/login")


    return render_template("login.html")


# ================= DASHBOARD =================

@app.route("/dashboard")
def dashboard():

    if "user_id" not in session:
        return redirect("/login")

    cursor = db.cursor(dictionary=True)

    sql = """
    SELECT full_name, balance
    FROM users
    WHERE id = %s
    """

    try:
        cursor.execute(sql, (session["user_id"],))
        user = cursor.fetchone()
    finally:
        cursor.close()

    if user is None:
        session.clear()
        return redirect("/login")

    return render_template(
        "dashboard.html",
        full_name=user["full_name"],
        balance=user["balance"]
    )


# ================= PROFILE =================

@app.route("/profile")
def profile():

    if "user_id" not in session:
        return redirect("/login")

    cursor = db.cursor(dictionary=True)

    sql = """
    SELECT
        full_name,
        email,
        phone,
        account_number,
        balance,
        created_at
    FROM users
    WHERE id = %s
    """

    try:
        cursor.execute(sql, (session["user_id"],))
        user = cursor.fetchone()
    finally:
        cursor.close()

    if user is None:
        session.clear()
        flash("User account not found. Please login again.", "error")
        return redirect("/login")

    return render_template("profile.html", user=user)

# ================= LOGOUT =================

@app.route("/logout")
def logout():

    session.clear()

    flash("You have been logged out.", "success")
    return redirect("/login")

# ================= DEPOSITE =================
@app.route("/deposit", methods=["GET", "POST"])
def deposit():
    if "user_id" not in session:
        return redirect("/login")

    if request.method == "POST":
        try:
            amount = Decimal(request.form["amount"])
        except (InvalidOperation, TypeError):
            return "Invalid amount", 400

        if amount <= 0:
            return "Invalid amount", 400

        cursor = db.cursor()

        # Update balance
        sql = """
        UPDATE users
        SET balance = COALESCE(balance, 0) + %s
        WHERE id = %s
        """

        try:
            cursor.execute(sql, (amount, session["user_id"]))

            transaction_sql = """
            INSERT INTO transactions
            (user_id, transaction_type, amount, description)
            VALUES (%s, %s, %s, %s)
            """

            cursor.execute(
                transaction_sql,
                (session["user_id"], "Deposit", amount, "Money deposited")
            )
            db.commit()
        except Exception:
            db.rollback()
            raise
        finally:
            cursor.close()

        return redirect("/dashboard")

    return render_template("deposit.html")


# ================= WITHDRAW =================

@app.route("/withdraw", methods=["GET", "POST"])
def withdraw():
    if "user_id" not in session:
        return redirect("/login")

    if request.method == "POST":
        try:
            amount = Decimal(request.form["amount"])
        except (InvalidOperation, TypeError):
            return "Invalid amount", 400

        if amount <= 0:
            return "Invalid amount", 400

        cursor = db.cursor(dictionary=True)

        try:
            cursor.execute(
                """
                UPDATE users
                SET balance = COALESCE(balance, 0) - %s
                WHERE id = %s AND COALESCE(balance, 0) >= %s
                """,
                (amount, session["user_id"], amount)
            )

            if cursor.rowcount != 1:
                db.rollback()
                return "Insufficient balance", 400

            cursor.execute(
                """
                INSERT INTO transactions
                (user_id, transaction_type, amount, description)
                VALUES (%s, %s, %s, %s)
                """,
                (session["user_id"], "Withdraw", amount, "Money withdrawn")
            )
            db.commit()
        except Exception:
            db.rollback()
            raise
        finally:
            cursor.close()

        return redirect("/dashboard")

    return render_template("withdraw.html")


# ================= TRANSFER AND TRANSACTIONS =================
@app.route("/transfer", methods=["GET", "POST"])
def transfer():
    if "user_id" not in session:
        return redirect("/login")

    if request.method == "POST":
        receiver_account = request.form.get("account_number", "").strip()

        try:
            amount = Decimal(request.form["amount"])
        except (InvalidOperation, TypeError):
            return "Invalid amount", 400

        if not receiver_account or amount <= 0:
            return "Invalid transfer details", 400

        cursor = db.cursor(dictionary=True)

        # Get sender
        cursor.execute(
            "SELECT id, balance, account_number FROM users WHERE id = %s FOR UPDATE",
            (session["user_id"],)
        )

        sender = cursor.fetchone()

        if sender is None:
            db.rollback()
            cursor.close()
            session.clear()
            return redirect("/login")

        # Get receiver
        cursor.execute(
            "SELECT id, account_number FROM users WHERE account_number = %s FOR UPDATE",
            (receiver_account,)
        )

        receiver = cursor.fetchone()

        # Check receiver
        if receiver is None:
            db.rollback()
            cursor.close()
            return "Receiver account not found", 404

        # Prevent self transfer
        if receiver["id"] == session["user_id"]:
            db.rollback()
            cursor.close()
            return "You cannot transfer money to your own account", 400

        # Check balance
        if amount > (sender["balance"] or Decimal("0")):
            db.rollback()
            cursor.close()
            return "Insufficient balance", 400

        # Deduct money from sender
        cursor.execute(
            """
            UPDATE users
            SET balance = balance - %s
            WHERE id = %s
            """,
            (amount, session["user_id"])
        )

        # Add money to receiver
        cursor.execute(
            """
            UPDATE users
            SET balance = balance + %s
            WHERE id = %s
            """,
            (amount, receiver["id"])
        )

        # Save sender transaction
        cursor.execute(
            """
            INSERT INTO transactions
            (user_id, transaction_type, amount, description)
            VALUES (%s, %s, %s, %s)
            """,
            (
                session["user_id"],
                "Transfer Sent",
                amount,
                "Money transferred to account " + receiver_account
            )
        )

        # Save receiver transaction
        cursor.execute(
            """
            INSERT INTO transactions
            (user_id, transaction_type, amount, description)
            VALUES (%s, %s, %s, %s)
            """,
            (
                receiver["id"],
                "Transfer Received",
                amount,
                "Money received from account " + sender["account_number"]
            )
        )

        try:
            db.commit()
        except Exception:
            db.rollback()
            raise
        finally:
            cursor.close()

        return redirect("/dashboard")

    return render_template("transfer.html")

@app.route("/transactions")
def transactions():

    if "user_id" not in session:
        return redirect("/login")

    cursor = db.cursor(dictionary=True)

    sql = """
    SELECT id, transaction_type, amount, description, created_at
    FROM transactions
    WHERE user_id = %s
    ORDER BY created_at DESC
    """

    try:
        cursor.execute(sql, (session["user_id"],))
        transactions = cursor.fetchall()
    finally:
        cursor.close()

    return render_template(
        "transactions.html",
        transactions=transactions
        )

if __name__ == "__main__":
    app.run(debug=True)
