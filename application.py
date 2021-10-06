import os

from cs50 import SQL
from flask import Flask, flash, jsonify, redirect, render_template, request, session
from flask_session import Session
from tempfile import mkdtemp
from werkzeug.exceptions import default_exceptions, HTTPException, InternalServerError
from werkzeug.security import check_password_hash, generate_password_hash

from helpers import apology, login_required, lookup, usd

# Configure application
app = Flask(__name__)

# Ensure templates are auto-reloaded
app.config["TEMPLATES_AUTO_RELOAD"] = True

# Ensure responses aren't cached
@app.after_request
def after_request(response):
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response

# Custom filter
app.jinja_env.filters["usd"] = usd

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_FILE_DIR"] = mkdtemp()
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///finance.db")

# Make sure API key is set
if not os.environ.get("API_KEY"):
    raise RuntimeError("API_KEY not set")


@app.route("/")
@login_required
def index():
    """Show portfolio of stocks"""

    rows = db.execute("SELECT * FROM stock WHERE user_id=:user_id", user_id=session["user_id"])
    total_assets = 0
    for row in rows:
        stock = lookup(row["symbol"])
        row["name"] = stock["name"]
        row["price"] = stock["price"]
        total_assets += row["shares"] * row["price"]
    cash = db.execute("SELECT cash FROM users WHERE id=:user_id", user_id=session["user_id"])
    return render_template("index.html", rows=rows, cash=cash[0]['cash'], total=total_assets)

@app.route("/account", methods=["GET", "POST"])
@login_required
def account():
    """Account Settings"""
    if request.method == "POST":

        # Retrieve user details for current user
        rows = db.execute("SELECT * FROM users WHERE id=:user_id",
                          user_id=session["user_id"])

        # Ensure password is correct
        if len(rows) != 1 or not check_password_hash(rows[0]["hash"], request.form.get("old-password")):
            return apology("invalid password", 403)
        # Ensure new password and confirmation match
        else:
            if request.form.get("new-password") != request.form.get("confirmation"):
                return apology("passwords must match", 403)
            # Change user password
            else:
                password = generate_password_hash(request.form.get("new-password"))
                db.execute("UPDATE users SET hash=:password WHERE id=:user_id", password=password, user_id=session["user_id"])

        return redirect("/")
    else:
        return render_template("account.html")

@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    """Buy shares of stock"""

    if request.method == "POST":

        # Store symbol & number of shares in variables
        symbol = request.form.get("symbol")
        shares = int(request.form.get("shares"))

        # Check for correct user input
        if not symbol:
            return apology("must provide symbol")
        elif not shares or shares < 1:
            return apology("must buy at least one share")

        # Lookup stock
        stock = lookup(symbol)

        # Check stock exists
        if stock == None:
            return apology("stock does not exist")
        # Purchase stock and write data to finance.db tables
        else:
            cash = db.execute("SELECT cash FROM users WHERE id = :user_id", user_id=session["user_id"])
            print(cash[0]['cash'])
            if cash[0]['cash'] < stock["price"] * shares:
                return apology("cash not found", 404)
            else:
                db.execute("INSERT INTO transactions (timestamp, user_id, symbol, shares, price) VALUES (CURRENT_TIMESTAMP, :user, :symbol, :shares, :price)", user=session["user_id"], symbol=stock["symbol"], shares=shares, price=stock["price"])
                cash[0]['cash'] = cash[0]['cash'] - stock["price"] * shares
                db.execute("UPDATE users SET cash=:cash WHERE id = :user_id", cash=cash[0]['cash'], user_id=session["user_id"])
                rows = db.execute("SELECT * FROM stock WHERE user_id=:user_id AND symbol=:symbol", user_id=session["user_id"], symbol=symbol.upper())
                print(rows)
                if not rows:
                    db.execute("INSERT INTO stock (user_id, symbol, shares) VALUES (:user_id, :symbol, :shares)", user_id=session["user_id"], symbol=stock["symbol"], shares=shares)
                else:
                    current_shares = db.execute("SELECT shares FROM stock WHERE user_id=:user_id AND symbol=:symbol", user_id=session["user_id"], symbol=stock["symbol"])
                    current_shares[0]['shares'] = current_shares[0]['shares'] + shares
                    db.execute("UPDATE stock SET shares=:shares WHERE user_id=:user_id AND id IN (SELECT id FROM stock WHERE symbol=:symbol AND user_id=:user_id)", shares=current_shares[0]['shares'], user_id=session["user_id"], symbol=stock["symbol"])

        return redirect("/")

    else:
        return render_template("buy.html")


@app.route("/history")
@login_required
def history():
    """Show history of transactions"""

    rows = db.execute("SELECT * FROM transactions WHERE user_id=:user_id", user_id=session["user_id"])
    return render_template("history.html", rows=rows)


@app.route("/login", methods=["GET", "POST"])
def login():
    """Log user in"""

    # Forget any user_id
    session.clear()

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        username = request.form.get("username")

        # Ensure username was submitted
        if not username:
            return apology("must provide username", 403)

        # Ensure password was submitted
        elif not request.form.get("password"):
            return apology("must provide password", 403)

        # Query database for username
        rows = db.execute("SELECT * FROM users WHERE username = :username",
                          username=username)

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(rows[0]["hash"], request.form.get("password")):
            return apology("invalid username and/or password", 403)

        # Remember which user has logged in
        session["user_id"] = rows[0]["id"]

        # Redirect user to home page
        return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("login.html")


@app.route("/logout")
def logout():
    """Log user out"""

    # Forget any user_id
    session.clear()

    # Redirect user to login form
    return redirect("/")


@app.route("/quote", methods=["GET", "POST"])
@login_required
def quote():
    """Get stock quote."""

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        # Get user entered symbol
        symbol = request.form.get("symbol")

        # Check for symbol
        if not symbol:
            return apology("must provide symbol")

        # Look up stock details from IEX
        stock = lookup(symbol)

        if stock == None:
            return apology("stock does not exist")
        else:
            return render_template("quoted.html", name=stock["name"], symbol=stock["symbol"], price=stock["price"])
    else:
        return render_template("quote.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""

     # Forget any user_id
    session.clear()

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        # Store user registration details in variables
        username = request.form.get("username")
        password = generate_password_hash(request.form.get("password"))
        confirmation = generate_password_hash(request.form.get("confirmation"))

        # Ensure username was submitted
        if not username:
            return apology("must provide username", 403)

        # Ensure password was submitted
        elif not password:
            return apology("must provide password", 403)

        # Ensure password and confirmation match
        elif request.form.get("password") != request.form.get("confirmation"):
            return apology("passwords must match", 403)

        # Query database for username
        rows = db.execute("SELECT * FROM users WHERE username = :username",
                          username=username)

        # Ensure username is unique
        if len(rows) != 0:
            return apology("username is already in use", 403)

        # If all tests pass, insert user into users table in finance database
        db.execute("INSERT INTO users (username, hash) VALUES (:username, :pwrd)", username=username, pwrd=password)

        # Query database for user_id
        rows = db.execute("SELECT * FROM users WHERE username = :username",
                          username=username)

        # Remember which user has logged in
        session["user_id"] = rows[0]["id"]

        # Return user to index page
        return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("register.html")


@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    """Sell shares of stock"""

    if request.method == "POST":

        symbol = request.form.get("symbol")
        shares = int(request.form.get("shares"))

        if not symbol:
            return apology("must select which stock to sell")
        elif not shares or int(shares) < 1:
            return apology("must sell at least one share")

        holdings = db.execute("SELECT shares FROM stock WHERE user_id=:user_id AND symbol=:symbol", user_id=session["user_id"], symbol=symbol)
        print(holdings)
        if holdings[0]['shares'] < shares:
            return apology("you can't sell what you don't have")
        else:
            cash = db.execute("SELECT cash FROM users WHERE id = :user_id", user_id=session["user_id"])
            stock = lookup(symbol)
            db.execute("INSERT INTO transactions (timestamp, user_id, symbol, shares, price) VALUES (CURRENT_TIMESTAMP, :user, :symbol, :shares, :price)", user=session["user_id"], symbol=stock["symbol"], shares=shares * -1, price=stock["price"])
            cash[0]['cash'] = cash[0]['cash'] + stock["price"] * shares
            db.execute("UPDATE users SET cash=:cash WHERE id = :user_id", cash=cash[0]['cash'], user_id=session["user_id"])
            current_shares = db.execute("SELECT shares FROM stock WHERE user_id=:user_id AND symbol=:symbol", user_id=session["user_id"], symbol=stock["symbol"])
            current_shares[0]['shares'] = current_shares[0]['shares'] - shares
            db.execute("UPDATE stock SET shares=:shares WHERE user_id=:user_id AND id IN (SELECT id FROM stock WHERE symbol=:symbol AND user_id=:user_id)", shares=current_shares[0]['shares'], user_id=session["user_id"], symbol=stock["symbol"])
            if current_shares[0]['shares'] == 0:
                db.execute("DELETE FROM stock WHERE symbol=:symbol AND user_id=:user_id", symbol=symbol, user_id=session["user_id"])


        return redirect("/")

    else:
        rows = db.execute("SELECT symbol FROM stock WHERE user_id=:user_id", user_id=session["user_id"])
        return render_template("sell.html", rows=rows)


def errorhandler(e):
    """Handle error"""
    if not isinstance(e, HTTPException):
        e = InternalServerError()
    return apology(e.name, e.code)


# Listen for errors
for code in default_exceptions:
    app.errorhandler(code)(errorhandler)
