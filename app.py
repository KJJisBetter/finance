import os

from cs50 import SQL # type: ignore
from flask import Flask, flash, redirect, render_template, request, session # type: ignore
from flask_session import Session
from werkzeug.security import check_password_hash, generate_password_hash # type: ignore

from helpers import apology, login_required, lookup, usd

# ! I could not figure out
# :( buy handles valid purchase
#     expected to find "112.00" in page, but it wasn't found
# ! I have no idea what it means at all.

# Configure application
app = Flask(__name__)

# Custom filter
app.jinja_env.filters["usd"] = usd

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///finance.db")


@app.after_request
def after_request(response):
    """Ensure responses aren't cached"""
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response


@app.route("/")
@login_required
def index():
    user_info = db.execute("SELECT * FROM users WHERE id = :user_id", user_id=session["user_id"])
    portfolio = db.execute("SELECT * FROM portfolio WHERE user_id = :user_id", user_id=session["user_id"])

    total_value = 0
    for item in portfolio:
        item["price"] = lookup(item["symbol"])["price"]
        item["total"] = item["price"] * item["shares"]
        item["amount"] = usd(item["total"])
        total_value += item["total"]

    total_assets = user_info[0]["cash"] + total_value
    return render_template("index.html", user=user_info[0], portfolio=portfolio, total=usd(total_assets), buying_power=usd(user_info[0]["cash"]))

@app.route("/add_cash", methods=["GET", "POST"])
@login_required
def add_cash():
    if request.method == "POST":
        amount = float(request.form.get("amount"))

        if amount <= 0:
            return apology("Amount must be a positive number", 400)

        user_id = session["user_id"]

        db.execute("UPDATE users SET cash = cash + :amount WHERE id = :id",
                   amount=amount, id=user_id)

        flash(f"Successfully added {usd(amount)} to your account")
        return redirect("/")

    return render_template("add_cash.html")

@app.route("/account")
@login_required
def account():
    user_info = db.execute("SELECT * FROM users WHERE id = :user_id", user_id=session["user_id"])

    return render_template("account.html", user=user_info[0])

@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    confirmed = False
    if request.method == "POST":
        symbol = request.form.get("symbol")
        shares = request.form.get("shares")

        # Ensure symbol was provided
        if not symbol:
            return apology("must provide symbol", 400)

        quote = lookup(symbol)

        # Ensure valid symbol
        if quote is None:
            return apology("invalid symbol", 400)

        # Ensure shares were provided
        if not shares:
            return apology("must provide shares", 400)

        try:
            shares = int(shares)
        except ValueError:
            return apology("shares must be a number", 400)

        # Ensure shares is positive
        if shares <= 0:
            return apology("shares must be positive", 400)

        total_cost = shares * quote["price"]

        if request.form.get("confirm"):
            # User confirmed the purchase
            user_id = session["user_id"]

            # Check cash on user
            rows = db.execute("SELECT cash FROM users WHERE id = :id", id=user_id)
            cash = rows[0]["cash"]

            # Check if user can afford stock
            if cash < total_cost:
                return apology("not enough cash", 400)

            # Reduce cash
            db.execute("UPDATE users SET cash = cash - :cost WHERE id = :id", cost=total_cost, id=user_id)

            # Check if user already has the stock
            rows = db.execute("SELECT shares FROM portfolio WHERE user_id = :user_id AND symbol = :symbol",
                              user_id=user_id, symbol=quote["symbol"])

            if len(rows) == 0:
                # If not, insert new stock
                db.execute("INSERT INTO portfolio (user_id, symbol, shares) VALUES (:user_id, :symbol, :shares)",
                           user_id=user_id, symbol=quote["symbol"], shares=shares)
            else:
                # If so, update the number of shares
                db.execute("UPDATE portfolio SET shares = shares + :shares WHERE user_id = :user_id AND symbol = :symbol",
                           shares=shares, user_id=user_id, symbol=quote["symbol"])

            # Record the transaction
            db.execute("INSERT INTO transactions (user_id, symbol, shares, price, transaction_type, time) VALUES (:user_id, :symbol, :shares, :price, :transaction_type, CURRENT_TIMESTAMP)",
                       user_id=user_id, symbol=quote["symbol"], shares=shares, price=quote["price"], transaction_type="purchase")

            flash(f"Successfully purchased {shares} shares of {quote['symbol']} for {usd(total_cost)}")
            return redirect("/")

        # Render the buy page with the quote details for confirmation
        return render_template("buy.html", quote=quote, shares=shares, total_cost=usd(float(total_cost)), price=usd(float(quote["price"])), confirmed=True)

    return render_template("buy.html", confirmed=False)






@app.route("/history")
@login_required
def history():

    transactions = db.execute("SELECT * FROM transactions WHERE user_id = :id", id=session["user_id"])


    for transaction in transactions:
        transaction["price"] = float(transaction["price"])  # Convert price to float for proper formatting
        transaction["shares"] = int(transaction["shares"])
        transaction["amount"] = usd(transaction["price"] * transaction["shares"])


    return render_template("history.html", transactions=transactions)


@app.route("/login", methods=["GET", "POST"])
def login():
    """Log user in"""

    # Forget any user_id
    session.clear()

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":
        # Ensure username was submitted
        if not request.form.get("username"):
            return apology("must provide username", 400)

        # Ensure password was submitted
        elif not request.form.get("password"):
            return apology("must provide password", 400)

        # Query database for username
        rows = db.execute(
            "SELECT * FROM users WHERE username = ?", request.form.get("username")
        )

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(
            rows[0]["hash"], request.form.get("password")
        ):
            return apology("invalid username and/or password", 400)

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
    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":
        symbol = request.form.get("symbol")

        # Ensure a symbol is submitted
        if not symbol:
            return apology("must provide symbol", 400)

        # Look up symbol if one is submitted
        quote = lookup(symbol)

        # Ensure symbol exists
        if quote is None:
            return apology("invalid symbol", 400)

        return render_template("quoted.html", quoted=usd(quote["price"]), symbol=quote["symbol"])

    # If method is not post just render the page
    return render_template("quote.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        confirmation = request.form.get("confirmation")

        # Ensure username was submitted
        if not username:
            return apology("must provide username", 400)

        # Ensure password was submitted
        elif not password:
            return apology("must provide password", 400)

        # Ensure confirmation password was submitted
        elif not confirmation:
            return apology("must provide password confirmation", 400)

        # Ensure password and confirmation match
        elif password != confirmation:
            return apology("passwords do not match", 400)


        # Query database for username to determine if an account already exists
        rows = db.execute(
            "SELECT * FROM users WHERE username = ?", request.form.get("username")
        )


        # If username exists return apology.
        if rows:
            return apology("An account already exists with that username")
        # If username doesnt exists make a new account
        elif not rows:
            #hash password
            hashed_pass = generate_password_hash(password)
            #create the user
            db.execute("INSERT INTO users (username, hash) VALUES (?, ?);", username, hashed_pass)
            return redirect("/login")

    # if method is not post just render the page
    return render_template("register.html")


@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    if request.method == "POST":
        symbol = request.form.get("symbol")
        shares = request.form.get("shares")

        # Ensure symbol was provided
        if not symbol:
            return apology("must provide symbol", 400)

        quote = lookup(symbol)

        # Ensure valid symbol
        if quote is None:
            return apology("invalid symbol", 400)

        # Ensure shares were provided
        if not shares:
            return apology("must provide shares", 400)

        try:
            shares = int(shares)
        except ValueError:
            return apology("shares must be a number", 400)

        # Ensure shares is positive
        if shares <= 0:
            return apology("shares must be positive", 400)

        # Check if user has enough shares to sell
        user_id = session["user_id"]
        rows = db.execute("SELECT shares FROM portfolio WHERE user_id = :user_id AND symbol = :symbol",
                          user_id=user_id, symbol=quote["symbol"])

        if len(rows) != 1 or rows[0]["shares"] < shares:
            return apology("not enough shares", 400)

        total_sale = shares * quote["price"]

        if request.form.get("confirm"):
            # User confirmed the sale

            # Update user's cash balance
            db.execute("UPDATE users SET cash = cash + :cost WHERE id = :id",
                       cost=total_sale, id=user_id)

            # Update user's portfolio
            db.execute("UPDATE portfolio SET shares = shares - :shares WHERE user_id = :user_id AND symbol = :symbol",
                       shares=shares, user_id=user_id, symbol=quote["symbol"])

            # Remove stock from portfolio if shares are zero
            db.execute("DELETE FROM portfolio WHERE user_id = :user_id AND symbol = :symbol AND shares = 0",
                       user_id=user_id, symbol=quote["symbol"])

            # Record the transaction
            db.execute("INSERT INTO transactions (user_id, symbol, shares, price, transaction_type, time) VALUES (:user_id, :symbol, :shares, :price, :transaction_type, CURRENT_TIMESTAMP)",
                       user_id=user_id, symbol=quote["symbol"], shares=-shares, price=quote["price"], transaction_type="sell")

            flash(f"Successfully sold {shares} shares of {quote['symbol']} for {usd(total_sale)}")
            return redirect("/")

        # Render the sell page with the quote details for confirmation
        return render_template("sell.html", quote=quote, shares=shares, total_sale=usd(float(total_sale)), price=usd(float(quote["price"])), confirmed=True, symbols=[])

    # Get user's portfolio for initial rendering
    portfolio = db.execute("SELECT * FROM portfolio WHERE user_id = :user_id", user_id=session["user_id"])
    symbols = [item["symbol"] for item in portfolio]
    for item in portfolio:
        item["price"] = lookup(item["symbol"])["price"]
        item["total"] = item["price"] * item["shares"]
    return render_template("sell.html", portfolio=portfolio, symbols=symbols, confirmed=False)




