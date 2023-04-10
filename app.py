import os

from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session
from flask_session import Session
from tempfile import mkdtemp
from werkzeug.security import check_password_hash, generate_password_hash
from datetime import datetime, timedelta

from helpers import apology, login_required

# Configure application
app = Flask(__name__)


# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)


# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///database.db")


@app.route("/")
def home():
    return render_template("home.html")


@app.after_request
def after_request(response):
    """Ensure responses aren't cached"""
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response


@app.route("/login", methods=["GET", "POST"])
def login():
    """Log user in"""

    # Forget any user_id
    session.clear()

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        # Ensure username was submitted
        if not request.form.get("username"):
            return apology("must provide username", 403)

        # Ensure password was submitted
        elif not request.form.get("password"):
            return apology("must provide password", 403)

        # Query database for username
        rows = db.execute("SELECT * FROM users WHERE username = ?", request.form.get("username"))

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(rows[0]["hash"], request.form.get("password")):
            return apology("invalid username and/or password", 403)

        # Remember which user has logged in
        session["user_id"] = rows[0]["id"]

        # Redirect user to home page
        return redirect("/home")

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


@app.route("/signup", methods=["GET", "POST"])
def signup():
    """Register user"""

    if request.method == "POST":
        # Get username, password and confirmation
        name = request.form.get("username")
        password = request.form.get("password")
        confirm_password = request.form.get("confirmation")
        type = request.form.get("type")
        db_usernames = db.execute("SELECT username FROM users")
        # Check the inputed values

        # input usernames from data base into a list and check whether the name is in the list
        if db_usernames:
            name_list = []
            for row in db_usernames:
                Newname = row["username"]
                name_list.append(Newname)
            if name in name_list:
                return apology("username taken")

        if not name:
            return apology("must provide username")

        if not password:
            return apology("must provide password")

        if not confirm_password:
            return apology("must provide confirmation password")

        if password != confirm_password:
            return apology("pasword and confirmation do not match")
        if not type:
            return apology("Choose your status")
        # Hash the password
        final_pass = generate_password_hash(password, method='pbkdf2:sha256', salt_length=8)

        # Insert values into database
        db.execute("INSERT INTO users (username, hash, type) VALUES (?, ?, ?)", name, final_pass, type)
        rows = db.execute("SELECT * FROM users WHERE username = ?", request.form.get("username"))
        # Remember which user has logged in
        session["user_id"] = rows[0]["id"]
        return redirect("/")
    else:
        return render_template("signup.html")


@app.route("/home", methods=["GET", "POST"])
@login_required
def homepage():
    # Link session id to username
    User_name = db.execute("SELECT username FROM users WHERE id = ?", session["user_id"])
    User_named = User_name[0]["username"]
    if request.method == "GET":
        # Task uncompleted
        tasks = db.execute("SELECT * FROM tasks WHERE username = ? AND status = ?", User_named, 0)

        time = datetime.now()
        week_list = []
        for i in range(1, 7):
            ntime = time + timedelta(i, 0)
            ntime = ntime.strftime('%A')
            week_list.append(ntime)

        time = time.strftime('%A')
        return render_template("homepage.html", tasks=tasks, time=time, wlist=week_list)

    if request.method == "POST":
        # Get form inputs
        name = request.form.get("name")
        description = request.form.get("description")
        day = request.form.get("day")
        task_time = request.form.get("time")
        # add data into tasks table
        db.execute("INSERT INTO tasks (username, name, description, day, time, status) VALUES (?, ?, ?, ?, ?, ?)",
                   User_named, name, description, day, task_time, 0)
        return redirect("/home")


@app.route("/check", methods=["POST"])
@login_required
def check():

    if request.method == "POST":
        task_name = request.form.get("option3")
        if task_name:
            db.execute("DELETE FROM tasks WHERE name = ?", task_name)
            return redirect("/home")
        # Link session id to username
        User_name = db.execute("SELECT username FROM users WHERE id = ?", session["user_id"])
        User_named = User_name[0]["username"]
        # If user checks a task, update it
        name = request.form.get("option1")
        db.execute("UPDATE tasks SET status = ? WHERE username = ? AND name = ?", "completed", User_named, name)
        return redirect("/home")


@app.route("/tasks", methods=["GET"])
@login_required
def tasks():
    # Link session id to username
    User_name = db.execute("SELECT username FROM users WHERE id = ?", session["user_id"])
    User_named = User_name[0]["username"]

    # Tasks completed
    c_tasks = db.execute("SELECT * FROM tasks WHERE username = ? AND status = ?", User_named, "completed")
    counter = 0
    for task in c_tasks:
        counter += 1
    return render_template("/tasks.html", c_tasks=c_tasks, num=counter)


@app.route("/addfriends", methods=["GET", "POST"])
@login_required
def addfriends():
    # Link session id to username
    User_name = db.execute("SELECT username FROM users WHERE id = ?", session["user_id"])
    User_named = User_name[0]["username"]
    search = request.form.get("search")
    if request.method == "POST":
        if search:
            if search == User_named:
                return apology("Enter a valid username")

            users = db.execute("SELECT username FROM users WHERE username LIKE ? AND id != ?", search, session["user_id"])
            if not users:
                return apology("User not found")
            return render_template("/addfriends.html", friends=users)
        else:
            name = request.form.get("option2")
            friends = db.execute("SELECT friends FROM friends WHERE username = ?", User_named)
            ls = []
            for i in range(0, len(friends)):
                ls.append(friends[i]["friends"])
            if name in ls:
                return apology("User is already your friend")
            db.execute("INSERT INTO friends (username, friends) VALUES (?, ?)", User_named, name)
            return redirect("/friends")
    else:

        return render_template("/addfriends.html")


@app.route("/friends", methods=["GET"])
@login_required
def friends():

    # Link session id to username
    User_name = db.execute("SELECT username FROM users WHERE id = ?", session["user_id"])
    User_named = User_name[0]["username"]
    friends = db.execute("SELECT friends FROM friends WHERE username = ?", User_named)
    return render_template("/friends.html", friends=friends)


@app.route("/friendtasks")
@login_required
def friendtasks():
    # Link session id to username
    User_name = db.execute("SELECT username FROM users WHERE id = ?", session["user_id"])
    User_named = User_name[0]["username"]
    status = db.execute("SELECT allow FROM users WHERE username = ?", User_named)
    if status[0]["allow"] == 0:
        return apology("Allow users to see your tasks in your account settings")
    friends = db.execute("SELECT friends FROM friends WHERE username = ?", User_named)
    tasks = db.execute("SELECT * FROM tasks WHERE username IN (SELECT friends FROM friends WHERE username = ?)", User_named)
    return render_template("/friendtasks.html", tasks=tasks)


@app.route("/del", methods=["POST"])
@login_required
def delete():
    name = request.form.get("option3")
    db.execute("DELETE FROM tasks WHERE name = ?", name)
    return redirect("/home")


# Function to allow user to see his account details

@app.route("/account", methods=["GET", "POST"])
@login_required
def account():

    # Link session id to username
    User_name = db.execute("SELECT username FROM users WHERE id = ?", session["user_id"])
    User_named = User_name[0]["username"]
    if request.method == "GET":
        return render_template("/account.html", name=User_named)
    else:
        # Change ability to see tasks of user's friends
        status = request.form.get("option4")

        counter = 1
        db.execute("UPDATE users SET allow = ? WHERE username = ?", counter, User_named)

        return render_template("/account.html", name=User_named)


@app.route("/account2", methods=["GET", "POST"])
@login_required
def account2():
    # Link session id to username
    User_name = db.execute("SELECT username FROM users WHERE id = ?", session["user_id"])
    User_named = User_name[0]["username"]
    status2 = request.form.get("option5")
    counter = 0
    db.execute("UPDATE users SET allow = ? WHERE username = ?", counter, User_named)
    return redirect("/account")


@app.route("/password", methods=["GET", "POST"])
@login_required
def password():
    if request.method == "POST":

        # GET username from session id and old password & new password
        User_name = db.execute("SELECT username FROM users WHERE id = ?", session["user_id"])
        User_named = User_name[0]["username"]
        rows = db.execute("SELECT * FROM users WHERE username = ?", User_named)
        password = request.form.get("old_pass")
        new_password = request.form.get("new_pass")
        final_pass = generate_password_hash(new_password, method='pbkdf2:sha256', salt_length=8)

        # check if old password entered is correct
        if not check_password_hash(rows[0]["hash"], password):
            return apology("Old password not correct ")
        else:
            db.execute("UPDATE users SET hash = ? WHERE username = ?", final_pass, User_named)
        return redirect("/")
    else:

        return render_template("password.html")