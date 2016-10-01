from flask import Flask, render_template, request, redirect, flash, session
from mysqlconnection import MySQLConnector
from flask_bcrypt import Bcrypt
import re

EMAIL_REGEX = re.compile(r'^[a-zA-Z0-9\.\+_-]+@[a-zA-Z0-9\._-]+\.[a-zA-Z]*$')
NAME_REGEX = re.compile(r'^[a-zA-Z]+[a-zA-Z-]*[a-zA-Z]+$')

app = Flask(__name__)
app.secret_key = 'supersecret'
bcrypt = Bcrypt(app)
mysql = MySQLConnector(app, 'the_wall_db')

@app.route('/')
def index():
    return render_template("index.html")

@app.route('/log')
def logpage():
    fields = None
    return render_template("login.html", fields = fields)

@app.route('/reg')
def regpage():
    fields = None
    return render_template("register.html", fields = fields)

@app.route('/main')
def main():
    username_query = "SELECT CONCAT(firstname,' ',lastname) AS name FROM users WHERE id = :userid"
    userid_data = {'userid': session['userid']['id']}
    name = mysql.query_db(username_query, userid_data)[0]['name']
    wall_query = "SELECT users.id AS msg_aut_id, CONCAT(firstname,' ',lastname) AS msg_aut, messages.id as msg_id, message AS msg, messages.created_at AS msg_date,comments.id AS com_id, comment AS com, comments.created_at AS com_date, comments.user_id AS com_aut_id, (SELECT CONCAT(firstname,' ',lastname) FROM users WHERE users.id = comments.user_id) AS com_aut FROM users JOIN messages ON users.id = messages.user_id LEFT JOIN comments ON messages.id = comments.message_id ORDER BY msg_date DESC, com_date ASC "
    wall_content = mysql.query_db(wall_query)
    print wall_content
    print type(wall_content[0]['com_id'])
    return render_template("wall.html", name = name, wall_content = wall_content)

@app.route('/logout', methods=['POST'])
def logout():
    session.pop('userid', None)
    return redirect('/')

@app.route('/register', methods=['POST'])
def create():
    query = "SELECT email FROM users"
    emails = mysql.query_db(query)
    errors = False
    if len(request.form['email']) < 1:
        errors = True
        flash("e-mail address is empty. Enter e-mail.")
    elif not EMAIL_REGEX.match(request.form['email']):
        errors = True
        flash("Invalid e-mail address. Enter e-mail.")
    elif {'email' : request.form['email']} in emails:
        errors = True
        flash("The e-mail address entered already exists in the database.")
    if not NAME_REGEX.match(request.form['firstname']):
        errors = True
        flash("Firstname must be at least two characters in length containing only letters and cannot begin or end with a hyphen")
    if not NAME_REGEX.match(request.form['lastname']):
        errors = True
        flash("Lastname must be at least two characters in length containing only letters and cannot begin or end with a hyphen")
    if len(request.form['password']) < 8:
        errors = True
        flash("Password must be at least eight characters in length")
    elif request.form['password'] != request.form['password_confirmation']:
        errors = True
        flash("Password and Password Confirmation do not match.")
    if errors:
        flash("Re-enter Password and Password Confirmation.")
        return render_template('register.html', fields = request.form)
    else:
        pw_hash = bcrypt.generate_password_hash(request.form['password'])
        query = "INSERT INTO users (email, firstname, lastname, password, created_at, updated_at) VALUES(:email, :firstname, :lastname, :password, NOW(),NOW());"
        data = {'email':request.form['email'], 'firstname' :request.form['firstname'], 'lastname' :request.form['lastname'], 'password': pw_hash }
        mysql.query_db(query, data)
        query = "SELECT id FROM users WHERE email = :email"
        data = { 'email': request.form['email'] }
        session['userid'] = mysql.query_db(query, data)[0]
        return redirect('/main')

@app.route('/login', methods=['POST'])
def login():
    query = "SELECT email FROM users"
    emails = mysql.query_db(query)
    email = request.form['email']
    if not {'email' : request.form['email']} in emails:
        flash("The e-mail address " +  email +" entered was not found.  Please check the email and register if you are a new user")
        return redirect ('/')
    if request.form['password'] != request.form['password_confirmation']:
        flash("Password and Password Confirmation do not match.")
        return render_template('login.html', fields = request.form)
    password = request.form['password']
    user_query = "SELECT * FROM users WHERE email = :email LIMIT 1"
    query_data = { 'email': email }
    user = mysql.query_db(user_query, query_data) # user will be returned in a list
    if bcrypt.check_password_hash(user[0]['password'], password):
        query = "SELECT id FROM users WHERE email = :email"
        data = { 'email': email }
        session['userid'] = mysql.query_db(query, data)[0]
        return redirect('/main')
    else:
        flash("The password did not match that for " + email +". Please check the password.")
        return render_template('login.html', fields = request.form)

if __name__ == "__main__":
    app.run(debug=True)
