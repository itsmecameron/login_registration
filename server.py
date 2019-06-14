from flask import Flask, render_template, request, redirect, flash, session
from mysqlconnection import connectToMySQL
from flask_bcrypt import Bcrypt        
app = Flask(__name__)
bcrypt = Bcrypt(app)
app.secret_key = "keep it cheesy"
import re
EMAIL_REGEX = re.compile(r'^[a-zA-Z0-9.+_-]+@[a-zA-Z0-9._-]+\.[a-zA-Z]+$') 
#------------------------------------------------------
#ROOT page
#------------------------------------------------------
@app.route("/")
def index():
    return render_template("index.html")

#------------------------------------------------------
#route to process the create login
#------------------------------------------------------

@app.route("/process", methods=["POST"]) 
def add_email():
    is_valid = True
    if not EMAIL_REGEX.match(request.form['email']):
        flash("Invalid Email", "email")
    if len(request.form['fname']) < 2:
        is_valid = False
        flash("Please enter your First name", "fname")
    if len(request.form['lname']) < 2:
        is_valid = False
        flash("Please enter your Last Name", "lname")
    if len(request.form['email']) < 2:
        is_valid = False
        flash("Please enter a valid email", "email")
    if len(request.form['password']) < 8:
        is_valid = False
        flash("Please enter a password longer than 8 characters", "password")
    if not request.form['password'] == request.form['confirm_password']:
        is_valid = False
        flash("Passwords do not match", "confirm_password")
    else:
        db = connectToMySQL('login')
        query ="SELECT * from users where email=(%(em)s);"
        data = {
            "em": request.form['email'],
        }
        count = db.query_db(query, data)
        
    if len(count) > 0:
        flash("Email already in use", "verify_email")
        if not is_valid:
            is_valid = False
        return redirect("/")

    else:
        pw_hash = bcrypt.generate_password_hash(request.form['password']) 
        db = connectToMySQL('login')
        query ="INSERT INTO users (first_name, last_name, email, password, created_at, updated_at) VALUES (%(fn)s, %(ln)s, %(em)s, %(pw)s, NOW(), NOW());"
        data = {
            "fn": request.form['fname'],
            "ln": request.form['lname'],
            "em": request.form['email'],
            "pw": pw_hash
        }
        id = db.query_db(query, data)
        session['id'] = id
        return redirect("/success/" + str(id))

#------------------------------------------------------
#route to login 
#------------------------------------------------------
@app.route('/login', methods=['POST'])
def login():

    mysql = connectToMySQL("login")
    query = "SELECT password, id FROM users WHERE email = %(em)s;"
    data = { "em" : request.form["login_email"]}

    result = mysql.query_db(query, data)
    if len(result) > 0:
        if bcrypt.check_password_hash(result[0]['password'], request.form['login_password']):
            session['id'] = result[0]['id']
            return redirect('/success/'+ str(session['id']))

    flash("You could not be logged in", "failed")
    return redirect('/')

#------------------------------------------------------
#route to view the user page after login form
#------------------------------------------------------

@app.route("/success/<id>")
def user_page(id):
    if not "id" in session:
        return redirect ("/")
    else:
        db = connectToMySQL('login')
        query = 'SELECT * FROM users '
        user = db.query_db(query)
        return render_template("show.html", user = user)

#------------------------------------------------------
#route to logout
#------------------------------------------------------

@app.route("/logout")
def logout():
    session.clear()
    return redirect("/")
    
if __name__ == "__main__":
    app.run(debug=True)