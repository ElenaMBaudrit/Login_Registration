from flask import Flask, render_template, request, redirect, session, flash
import md5, re
import os, binascii 
from mysqlconnection import MySQLConnector
app = Flask(__name__)
mysql =  MySQLConnector(app, 'login_registration') #this is the name of the database. In this case, it has not been created yet

hashed_password = md5.new(password).hexdigest()

salt = '123' #where the value 123 changes randomly
hashed_password = md5(password + salt)

print hashed_password

@app.route('/')
def index():
    print 'test'
    return render_template("logReg_index.html")

@app.route('/login')
def login():
    password = md5.new(request.form['password']).hexdigest()
    email = request.form['email']
    user_query = "SELECT * FROM users where users.email = :email AND users.password = :password"
    query_data = { 'email': email, 'password': password}
    user = mysql.query_db(user_query, query_data)
    
    query = "SELECT * FROM users WHERE email = :email LIMIT 1" 
    data = {
        'email': request.form['email']
    }
    get_user = mysql.query_db(query, data)
    #Check the user info and password
    # if len(user.email) is 0:
    #     flash("Oops! The information does not match. Please log in again")
    #     return redirect('/')
    # elif len(user.email) >= 0:
    #     if data(form.email) != query(user.email):
    #         flash("Oops! The information does not match. Please log in again")
    #         return redirect('/')
    #     if len(user.password) != 0:
    #         encrypted_password = md5.new(password + user[0]['salt']).hexdigest()
    #         if user[0]['password'] == encrypted_password:
    #         flash("Oops! The information does not match. Please log in again")
    #         return redirect('/')
    #     elif len(user.password) >= 0:
    #         if data(form.password) is query(user.password):
    #             flash('Congratulations! Login successful!')
    #             return redirect('/wall')
    #     else:
    #         flash("Oops! The information does not match. Please log in again")
    #         return redirect('/') 
    # return render_template("Login_page.html")

@app.route('/reg_form')
def reg_form():
    return render_template("registration.html")

@app.route('/registration',  methods=['POST'])
def create(): 
    username = request.form['username']
    email = request.form['email']
    password = request.form['password']
    salt =  binascii.b2a_hex(os.urandom(15))
    hashed_pw = md5.new(password + salt).hexdigest()
    insert_query = "INSERT INTO users (username, email, password, created_at, updated_at) VALUES (:username,
    :email, :password, NOW(), NOW())"
    query_data = { 'username': username, 'email': email, 'password': password }
    mysql.query_db(insert_query, query_data)



    if len(request.form ['first_name']) <= 2:
        flash("Oops! The information does not match. Please log in again")
        return redirect('/')
        if first_name.isalpha() is False: #https://docs.python.org/2/library/stdtypes.html?highlight=isalpha#str.isalpha
            flash("Oops! The information does not match. Please log in again")
            return redirect('/')
    if len(request.form ['last_name']) <= 2:
        flash("Oops! The information does not match. Please log in again")
        return redirect('/')
        if last_name.isalpha() is False: 
            flash("Oops! The information does not match. Please log in again")
            return redirect('/')
    if len(request.form ['email']) <=4:
        flash("Oops! The information does not match. Please log in again")
        return redirect('/')
    if data(request.form ['email']) != query(user.email):
        flash("Oops! The information does not match. Please log in again")
        return redirect('/')
    if len((request.form ['password'])) <= 7:
        flash("Oops! The information does not match. Please log in again")
        return redirect('/')
    if len(registration.password_conf) is (registration.password):
        flash('Congratulations! Registration successful!')
        query = 'INSERT INTO users (first_name, last_name, email, password, created_at, updated_at) VALUES (:first_name, :last_name, :email, :password, NOW(), NOW())'
        data = {
            'first_name': request.form ['first_name'],
            'last_name': request.form ['last_name'],
            'email': request.form['email'],
            'password': request.form['password']
        }
        mysql.query_db(query,data)
        return redirect('/wall')
    else:
        return render_template("registration.html")
    return render_template("registration.html")



#  email = TextField('Email:', validators=[validators.required(), validators.Length(min=6, max=35)])
#     password = TextField('Password:', validators=[validators.required(), validators.Length(min=3, max=35)])

#     if get_user:
#         session['userid'] = get_user[0]['id']
#         session['user_first_name'] = get_user[0]['first_name']
#         hashed_password = get_user[0]['password']
#         if bcrypt.check_password_hash(hashed_password, request.form['password']):
#             session['logged_in'] = True
#             flash("You successfully logged in...")

#             return redirect('/home')
#         else:
#             session['logged_in'] = False
#             flash("Login failed... Try again, or register.")
#             return redirect('/')
#     else:
#         flash("Your username (email) was not found, please try again or register")
# return redirect('/')
#     return render_template("Login_page.html")

# @app.route('/create')
# def registration():

#     return render_template("registration.html")

# @app.route('/create/user', methods=['POST'])
# def create_user():
#      username = request.form['username']
#      email = request.form['email']
#      password = md5.new(request.form['password']).hexdigest()
#      insert_query = "INSERT INTO users (username, email, password, created_at, updated_at) VALUES (:username,
#      :email, :password, NOW(), NOW())"
#      query_data = { 'username': username, 'email': email, 'password': password }
#      mysql.query_db(insert_query, query_data)


#     return render_template('friendsNames.html', all_friends= friends_names)

# @app.route('/users', methods=['POST'])
# def create_user():
#    print "Got Post Info"
#    session['name'] = request.form['name']
#    session['age'] = request.form['age']
#    return redirect('/show') 

app.run(debug=True)