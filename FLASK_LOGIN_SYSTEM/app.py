from distutils.log import debug
from email import message
import email
from http import client
from importlib import find_loader
import bcrypt
from flask import Flask, redirect, render_template, request, session, url_for
import pymongo
from requests_cache import utf8_encoder
app = Flask(__name__)
app.secret_key="testing"
client = pymongo.MongoClient("mongodb://localhost:27017/?readPreference=primary&appname=MongoDB%20Compass&directConnection=true&ssl=false")
db = client['totalrecords']
records = db['user_data']

@app.route('/',methods=["POST","GET"])
def index():
    message=''
    if "email" in session:
        return render_template('logged_in.html')
    if request.method=='POST':
        user = request.form.get('fullname')
        email = request.form.get('email')

        password1 = request.form.get('password1')
        password2 = request.form.get('password2')

        user_found = records.find_one({'name':user})
        email_found = records.find_one({'email':email})

        if user_found:
            message = "There is already a user by this name"
            return render_template('index.html',message = message)
        if email_found:
            message = "This email already exists in database"
            return render_template('index.html',message = message)

        if password1!=password2:
            message = "Passwords doesn't match!"
            return render_template('index.html',message = message)
        else:
            hashed = bcrypt.hashpw(password2.encode('utf-8'),bcrypt.gensalt())
            user_input = {'name':user,'email':email,'password':hashed}
            records.insert_one(user_input)

            user_data = records.find_one({"email":email})
            new_email = user_data['email']
            return render_template('logged_in.html',email = new_email)

    return render_template('index.html')

@app.route('/login',methods=['post','get'])
def login():
    message = 'Please login to your account'
    if "email" in session:
        return redirect(url_for("logged_in"))
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        
        email_found = records.find_one({'email':email})
        if email_found:
            email_val = email_found['email']
            password_check = email_found['password']

            if bcrypt.checkpw(password.encode('utf-8'),password_check):
                session['email'] = email_val
                return redirect(url_for('logged_in.html'))
            else:
                if email in session:
                    return redirect(url_for('logged_in.html'))
                else:
                    message = "Wrong Password"
                    return render_template('login.html',message=message)
        else:
            message = 'email not found'
            return render_template('login.html',message=message)
    return render_template('login.html',message=message)

@app.route('/logout',methods=['post','get'])
def logout():
    if "email" in session:
        session.pop('email',None)
        return render_template("signout.html")
    else:
        return render_template('index.html')

if __name__ == '__main__':
    app.debug  = True
    app.run()