from flask import Flask, render_template, redirect, url_for, request, session, g, current_app
from werkzeug.security import generate_password_hash, check_password_hash
from googleapiclient.discovery import build
from google.oauth2 import service_account
import hmac
import hashlib
import secrets
import datetime
import sqlite3
import os
import json
from flask_sqlalchemy import SQLAlchemy
from flask_session import Session
from waitress import serve
import urllib
from datetime import timedelta
import logging


AUTH_SHEET_ID = "1ge1ICzCRMXXHbllb9Rl9A90UiVWCXZkgGRuDvIBfgpA"
SCOPES = ""
SERVICE_ACCOUNT_FILE = ""
AUTH_SHEET_RANGE = 'Auth!A2:F'
creds = None
pwdhashkey = "thisismysuuuuuuperlonghashKey"
sessionKey = "this@@@ismy$$$superlong!!sessionKeyabcdef"
sessionExpiryTime = 5 #in mins
config_file = "./config/auth.config"
config = None

app = Flask(__name__)
app.secret_key = "thisismyveryloooongsecretkey"
logging.basicConfig(format='%(levelname)s:%(message)s', level=logging.DEBUG)

route_prefix = os.getenv('APP_ROUTE') or ""

if(route_prefix != ""):
    route_prefix = "/" + route_prefix

# with open(config_file) as json_file:
#     config = json.load(json_file)


sessionExpiryDays = os.getenv('LOGIN_EXPIRY')
if(sessionExpiryDays):
    sessionExpiryDays = int(sessionExpiryDays)
sessionExpiryTime = 5

logging.debug("SED : %s, SET:%s",sessionExpiryDays,sessionExpiryTime)

logging.debug("Route Prefix : %s",route_prefix)

SCOPES = ['https://www.googleapis.com/auth/spreadsheets']
SERVICE_ACCOUNT_FILE = './json/myutils-437714-bd0d0a3e77bd.json'  # Update this path
creds = service_account.Credentials.from_service_account_file(
    SERVICE_ACCOUNT_FILE, scopes=SCOPES)

db_name = "./tokens.db"
db = SQLAlchemy()
basedir = os.path.abspath(os.path.dirname(__file__))


def init(): 
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(basedir, 'sessions.db')
    # Attach SQLAlchemy to Flask-Session
    app.config['SECRET_KEY'] = sessionKey
    app.config['SESSION_TYPE'] = 'sqlalchemy'
    app.config['SESSION_SQLALCHEMY_TABLE'] = 'sessions'
    app.config['SESSION_USE_SIGNER'] = True
    app.config['SESSION_PERMANENT'] = True
    app.config['SESSION_SQLALCHEMY'] = db
    app.config['SESSION_COOKIE_NAME'] = 'myauthapi'
    db.init_app(app)

    # Create the sessions table if not exists
    with app.app_context():
        db.create_all()
    
    Session(app)


    
    app.creds = service_account.Credentials.from_service_account_file(
        SERVICE_ACCOUNT_FILE, scopes=SCOPES)
    # Create a table
    conn = sqlite3.connect(db_name)
    cursor = conn.cursor()
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS tokens (
        token TEXT NOT Null PRIMARY KEY,
        username TEXT NOT NULL,
        expires TEXT NOT NULL
    )
    """)
    #can be retried only with the private key. server to server.
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS keytotoken (
        key TEXT NOT Null PRIMARY KEY,
        token TEXT NOT NULL
    )
    """)
    conn.commit()
    conn.close()

def removeToken(token):
    conn = sqlite3.connect(db_name)
    cursor = conn.cursor()
    cursor.execute("DELETE FROM tokens where token='"+token+"'")
    session.clear()
    conn.commit()
    conn.close

def removekeytotoken(key):
    conn = sqlite3.connect(db_name)
    cursor = conn.cursor()
    cursor.execute("DELETE FROM keytotoken where key='"+key+"'")    
    conn.commit()
    conn.close

def upsertToken(token, un):
    conn = sqlite3.connect(db_name)
    cursor = conn.cursor()
    print (str(sessionExpiryDays) + "-")

    if sessionExpiryDays:
        current_date = (datetime.datetime.now() + datetime.timedelta(days=sessionExpiryDays)).strftime("%Y-%m-%d %H:%M:%S")
    else:
        current_date = (datetime.datetime.now() + datetime.timedelta(minutes=sessionExpiryTime)).strftime("%Y-%m-%d %H:%M:%S")
    _token = getToken(token)
    if(_token):
        cursor.execute('''UPDATE tokens set expires=? where token = ?''',(current_date,token))
    else:
        cursor.execute('''INSERT INTO tokens (token, username, expires) 
    VALUES (?, ?, ?)''',(token,un, current_date))
    conn.commit()
    conn.close()
    
def upsertKeytoToken(key, token):
    conn = sqlite3.connect(db_name)
    cursor = conn.cursor()
    removekeytotoken(key)
    cursor.execute('''INSERT INTO keytotoken (key, token) 
    VALUES (?, ?)''',(key,token))
    conn.commit()
    conn.close()

def getTokenFromKey(key):
    conn = sqlite3.connect(db_name)
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM keytotoken where key = '" + key + "'")
    ret = cursor.fetchone()
    conn.close()
    #removekeytotoken(key) #uncomment after testing. once key is read, remove it.
    return ret

def getToken(token):
    conn = sqlite3.connect(db_name)
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM tokens where token = '" + token + "'")
    ret = cursor.fetchone()
    conn.close()
    return ret
    

def getUserProfile(name_to_filter):
    service = build('sheets', 'v4', credentials=app.creds)
    result = service.spreadsheets().values().get(spreadsheetId=AUTH_SHEET_ID, range=AUTH_SHEET_RANGE).execute()
    values = result.get('values', [])
    filtered_values = [row for row in values if row and row[1] == name_to_filter]
    #ndate = datetime.datetime.now() + datetime.timedelta(days=-1) #datetime.strptime(date_string, "%Y-%m-%d")
    
    # if session.get("isadmin") == None:
    #     # Filter by name
    #     filtered_values = [row for row in values if row and row[1] == name_to_filter and datetime.datetime.strptime(row[3], "%Y-%m-%d") >= ndate]
    # else:
    #     filtered_values = [row for row in values if row and datetime.datetime.strptime(row[3], "%Y-%m-%d") >= ndate]
    
    
    
    # for row in filtered_values:
    #     row.append(datetime.datetime.strptime(row[3], '%Y-%m-%d').strftime('%A'))
    return filtered_values

def encrypt(txt):
    txt = txt.encode()
    skey = pwdhashkey.encode()
    hmac_object = hmac.new(skey, txt, hashlib.sha256)
    return hmac_object.hexdigest()

@app.route('/')
def default():
    logging.debug("Prefix: " + route_prefix)
    return render_template('error.html',message="Invalid login or App not registered : ",token=session.get("token"),routePrefix=route_prefix,msgtype="error")

@app.route('/logout')
def logout():
    if session.get("token"):
        removeToken(session.get("token")) #removes session as well
    return render_template('error.html',message="Logout successful.",token=session.get("token"),routePrefix=route_prefix, backurl=request.args.get("callback"),msgtype="logout")

@app.route('/favicon.ico')
def favicon():
    return current_app.send_static_file("images/favicon.png") #send_from_directory(os.path.join(app.root_path, 'static/images'),
            #                   'favicon.png', mimetype='image/vnd.microsoft.icon')

@app.route("/sessioncheck")
def sessioncheck():
    s = session.get("myval")
    if s is not None:
        session["myval"] = (int(s)+1)
    else:
        session["myval"] = 0
    return "Session val : " + str(session.get("myval")) + " sessionid :" + str(session.get("sid") or "")

#will not work...the session object will not be accessible.
#need to create a unique token and set the user to be signed on in the db
#which will be validated.

#will be hit directly from the client
@app.route("/signon", methods=["GET"])
def signon():
    #check the session if valid. Could be a call from another application.
    token = session.get("token")
    session["redirect-to"] = request.args.get("callback") or request.url #needed after /login post.
    logging.debug("Prefix: " + route_prefix)
    if token:
        urow = getToken(token)
        #there is a session, check if its not expired.
        if urow and (datetime.datetime.strptime(urow[2], "%Y-%m-%d %H:%M:%S") > 
                                        datetime.datetime.now()):   #valid session found return back with payload.
            upsertToken(token, urow[1]) #update expiry
            k = secrets.token_hex(16)
            upsertKeytoToken(k,token) 
            logging.debug("Token updated. Redirecting to %s",session["redirect-to"])           
            return redirect(session["redirect-to"] + "?singleuse=" + k) #callback to application
    logging.debug("Rendering login")
    return render_template('login.html',routePrefix=route_prefix) #send to login page

#will be hit directly from the client. 
@app.route("/login", methods=['POST'])
def login():
    p = request.form.get("passw")
    u = request.form.get("uname")
    cb = request.form.get("callback")
    u = u.lower()    
    profileRow = getUserProfile(u)
    if(len(profileRow) > 0):
        if(len(profileRow[0]) > 2): #password hash found
            #to forward hash and store in gsheet
            if(profileRow[0][2] == '' and p == ''): #password blank
                #for reg
                return render_template('login.html', username=u, firstLogin=True, routePrefix=route_prefix) #for registration
            else:
                logging.debug("Enc pw: %s and rcvd pw: %s",encrypt(p),profileRow[0][2])
                if(encrypt(p) == profileRow[0][2]): #check password
                    #password matched.
                    token = secrets.token_hex(16)
                    upsertToken(token, u) #generate token
                    session["token"] = token
                    session["username"] = u
                    k = secrets.token_hex(16) #generating single use key
                    upsertKeytoToken(k,token)
                    #upsert_by_name(profileRow[0][1],session["x-token"]) #update local file
                    #pl = urllib.parse.quote({"singleuse":k})           
                    if(session.get("redirect-to")):
                        try:  
                            logging.debug("Redirecting to %s -",session["redirect-to"])                    
                            return redirect(session["redirect-to"]+ "?singleuse="+k) #should reach a callback route
                        except:
                            logging.debug("Single Use token: " + k)
                            return render_template('error.html', message="Could not reach callback url. " + session["redirect-to"],routePrefix=route_prefix) 
                    else:
                        return redirect("/") #app redirect to be setup
                else:
                    #password error
                    return render_template('login.html', username='', firstLogin=False, loginFailed=True, message="Invalid username or password",routePrefix=route_prefix)
        else: #for reg
            return render_template('login.html', username=u, firstLogin=True, loginFailed=False, message="",routePrefix=route_prefix)
    else: 
        return render_template('login.html', username='', firstLogin=False, loginFailed=True, message="Invalid username or password",routePrefix=route_prefix)
    
#is a server - server api call
@app.route('/validate/<token>')
def validate(token):
    data = {}   
    tokenrow = getToken(token)
    if tokenrow is not None:
        if tokenrow[2] is not None and (datetime.datetime.strptime(tokenrow[2], "%Y-%m-%d %H:%M:%S") > 
                                        datetime.datetime.now()): #to check expiry date
            data["success"] = True
            data["username"] = tokenrow[1] 
            data["expires"] = tokenrow[2]
            data["now"] = str(datetime.datetime.now())
        else:        
            data["success"] = False
    else:
        data["success"] = False
    return json.dumps(data)

@app.route("/register", methods=['POST'])
def register():
    p = request.form.get("passw")
    u = request.form.get("uname")
    cb = request.form.get("callback")
    u = u.lower()
    
    service = build('sheets', 'v4', credentials=app.creds)
    profileRow = getUserProfile(u)

    if(p != ""):
        if(len(profileRow) > 0):
            ui = profileRow[0][0]
            p = encrypt(p)
            values = [[ui, u, p,'',datetime.datetime.now().strftime("%m/%d/%Y %H:%M:%S")]]  
            range_name = f'Auth!{0}{ui}:{4}{ui}' 
            body = {
                'values': values
            }
            service.spreadsheets().values().update(
                spreadsheetId=AUTH_SHEET_ID,
                range=range_name,
                valueInputOption='RAW',
                body=body
            ).execute()
            token = secrets.token_hex(16)
            upsertToken(token, u) #generate token
            session["token"] = token
            session["username"] = u
            k = secrets.token_hex(16) #generating single use key
            upsertKeytoToken(k,token)
            #upsert_by_name(profileRow[0][1],session["x-token"]) #update local file
            #pl = urllib.parse.quote({"singleuse":k})           
            if(session.get("redirect-to")):
                try:  
                    logging.debug("Reg.Redirecting to %s -",session["redirect-to"])                    
                    return redirect(session["redirect-to"]+ "?singleuse="+k) #should reach a callback route
                except:
                    logging.debug("Reg. Single Use token: " + k)
                    return render_template('error.html', message="Could not reach callback url. " + session["redirect-to"],routePrefix=route_prefix) 
            else:
                return redirect("/") #app redirect to be setup
        else:
            return render_template('login.html', username='', firstLogin=True, loginFailed=True, message="Error Registering. Check inputs and try again later.",routePrefix=route_prefix )
    return render_template('login.html', username=u, firstLogin=True, loginFailed=True, message="Error Registering. Check inputs and try again later." ,routePrefix=route_prefix)

@app.route('/gettokenfromkey/<privatekey>/<key>', methods=["GET"])
def gettokenfromkey(privatekey, key):
    data={}
    if sessionKey == privatekey:        
        tokenrow = getTokenFromKey(key)
        if tokenrow:
            data["token"] = tokenrow[1]
    return json.dumps(data)


if __name__ == '__main__':
    init()
    #app.run(debug=True, host="0.0.0.0", port=8000)
    serve(app, host='0.0.0.0', port=8000)
