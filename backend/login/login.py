from fastapi import FastAPI,HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import mysql.connector
import bcrypt
from email_validator import validate_email,EmailNotValidError
from datetime import datetime,timezone


def get_connection(db):
    """
     connects to database and return the connection (MYSQL)
    """
    return mysql.connector.connect(
        host="localhost",
        user="app_user",
        password="strong_password",
        database=db
    )


def validate(email):
    """
    validate the input email and return boolean
    """
    try:
        validate_email(email)
        return True
    except EmailNotValidError:
        return False

app=FastAPI()
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"]
)

#login format
class user_input(BaseModel):
    email:str
    password:str


#while signingup to make sure user didnt make typo in password
class user_input_signup(BaseModel):
    email:str
    password:str
    confirm_password:str


#todo signup

@app.post("/signup")
def signup(x:user_input_signup):
    password_check=x.password==x.confirm_password
    email_check=validate(x.email)
    if password_check and email_check:
        pass
    else:
        if not password_check and not email_check:
            return {
                "process":"signup",
                "errors":"2",
                "error1":"notvalidemail",
                "error2":"pwdnomatch"
            }
        elif not password_check:
            return{
                "process":"signup",
                "errors":1,
                "error1":"pwdnomatch"
            }
        else:
            return{
                "process":"signup",
                "errors":1,
                "error1":"notvalidemail"
            }
    query1="SELECT email FROM user_metadata WHERE email=%s"
    query2="INSERT INTO user_metadata VALUES(%s,%s,%s)"
    creation_time=datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    connection=get_connection("chat_db")
    cursor=connection.cursor()
    cursor.execute(query1,(x.email,))
    email_existing_acc=cursor.fetchone()
    if email_existing_acc is not None:
        return{
            "process":"singup",
            "errors":"1",
            "error1":"accountexisting"
        }
    cursor.execute(query2,(x.email,bcrypt.hashpw(x.password.encode(), bcrypt.gensalt()).decode(),creation_time))
    return{
        "process":"signup",
        "error":"0",
        "status":"success"
    }

#otp verification also


#todo tokenization for session management
@app.post("/login")
def login(x:user_input):
    query="SELECT password FROM user_metadata WHERE email=%s"
    connection=get_connection("chat_db")
    cursor=connection.cursor()
    cursor.execute(query,(x.email,))
    creds=cursor.fetchone()
    cursor.close()
    connection.close()
    if creds is None:
        return{
            "process":"login",
            "status":"createaccount"
        }
    if bcrypt.checkpw(x.password.encode(),creds[0].encode()):
        return{
            "process":"login",
            "status":"success"
        }
    
    return{
        "process":"login",
        "status":"fail"
    }