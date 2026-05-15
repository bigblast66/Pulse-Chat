from fastapi import FastAPI,HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import aiomysql
import bcrypt
from email_validator import validate_email,EmailNotValidError
from datetime import datetime,timezone
from pymysql.err import IntegrityError
import jwt
import re


async def get_connection(db):
    """
     connects to database and return the connection (MYSQL)
    """
    return await aiomysql.connect(
        host="localhost",
        user="app_user",
        password="strong_password",
        database=db
    )


def isValidEmail(email):
    """
    validate the input email and return boolean
    """
    try:
        validate_email(email)
        return True
    except EmailNotValidError:
        return False


def isValidUserName(username):
    USERNAME_REGEX = r"^[a-zA-Z0-9._]{3,30}$"
    username = username.strip()
    if not username:
        return "Username is required"
    
    if not re.match(USERNAME_REGEX, username):
        return (
            "Username must be 3-30 characters and contain only "
            "letters, numbers, dots, or underscores"
        )

    return None #valid

def isValidPassword(password):
    if len(password) < 8:
        return "Password must be at least 8 characters"

    if len(password) > 128:
        return "Password too long"

    if " " in password:
        return "Password cannot contain spaces"

    if not re.search(r"[A-Z]", password):
        return "Password must contain an uppercase letter"

    if not re.search(r"[a-z]", password):
        return "Password must contain a lowercase letter"

    if not re.search(r"\d", password):
        return "Password must contain a number"

    return None

def generate_token(email):
    payload={
        "email":email,
    }
    pass


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
    username:str
    password:str
    confirm_password:str


#todo signup

@app.post("/signup")
async def signup(x:user_input_signup):
    username=x.username.strip()
    email=x.email.strip()
    password_check=isValidPassword(x.password) is None and x.password==x.confirm_password
    email_check=isValidEmail(email)
    username_check=isValidUserName(username) is None

    if password_check and email_check and username_check:
        query="INSERT INTO user_metadata (email,password,creation_date,username)VALUES(%s,%s,%s,%s)"
        creation_time=datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")


        connection=await get_connection("chat_db")
        cursor=await connection.cursor()


        try:
            
            await cursor.execute(query,(email,bcrypt.hashpw(x.password.encode(), bcrypt.gensalt()).decode(),creation_time,username))
            await connection.commit()
            
            
            return{
                "process":"signup",
                "errors":0,
                "status":"success"
            }
        except IntegrityError as e:
            msg=str(e).lower()
            if "email" in msg:
                return{
                    "process":"signup",
                    "errors":1,
                    "error1":"accountexisting"
                }
            if "username" in msg:
                return{
                    "process":"signup",
                    "errors":1,
                    "error1":"usernameexisting"
                }
            
        finally:
            await cursor.close()
            connection.close()
    else:
        errors={
            "process":"signup",
            "errors":0
        }
        if not email_check:
            errors["errors"]+=1
            errors[f"error{errors['errors']}"]="notvalidemail"
        if not password_check:
            errors["errors"]+=1
            errors[f"error{errors['errors']}"]="pwdnomatch"
        if not username_check:
            errors["errors"]+=1
            errors[f"error{errors['errors']}"]="invalidusername"
        return errors

#otp verification also


#todo tokenization for session management
@app.post("/login")
async def login(x:user_input):
    email=x.email.strip()
    query="SELECT password FROM user_metadata WHERE email=%s"

    connection=await get_connection("chat_db")
    cursor=await connection.cursor()
    try:
        await cursor.execute(query,(email,))
        creds=await cursor.fetchone()
        
        if creds is None:
            return{
                "process":"login",
                "status":"fail"
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
    finally:
        await cursor.close()
        connection.close()