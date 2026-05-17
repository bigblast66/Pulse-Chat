from fastapi import FastAPI,HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel
import aiomysql
import bcrypt
from email_validator import validate_email,EmailNotValidError
from datetime import datetime,timezone,timedelta
from pymysql.err import IntegrityError
import jwt
import re
from dotenv import load_dotenv
import os
import redis.asyncio as redis


r=redis.Redis(host='localhost',port=6379,decode_responses=True)

async def get_connection(db_name):
    """
     connects to database and return the connection (MYSQL)
    """
    return await aiomysql.connect(
        host="localhost",
        user="app_user",
        password="strong_password",
        db=db_name
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
    """
    username validation with regex
    """
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
    """
    password validation
    """
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

load_dotenv()
SECRET_KEY=os.getenv("JWT_SECRET")

def generate_token(email,username):
    """
    token generation for session management
    """
    payload={
        "username":username,
        "email":email,
        "exp":datetime.now(timezone.utc)+timedelta(days=1)
    }
    token=jwt.encode(payload,SECRET_KEY,algorithm="HS256")
    return token


app=FastAPI()
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://127.0.0.1:5500"],
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
    """
    all signup queries run this function validates email pwd username, raises exception if same email/username in db also prevents racing and generates a token
    on successs.
    hashed password stored never plain
    """
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
            # response=JSONResponse(
            #     content={
            #         "process":"signup",
            #         "errors":0,
            #         "status":"success"
            #     }
            # )
            # response.set_cookie(
            #     key="token",
            #     value=generate_token(email,username),
            #     httponly=True,
            #     secure=False,
            #     samesite="lax",
            #     max_age=60*60*24
            # )
            
            content={
                    "process":"signup",
                    "errors":0,
                    "status":"success",
                    "token":generate_token(email,username)
                }
            
            return content

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
            errors[f"error{errors['errors']}"]="pwdnomatch" if x.password!=x.confirm_password else isValidPassword(x.password)
        if not username_check:
            errors["errors"]+=1
            errors[f"error{errors['errors']}"]="invalidusername"
        return errors

#otp verification also


#todo tokenization for session management
@app.post("/login")
async def login(x:user_input):
    """
    all login queries hit this function checks database and validates.
    hashes the pwd then checks with existing hash pwd.
    """
    email=x.email.strip()
    query="SELECT password,username FROM user_metadata WHERE email=%s"

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
            # response=JSONResponse(
            #     content={
            #         "process":"login",
            #         "status":"success"
            #     }
            # )
            # response.set_cookie(
            #     key="token",
            #     value=generate_token(email,creds[1]),
            #     httponly=True,
            #     secure=False,
            #     samesite="lax",
            #     max_age=60*60*24
            # )
            content={
                    "process":"login",
                    "status":"success",
                    "token":generate_token(email,creds[1])
                }
            return content
        
        return{
            "process":"login",
            "status":"fail"
        }
    finally:
        await cursor.close()
        connection.close()






def validate_token(token):
    try:
        payload=jwt.decode(token,SECRET_KEY,algorithms=["HS256"])
    except jwt.exceptions.ExpiredSignatureError as e:
        raise HTTPException(status_code=401,detail="token expired")
        
    except jwt.exceptions.DecodeError as e:
        raise HTTPException(status_code=401,detail="invalid token")
    
    return{
            "action":"redirect"
        }



@app.get("/session/{token}")
def validate_session(token:str):
    return validate_token(token)



@app.get("/me/{token}")
async def user_profile(token:str):
    connection=await get_connection("chat_db")
    cursor=await connection.cursor()
    try:
        if await r.exists(f"blacklist:{token}"):
            raise HTTPException(status_code=401,detail="invalid token")
        payload=jwt.decode(token,SECRET_KEY,algorithms=["HS256"])
        await cursor.execute("SELECT about_me,creation_date FROM user_metadata WHERE email=%s",(payload["email"],))
        detail=await cursor.fetchone()
        return{
            "email":payload["email"],
            "username":payload["username"],
            "about":detail[0],
            "creation_date":detail[1]
        }
    finally:
        await cursor.close()
        connection.close()
class about_input(BaseModel):
    about:str

@app.patch("/update_about/{token}")
async def update_about(about:about_input,token:str):
    connection=await get_connection("chat_db")
    cursor=await connection.cursor()
    query="UPDATE user_metadata SET about_me=%s WHERE email=%s"
    try:
        if await r.exists(f"blacklist:{token}"):
            raise HTTPException(status_code=401,detail="invalid token")
        payload=jwt.decode(token,SECRET_KEY,algorithms=["HS256"])
        
        await cursor.execute(query,(about.about,payload["email"]))
        await connection.commit()
    finally:
        await cursor.close()
        connection.close()


@app.get("/logout/{token}")
async def logout(token:str):
    try:
        payload=jwt.decode(token,SECRET_KEY,algorithms=["HS256"])
        exp=payload["exp"]
        now=int(datetime.now(timezone.utc).timestamp())
        ttl=exp-now
        if ttl>0:
            await r.setex(f"blacklist:{token}",ttl,"1")
    finally:
        return{
            "process":"logout",
            "status":"success"
        }





#----- REQUESTS -----


@app.get("/request_notification/{token}")
async def requests_count(token:str):
    query="SELECT COUNT(*) FROM requests WHERE receiver=%s"
    connection=await get_connection("chat_db")
    cursor=await connection.cursor()
    try:
        if await r.exists(f"blacklist:{token}"):
            raise HTTPException(status_code=401,detail="invalid token")
        payload=jwt.decode(token,SECRET_KEY,algorithms=["HS256"])
        await cursor.execute(query,(payload["username"],))
        req_count=await cursor.fetchone()
        return{
            "requests_count":req_count[0]
        }
    finally:
        await cursor.close()
        connection.close()

@app.get("/requests_list/{token}")
async def requests_list(token:str):
    query=("SELECT id,sender,req_time FROM requests WHERE receiver=%s")
    connection=await get_connection("chat_db")
    cursor=await connection.cursor()
    try:
        if await r.exists(f"blacklist:{token}"):
            raise HTTPException(status_code=401,detail="invalid token")
        payload=jwt.decode(token,SECRET_KEY,algorithms=["HS256"])
        await cursor.execute(query,(payload["username"],))
        req_list=await cursor.fetchall()
        return req_list
    finally:
        await cursor.close()
        connection.close()