from fastapi import FastAPI,HTTPException,WebSocket,WebSocketDisconnect,Request,Response
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
import json
import hashlib
import ssl
import httpx
from typing import Optional

load_dotenv()

DB_HOST = os.getenv("DB_HOST")
DB_USER = os.getenv("DB_USER")
DB_PASSWORD = os.getenv("DB_PASSWORD")
DB_NAME = os.getenv("DB_NAME")
REDIS_HOST = os.getenv("REDIS_HOST")
REDIS_PORT = int(os.getenv("REDIS_PORT"))
ALLOWED_ORIGIN = os.getenv("ALLOWED_ORIGIN", "").split(",")
# cert_content= os.getenv("DB_CERT")
# DB_PORT= int(os.getenv("DB_PORT"))

r=redis.Redis(host=REDIS_HOST,port=REDIS_PORT,decode_responses=True)
# r=redis.from_url(os.getenv("REDIS_URL"),decode_responses=True)
async def get_connection(db_name):
    """
     connects to database and return the connection (MYSQL)
    """
    return await aiomysql.connect(
        host=DB_HOST,
        user=DB_USER,
        password=DB_PASSWORD,
        db=db_name
    )
    # ssl_context = ssl.create_default_context()
    # ssl_context.load_verify_locations(cadata=cert_content)

    # return await aiomysql.connect(
    #     host=DB_HOST,
    #     user=DB_USER,
    #     password=DB_PASSWORD,
    #     port=DB_PORT,
    #     db=db_name,
    #     ssl=ssl_context
    # )



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
    allow_origins=ALLOWED_ORIGIN,
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


        connection=await get_connection(DB_NAME)
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
            

            response=JSONResponse(
                content={
                    "process":"signup",
                    "errors":0,
                    "status":"success"
                }
            )
            response.set_cookie(
                key="token",
                value=generate_token(email,username),
                httponly=True,
                secure=False,
                samesite="lax",
                max_age=60*60*24
            )
            
            return response
            
            

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

    connection=await get_connection(DB_NAME)
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
            response=JSONResponse(
                content={
                    "process":"login",
                    "status":"success"
                }
            )
            response.set_cookie(
                key="token",
                value=generate_token(email,creds[1]),
                httponly=True,
                secure=False,
                samesite="lax",
                max_age=60*60*24
            )
            
            return response
        
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



@app.get("/session")
async def validate_session(request: Request):
    token=request.cookies.get("token")
    try:
        if await r.exists(f"blacklist:{token}"):
                raise HTTPException(status_code=401,detail="invalid token")
    except:
        pass
    return validate_token(token)



@app.get("/me")
async def user_profile(request: Request):
    token=request.cookies.get("token")
    connection=await get_connection(DB_NAME)
    cursor=await connection.cursor()
    try:
        if await r.exists(f"blacklist:{token}"):
            raise HTTPException(status_code=401,detail="invalid token")
        payload=jwt.decode(token,SECRET_KEY,algorithms=["HS256"])
      
        cached=await r.get(f"profile:{payload['username']}")
        if cached is not None:
            return json.loads(cached)
    
        await cursor.execute("SELECT about_me,creation_date FROM user_metadata WHERE email=%s",(payload["email"],))
        detail=await cursor.fetchone()
        data={
            "email":payload["email"],
            "username":payload["username"],
            "about":detail[0],
            "creation_date":detail[1]
        }
        await r.setex(f"profile:{payload['username']}",300,json.dumps(data))
        return data
    finally:
        await cursor.close()
        connection.close()
class about_input(BaseModel):
    about:str

@app.patch("/update_about")
async def update_about(about:about_input,request:Request):
    token=request.cookies.get("token")
    connection=await get_connection(DB_NAME)
    cursor=await connection.cursor()
    query="UPDATE user_metadata SET about_me=%s WHERE email=%s"
    try:
        if await r.exists(f"blacklist:{token}"):
            raise HTTPException(status_code=401,detail="invalid token")
        payload=jwt.decode(token,SECRET_KEY,algorithms=["HS256"])
        await r.delete(f"profile:{payload['username']}")
        
        await cursor.execute(query,(about.about,payload["email"]))
        await connection.commit()
    finally:
        await cursor.close()
        connection.close()


@app.get("/logout")
async def logout(request:Request,response: Response):
    token=request.cookies.get("token")
    try:
        payload=jwt.decode(token,SECRET_KEY,algorithms=["HS256"])
        exp=payload["exp"]
        now=int(datetime.now(timezone.utc).timestamp())
        ttl=exp-now
        if ttl>0:
            await r.setex(f"blacklist:{token}",ttl,"1")
    finally:
        response=JSONResponse(content={ "process":"logout","status":"success"})
        response.delete_cookie(
            key="token",
            httponly=True,
            secure=False,
            samesite="lax"
        )
        return response





#----- REQUESTS -----


@app.get("/request_notification")
async def requests_count(request:Request):
    token=request.cookies.get("token")
    query="SELECT COUNT(*) FROM requests WHERE receiver=%s"
    connection=await get_connection(DB_NAME)
    cursor=await connection.cursor()
    try:
        if await r.exists(f"blacklist:{token}"):
            raise HTTPException(status_code=401,detail="invalid token")
        payload=jwt.decode(token,SECRET_KEY,algorithms=["HS256"])
        cached=await r.get(f"req_count:{payload['username']}")
        if cached is not None:
            return {"requests_count":cached}

        await cursor.execute(query,(payload["username"],))
        req_count=await cursor.fetchone()
        data={
            "requests_count":req_count[0]
        }
        await r.set(f"req_count:{payload['username']}",req_count[0])
        return data
    finally:
        await cursor.close()
        connection.close()

@app.get("/requests_list")
async def requests_list(request:Request):
    token=request.cookies.get("token")
    query=("SELECT id,sender,req_time FROM requests WHERE receiver=%s")
    connection=await get_connection(DB_NAME)
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



@app.get("/requests_list_outgoing")
async def requests_list(request:Request):
    token=request.cookies.get("token")
    query=("SELECT id,receiver,req_time FROM requests WHERE sender=%s")
    connection=await get_connection(DB_NAME)
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

user_socket={}
socket_user={}

async def safe_send(soc, data: str):
    """Send to a websocket, silently removing it if it's already closed."""
    try:
        await soc.send_text(data)
    except Exception:
        # Socket is closed/broken — remove it from the registry
        username = socket_user.pop(soc, None)
        if username and user_socket.get(username):
            try:
                user_socket[username].remove(soc)
            except ValueError:
                pass
            if not user_socket[username]:
                del user_socket[username]


#todo make outgoing req in frontend and send outgoing req list and sending a  req to a user also and taking back requests also
#make friends table and decide how do u want it rn plan is user a user b date




@app.websocket("/pulse")
async def socket_manager(websocket: WebSocket):


    await websocket.accept()
    token=websocket.cookies.get("token")

    try:
        if await r.exists(f"blacklist:{token}"):
            await websocket.close(code=4001)
            return
        payload=jwt.decode(token,SECRET_KEY,algorithms=["HS256"])


        if user_socket.get(payload["username"]) is None:
            user_socket[payload["username"]]=[websocket]
            socket_user[websocket]=payload["username"]
        else:
            user_socket[payload["username"]].append(websocket)
            socket_user[websocket]=payload["username"]


        while True:
            data=await websocket.receive_text()
            data=json.loads(data)
            if data["type"]=="request":
                query1="DELETE FROM requests WHERE id=%s"
                connection=await get_connection(DB_NAME)
                cursor=await connection.cursor()
                try:
                    await cursor.execute(query1,(data["id"],))
                    if await r.exists(f"req_count:{payload['username']}"):
                        await r.decr(f"req_count:{payload['username']}")
                    if data["status"]=="accept":
                        query2="INSERT INTO friends (user1,user2,friend_date,chat_id) VALUES(%s,%s,%s,%s)"
                        friend_date=datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
                        x=payload["username"] if payload["username"]<data["username"] else data["username"]
                        y=payload["username"] if payload["username"]>data["username"] else data["username"]
                        chat_id=hashlib.sha256((x+y).encode()).hexdigest()
                        await cursor.execute(query2,(socket_user[websocket],data["username"],friend_date,chat_id))
                        await cursor.execute(query2,(data["username"],socket_user[websocket],friend_date,chat_id))

                        query6="INSERT INTO read_receipts (last_read_id,chat_id,username) VALUES(%s,%s,%s)"

                        await cursor.execute(query6,(0,chat_id,payload["username"]))
                        await cursor.execute(query6,(0,chat_id,data["username"]))

                        
                        for soc in user_socket.get(data["username"],[]):
                            await safe_send(soc,json.dumps({
                                "type":"request",
                                "status":"accepted",
                                "username":socket_user[websocket]
                            }))
                        for soc in user_socket.get(payload["username"],[]):
                            await safe_send(soc,json.dumps({
                                "type":"request",
                                "status":"accepted",
                                "username":data["username"]
                            }))
                    else:
                        
                        for soc in user_socket.get(data["username"],[]):
                            await safe_send(soc,json.dumps({
                                "type":"request",
                                "status":"rejected",
                                "username":socket_user[websocket]
                            }))
                            #sending to the guy who rejected maybe multiple tabs
                        for soc in user_socket.get(payload["username"],[]):
                            await safe_send(soc,json.dumps({
                                "type":"request",
                                "status":"rejected",
                                "username":data["username"]
                            }))
                finally:
                    await connection.commit()
                    await cursor.close()
                    connection.close()
            elif data["type"]=="request_send":
                query1="SELECT username FROM user_metadata WHERE username=%s"
                query2="SELECT user1 FROM friends WHERE user1=%s AND user2=%s"
                query3="SELECT sender,receiver FROM requests WHERE sender=%s AND receiver=%s"
                if data["username"]==payload["username"]:
                    continue
                connection=await get_connection(DB_NAME)
                cursor=await connection.cursor()
                try:
                    await cursor.execute(query3,(payload["username"],data["username"]))
                    a=await cursor.fetchone()
                    if a is not None:
                        await safe_send(websocket,json.dumps({
                            "type":"request_send",
                            "reason":"request_exists"
                        }))
                        continue
                    await cursor.execute(query3,(data["username"],payload["username"]))
                    d=await cursor.fetchone()
                    if d is not None:
                        await safe_send(websocket,json.dumps({
                            "type":"request_send",
                            "reason":"request_from_user_exists"
                        }))
                        continue
                    await cursor.execute(query2,(payload["username"],data["username"]))
                    b=await cursor.fetchone()
                    if b is not None:
                        await safe_send(websocket,json.dumps({
                            "type":"request_send",
                            "reason":"already_friend"
                        }))
                        continue
                    await cursor.execute(query1,(data["username"],))
                    c=await cursor.fetchone()
                    if c is None:
                        await safe_send(websocket,json.dumps({
                            "type":"request_send",
                            "reason":"user_no_exist"
                        }))
                        continue
                    req_time=datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
                    query4="INSERT INTO requests (sender,receiver,req_time) VALUES(%s,%s,%s)"
                    query5="SELECT LAST_INSERT_ID()"
                    
                    await cursor.execute(query4,(payload["username"],data["username"],req_time))
                    if await r.exists(f"req_count:{data['username']}"):
                        await r.incr(f"req_count:{data['username']}")
                    await connection.commit()
                    await cursor.execute(query5)
                    e=await cursor.fetchone()
                    for soc in user_socket.get(payload["username"],[]):
                        await safe_send(soc,json.dumps({
                            "type":"request_send",
                            "reason":"success",
                            "req_detail":[e[0],data["username"],req_time]
                        }))
                    for soc in user_socket.get(data["username"],[]):
                        await safe_send(soc,json.dumps({
                            "type":"request_receive",
                            "req_detail":[e[0],payload["username"],req_time]
                        }))
                finally:
                    await cursor.close()
                    connection.close()
            elif data["type"]=="request_takeback":
                query1="DELETE FROM requests WHERE id=%s"
                connection=await get_connection(DB_NAME)
                cursor=await connection.cursor()
                try:
                    await cursor.execute(query1,(data["id"],))
                    if await r.exists(f"req_count:{data['username']}"):
                        await r.decr(f"req_count:{data['username']}")
                    await connection.commit()
                    for soc in user_socket.get(payload["username"],[]):
                        await safe_send(soc,json.dumps({
                            "type":"request_takeback",
                            "req_detail":[data["id"],data["username"]]
                        }))
                    for soc in user_socket.get(data["username"],[]):
                        await safe_send(soc,json.dumps({
                            "type":"request_takeback",
                            "req_detail":[data["id"],payload["username"]]
                        }))
                finally:
                    await cursor.close()
                    connection.close()
            elif data["type"]=="send_message":
                query1="INSERT INTO chats (chat_id,sender,content,sent_at,replied_to) VALUES(%s,%s,%s,%s,%s)"
                query2="SELECT user1 FROM friends WHERE chat_id=%s"
                query3="SELECT sender,content,sent_at FROM chats WHERE id=%s"

                sent_time=datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
                connection=await get_connection(DB_NAME)
                cursor=await connection.cursor()
                try:
                    await cursor.execute(query2,(data["chat_id"],))
                    res=await cursor.fetchall()
                    members={res[0][0],res[1][0]}
                    if payload["username"]==data["username"]:
                        continue
                    if payload["username"] not in members:
                        continue
                    if data["username"] not in members:
                        continue
                    replied=data.get("replied_to")
                    replied_content=None
                    await cursor.execute(query1,(data["chat_id"],payload["username"],data["content"],sent_time,replied))
                    if replied is not None:
                        await cursor.execute(query3,(replied,))
                        replied_msg=await cursor.fetchone()
                        replied_content=replied_msg[0]

                    query2="SELECT LAST_INSERT_ID()"
                    await cursor.execute(query2)
                    res=await cursor.fetchone()
                    await r.delete(f"sidebar:{payload['username']}")
                    await r.delete(f"sidebar:{data['username']}")
                    for soc in user_socket.get(payload["username"],[]):
                        await safe_send(soc,json.dumps({
                            "type":"sent_message",
                            "content":data["content"],
                            "chat_id":data["chat_id"],
                            "sent_at":sent_time,
                            "id":res[0],
                            "sender":payload["username"],
                            "replied_to":replied,
                            "replied_content":replied_content
                        }))
                    for soc in user_socket.get(data["username"],[]):
                        await safe_send(soc,json.dumps({
                            "type":"receive_message",
                            "content":data["content"],
                            "chat_id":data["chat_id"],
                            "sent_at":sent_time,
                            "id":res[0],
                            "sender":payload["username"],
                            "replied_to":replied,
                            "replied_content":replied_content
                        }))
                finally:
                    await connection.commit()
                    await cursor.close()
                    connection.close()
            elif data["type"]=="update_read_receipt":
                connection=await get_connection(DB_NAME)
                cursor=await connection.cursor()
                try:
                    
                    query="UPDATE read_receipts SET last_read_id=%s WHERE chat_id=%s AND username=%s"
                    await cursor.execute(query,(data["id"],data["chat_id"],payload["username"]))
                    for soc in user_socket.get(payload["username"],[]):
                        await safe_send(soc,json.dumps({
                            "type":"updated_read_receipt",
                            "id":data["id"],
                            "chat_id":data["chat_id"]
                        }))


                finally:
                    await connection.commit()
                    await cursor.close()
                    connection.close()
            elif data["type"]=="typing":
                if await r.exists(f"typing:{payload['username']}:{data['username']}"):
                    continue
                await r.setex(f"typing:{payload['username']}:{data['username']}",3,1)
                for soc in user_socket.get(data['username'],[]):
                    await safe_send(soc,json.dumps({
                        "type":"typing",
                        "username":payload['username'],
                        "chat_id":data["chat_id"]
                    }))

    except WebSocketDisconnect:
        username=socket_user[websocket]
        if socket_user.get(websocket) is not None:
            del socket_user[websocket]
        if username is not None and user_socket.get(username) is not None:
            if len(user_socket[username])==1:
                del user_socket[username]
            else:
                user_socket[username].remove(websocket)



@app.get("/load_sidebar/{id}")
async def load_sidebar(request:Request,id: int):
    token=request.cookies.get("token")
    connection=await get_connection(DB_NAME)
    cursor=await connection.cursor()
    try:
        if await r.exists(f"blacklist:{token}"):
            return
        payload=jwt.decode(token,SECRET_KEY,algorithms=["HS256"])
        if id==999999999:
            cached=await r.get(f"sidebar:{payload['username']}")
            if cached is not None:
                return json.loads(cached)
        query = """
                SELECT a.user2, a.chat_id, b.sender, b.content, b.sent_at, b.id as last_id,
                    (
                        SELECT COUNT(*) FROM chats c
                        WHERE c.chat_id = a.chat_id
                        AND c.id > COALESCE((
                            SELECT last_read_id FROM read_receipts
                            WHERE chat_id = a.chat_id AND username = %s
                        ), 0)
                        AND c.sender != %s
                    ) as unread_count
                FROM friends a
                LEFT JOIN chats b ON b.id = (
                    SELECT MAX(id) FROM chats WHERE chat_id = a.chat_id
                )
                WHERE a.user1 = %s AND (b.id < %s OR b.id IS NULL)
                ORDER BY b.id DESC
                LIMIT 50
            """
        await cursor.execute(query,(payload["username"],payload["username"],payload["username"],id))
        result=await cursor.fetchall()
        if id==999999999:
            await r.setex(f"sidebar:{payload['username']}",3600,json.dumps(result))
        return result

    
    finally:
        await cursor.close()
        connection.close()

@app.get("/load_chat/{id}/{chat_id}")
async def load_sidebar(request:Request,id: int,chat_id:str):
    token=request.cookies.get("token")
    connection=await get_connection(DB_NAME)
    cursor=await connection.cursor()
    try:
        if await r.exists(f"blacklist:{token}"):
            return
        payload=jwt.decode(token,SECRET_KEY,algorithms=["HS256"])

        query = """
    SELECT a.id, a.chat_id, a.sender, a.content, a.sent_at, a.replied_to,
           att.public_url, att.content_type, att.original_name, att.size_bytes
    FROM chats a
    LEFT JOIN attachments att ON att.id = a.attachment_id
    LEFT JOIN chats b ON a.replied_to = b.id
    WHERE a.chat_id=%s AND a.id<%s
    ORDER BY a.id DESC
    LIMIT 50
"""
        await cursor.execute(query,(chat_id,id))
        
        result=await cursor.fetchall()
        return result

    
    finally:
        await cursor.close()
        connection.close()

@app.get("/load_chat_after/{id}/{chat_id}")
async def load_chat_after(request:Request, id: int, chat_id: str):
    token=request.cookies.get("token")
    connection=await get_connection(DB_NAME)
    cursor=await connection.cursor()
    try:
        if await r.exists(f"blacklist:{token}"):
            return
        payload=jwt.decode(token,SECRET_KEY,algorithms=["HS256"])

        query = """
            SELECT a.id, a.chat_id, a.sender, a.content, a.sent_at, a.replied_to,
                att.public_url, att.content_type, att.original_name, att.size_bytes
            FROM chats a
            LEFT JOIN attachments att ON att.id = a.attachment_id
            LEFT JOIN chats b ON a.replied_to = b.id
            WHERE a.chat_id=%s AND a.id>%s
            ORDER BY a.id DESC
            LIMIT 50
        """
        await cursor.execute(query,(chat_id,id))
        
        result=await cursor.fetchall()
        return result

    
    finally:
        await cursor.close()
        connection.close()

# @app.patch("/update_read_receipt/{token}/{id}/{chat_id}")
# async def update_read_receipt(token:str,chat_id:str,id:int):
#     connection=await get_connection(DB_NAME)
#     cursor=await connection.cursor()
#     try:
#         if await r.exists(f"blacklist:{token}"):
#             return
#         payload=jwt.decode(token,SECRET_KEY,algorithms=["HS256"])

#         query="UPDATE read_receipts SET last_read_id=%s WHERE chat_id=%s AND username=%s"

#         await cursor.execute(query,(id,chat_id,payload["username"]))
#     finally:
#         await connection.commit()
#         await cursor.close()
#         connection.close()

@app.get("/search_sidebar/{input}")
async def search_sidebar(request:Request,input:str):
    token=request.cookies.get("token")
    connection=await get_connection(DB_NAME)
    cursor=await connection.cursor()
    try:
        if await r.exists(f"blacklist:{token}"):
            return
        payload=jwt.decode(token,SECRET_KEY,algorithms=["HS256"])

        query="SELECT user2 FROM friends WHERE user1=%s AND user2 LIKE %s"
        await cursor.execute(query,(payload["username"],f"{input.strip()}%"))
        results=await cursor.fetchall()
        return results
    finally:
        await cursor.close()
        connection.close()

@app.get("/search_chat/{chat_id}/{input}/{id}")
async def search_chat(request:Request,chat_id:str,input:str,id:int):
    token=request.cookies.get("token")
    connection=await get_connection(DB_NAME)
    cursor=await connection.cursor()
    try:
        if await r.exists(f"blacklist:{token}"):
            return
        payload=jwt.decode(token,SECRET_KEY,algorithms=["HS256"])

        query="SELECT id,sender,content,sent_at FROM chats WHERE content LIKE %s AND id<%s ORDER BY id DESC LIMIT 50"
        await cursor.execute(query,(f"%{input.strip()}%",id))
        results=await cursor.fetchall()
        return results
    finally:
        await cursor.close()
        connection.close()


S3_TOKEN=os.getenv("S3_TOKEN")

class file_details(BaseModel):
    filename:str
    content_type:str
    size_bytes:int




def is_valid_filename(filename: str):
    if not filename:
        return False

    if len(filename) > 255:
        return False

    # no leading/trailing spaces
    if filename != filename.strip():
        return False

    # block path traversal
    if "/" in filename or "\\" in filename:
        return False

    # block weird names
    if filename in [".", ".."]:
        return False

    # allow letters, numbers, spaces, dots, dashes, underscores
    if not re.fullmatch(r"[A-Za-z0-9._\- ]+", filename):
        return False

    return True




@app.post("/upload_media/{chat_id}")
async def upload_media(request:Request,chat_id:str,file:file_details):
    token=request.cookies.get("token")
    try:
        if await r.exists(f"blacklist:{token}"):
            return
        payload=jwt.decode(token,SECRET_KEY,algorithms=["HS256"])
        

        ALLOWED_CONTENT_TYPES = [
        # Images
        "image/jpeg",
        "image/png",
        "image/webp",
        "image/gif",
        "image/avif",

        # Videos
        "video/mp4",
        "video/webm",
        "video/quicktime",

        # Audio
        "audio/mpeg",
        "audio/mp4",
        "audio/wav",
        "audio/webm",
        "audio/ogg",

        # Documents
        "application/pdf",
        "application/msword",
        "application/vnd.openxmlformats-officedocument.wordprocessingml.document",

        # Text
        "text/plain",

        # Archives
        "application/zip",
        "application/x-zip-compressed",
        ]




        if file.size_bytes >=10*1024*1024 or file.size_bytes<=0:
            raise HTTPException(status_code=413,detail="File too large")
        if file.content_type not in ALLOWED_CONTENT_TYPES:
            raise HTTPException(status_code=400,detail="Unsupported file type")
        if is_valid_filename(file.filename)==False:
            raise HTTPException(status_code=400,detail="Filename is invalid")
        async with httpx.AsyncClient() as client:
            response=await client.post("https://putput.io/api/v1/upload/presign",
                                            headers={
                                                "Authorization":f"Bearer {S3_TOKEN}",
                                                "Content-Type":"application/json"
                                            },
                                            json={
                                                "filename":file.filename,
                                                "content_type":file.content_type,
                                                "size_bytes":file.size_bytes
                                            })
        data=response.json()
        return JSONResponse(
                content=data,
                status_code=response.status_code
            )
    except:
        pass

class upload_id(BaseModel):
    uploadid:str
    message:Optional[str]=None
    username:str
    id:Optional[int]=None
    replied_content:Optional[str]=None
@app.post("/confirm_media/{chat_id}")
async def confirm_media(request:Request,chat_id:str,x:upload_id):
    token=request.cookies.get("token")
    try:
        if await r.exists(f"blacklist:{token}"):
            return
        payload=jwt.decode(token,SECRET_KEY,algorithms=["HS256"])
        async with httpx.AsyncClient() as client:
            response=await client.post("https://putput.io/api/v1/upload/confirm",headers={
                                                        "Authorization":f"Bearer {S3_TOKEN}",
                                                    "Content-Type":"application/json"
                                                },
                                                json={
                                                    "upload_id":x.uploadid
                                                })
            
        query="INSERT INTO attachments (upload_id,file_id,public_url,original_name,content_type,size_bytes) VALUES(%s,%s,%s,%s,%s,%s)"
        query1="SELECT LAST_INSERT_ID()"
        query2="INSERT INTO chats (chat_id,sender,content,sent_at,replied_to,content_type,attachment_id) VALUES(%s,%s,%s,%s,%s,%s,%s)"
        sent_time=datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")

        
        data=response.json()
        if response.status_code!=200:
            return JSONResponse(
                content=data,
                status_code=response.status_code
            )
        else:
            data=data["file"]

            connection=await get_connection("chat_db")
            cursor=await connection.cursor()
            
            await cursor.execute(query,(x.uploadid,data["id"],data["public_url"],data["original_name"],data["content_type"],data["size_bytes"]))
            await cursor.execute(query1)
            res=await cursor.fetchone()
            await cursor.execute(query2,(chat_id,payload['username'],x.message,sent_time,x.id,data["content_type"],res[0]))
            await cursor.execute(query1)
            res=await cursor.fetchone()
            await connection.commit()

            for soc in user_socket.get(payload["username"],[]):
                await safe_send(soc,json.dumps({
                    "type":"sent_attachment",
                    "content":x.message,
                    "chat_id":chat_id,
                    "sent_at":sent_time,
                    "id":res[0],
                    "sender":payload["username"],
                    "replied_to":x.id,
                    "replied_content":x.replied_content,
                    "attachment_url":data["public_url"],
                    "content_type": data["content_type"],
                    "original_name": data["original_name"],
                    "size_bytes": data["size_bytes"]

                }))
            for soc in user_socket.get(x.username,[]):
                await safe_send(soc,json.dumps({
                    "type":"receive_attachment",
                    "content":x.message,
                    "chat_id":chat_id,
                    "sent_at":sent_time,
                    "id":res[0],
                    "sender":payload["username"],
                    "replied_to":x.id,
                    "replied_content":x.replied_content,
                    "attachment_url":data["public_url"],
                    "content_type": data["content_type"],
                    "original_name": data["original_name"],
                    "size_bytes": data["size_bytes"]
                }))

            return {
                "attachment_url":data["public_url"]
            }
    finally:
        if cursor:
            await cursor.close()
        if connection:
            connection.close()