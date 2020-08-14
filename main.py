

from datetime import datetime, timedelta
from typing import List, Optional
import random
from fastapi import Depends, FastAPI, HTTPException, Security, status
from fastapi.responses import JSONResponse
from fastapi.security import (
    OAuth2PasswordBearer,
    OAuth2PasswordRequestForm,
    SecurityScopes,
)
import json
import string
import requests
import re
from jose import JWTError, jwt
from passlib.context import CryptContext
from pydantic import BaseModel, ValidationError
import mysql.connector
from fastapi.middleware.cors import CORSMiddleware
# to get a string like this run:
# openssl rand -hex 32
SECRET_KEY = "09d25e094faa6ca2556c818166b7a9563b93f7099f6f0f4caa6cf63b88e8d3e7"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30
regex = '^[a-z0-9]+[\._]?[a-z0-9]+[@]\w+[.]\w{2,3}$'

cnx = mysql.connector.connect(user='sql12359904', password='Uz363CqZFF',
                                 host='sql12.freemysqlhosting.net',
                                 database='sql12359904',port=3306)
cursor = cnx.cursor()

origins = [
    "https://tesstapidai.herokuapp.com/",
    "http://localhost",
    "http://localhost:3000",
    "https://demoooo-1.herokuapp.com",
    "https://demoooo-1.herokuapp.com/login"
]



def slack_hooking(payload:str):
    slack_url="https://hooks.slack.com/services/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"
    slack_headers = {
                                'accept': "application/x-www-form-urlencoded",
                                'cache-control': "no-cache"
                            }
    slack_payload={"text": payload}
    response_slack=requests.post( slack_url, data=json.dumps(slack_payload),headers={'Content-Type': 'application/json'})

def check_email(email):  
  
    if(re.search(regex,email)):  
        return True  
    return False

def get_user_db(username:str):
    cursor.execute("select *from user where email='"+username+"'")

    myresult = cursor.fetchone()
    
    if myresult is None:
        return None
    user={
        "id": myresult[0],
        "username": myresult[1],
        "hashed_password": myresult[2],
        "disabled": myresult[4],
        "role":myresult[3]
        }
    return user

def get_country_name(country_zip:str):
    cursor.execute("select name from Country where zip_code='"+country_zip+"'")
    return cursor.fetchone()[0]

def get_channel_id(manager_id:str):
    cursor.execute("select id from channel where manager_id='"+str(manager_id)+"'")
    if cursor.fetchone() is None:
        return None
    return cursor.fetchone()[0]

def get_all_shop_admin():
    cursor.execute("select *from shop ")

    myresult = cursor.fetchall()
    all_shop=[]
    for shop in myresult:
        all_shop.append({
            "id": shop[0],
            "name": shop[1],
            "url": shop[2],
            "country_zip": shop[3],
            "sim_id": shop[4],
            "channel_id":shop[6],
            "executor_id":shop[5]
        })
    return all_shop

def get_all_shop(username:str):
    user=get_user_db(username)
    if user["role"]=="admin":
        cursor.execute("select *from shop ")
    elif user["role"]=="executor":
        cursor.execute("select *from shop where executor_id='"+str(user["id"])+"'")
    channel_id=get_channel_id(user["id"])
    if channel_id is None:
        return []
    cursor.execute("select *from shop where channel_id='"+str(channel_id)+"'")
    myresult = cursor.fetchall()
    all_shop=[]
    for shop in myresult:
        all_shop.append({
            "id": shop[0],
            "name": shop[1],
            "url": shop[2],
            "country": get_country_name(shop[3]),
            "sim_id": shop[4],
            "channel_id":shop[6],
            "executor_id":shop[5]
        })
    return all_shop
def random_password(length):
    letters = string.ascii_lowercase
    result_str = ''.join(random.choice(letters) for i in range(length))
    return result_str
    
class Token(BaseModel):
    access_token: str
    token_type: str

class Token_body(BaseModel):
    access_token: str

class TokenData(BaseModel):
    username: Optional[str] = None
    scopes: List[str] = []

class User_Account(BaseModel):
    username: str
    password: str

class NewUser(BaseModel):
    email: str
    role: str

class User(BaseModel):
    username: str
    disabled: str

class UserInDB(User):
    hashed_password: str

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

oauth2_scheme = OAuth2PasswordBearer(
    tokenUrl="token",
    scopes={"me": "Read information about the current user.", "items": "Read items."},
)

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password):
    return pwd_context.hash(password)

def create_new_user(username:str,hashed_password:str,role:str,create_date:str):
    cursor.execute("insert into user (email, password,role,create_date,disable) values ('"+username+"','"+hashed_password+"','"+role+"','"+create_date+"',0); ")
    cnx.commit()

def check_user_db(username:str):
    cursor.execute("select * from user where email='"+username+"'")
    results=cursor.fetchone()
    if results is None:
        return False
    return True
def authenticate_user(username: str, password: str):
    user = get_user_db(username)
    if user is None:
        return False
    if not verify_password(password, user["hashed_password"]):
        return False
    return user


def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt


async def get_current_user(security_scopes: SecurityScopes, token: str = Depends(oauth2_scheme)):
    if security_scopes.scopes:
        authenticate_value = f'Bearer scope="{security_scopes.scope_str}"'
    else:
        authenticate_value = f"Bearer"
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": authenticate_value},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
        token_scopes = payload.get("scopes", [])
        token_data = TokenData(scopes=token_scopes, username=username)
    except (JWTError, ValidationError):
        raise credentials_exception
    user = get_user_db(username=token_data.username)
    if user is None:
        raise credentials_exception
    for scope in security_scopes.scopes:
        if scope not in token_data.scopes:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Not enough permissions",
                headers={"WWW-Authenticate": authenticate_value},
            )
    return user

@app.post("/login/token", response_model=Token,tags=["login"])
async def login_for_access_token(User_Account : User_Account):
    user=get_user_db(User_Account.username)
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username ",
            headers={"WWW-Authenticate": "Bearer"},
        )

    if not verify_password(User_Account.password, user["hashed_password"]):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect  password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token =create_access_token(
        data={"sub": user["username"],"role":user["role"]}, expires_delta=access_token_expires
    )
    return JSONResponse({"access_token": access_token, "token_type": "bearer"})

@app.get("/admin/",tags=["admin"])
async def admin_page(token:str):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        role: str = payload.get("role")
        if role!="admin":
            raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Unauthorized ",
            headers={"WWW-Authenticate": "Bearer"},
        )
    except (JWTError, ValidationError):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Unauthorized ",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return{"message:":"Access admin page success"}

@app.get("/admin/shops",tags=["admin"])
async def get_all_shops(token:str):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        role: str = payload.get("role")
        if role!="admin":
            raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Unauthorized ",
            headers={"WWW-Authenticate": "Bearer"},
        )
        
    except (JWTError, ValidationError):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Unauthorized ",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return JSONResponse(get_all_shop())

@app.get("/executor/",tags=["executor"])
async def executor_page(token:str):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        role: str = payload.get("role")
        if role!="executor":
            raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Unauthorized ",
            headers={"WWW-Authenticate": "Bearer"},
        )
    except (JWTError, ValidationError):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Unauthorized ",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return{"message:":"Access executor page success"}
    
@app.get("/manager/",tags=["manager"])
async def manager_page(token:str):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        role: str = payload.get("role")
        if role!="manager":
            raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Unauthorized ",
            headers={"WWW-Authenticate": "Bearer"},
        )
    except (JWTError, ValidationError):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Unauthorized ",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return{"message:":"Access manager page success"}

@app.get("/manager/shops",tags=["manager"])
async def manager_page(token:str):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        role: str = payload.get("role")
        if role!="manager":
            raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Unauthorized ",
            headers={"WWW-Authenticate": "Bearer"},
        )
    except (JWTError, ValidationError):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Unauthorized ",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return{"message:":"Access manager page success"}

@app.post("/admin/new-account/",tags=["admin"])
async def create_new_account(token:str,email:str,role:str):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        roles: str = payload.get("role")
        if roles!="admin":
            raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Unauthorized ",
            headers={"WWW-Authenticate": "Bearer"},
        )
        if check_email(email)==False:
            raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid email value"
            )
        if check_user_db(email)==True:
            raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid email, email already exist "
        )
        if role!="executor" and role!="manager":
            raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Role must be executor or manager"
            )
        password=random_password(8)
        new_hashed_password=get_password_hash(password)
        create_new_user(email,new_hashed_password,role,datetime.now().strftime("%m/%d/%Y, %H:%M:%S"))
    except (JWTError, ValidationError):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Unauthorized ",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return {"message":"create success"}

@app.get("/status/")
async def read_system_status(current_user: User = Depends(get_current_user)):
    return {"status": "ok"}

