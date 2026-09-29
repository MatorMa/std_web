from fastapi import FastAPI,HTTPException,Response,Request
from datetime import datetime
from pydantic import BaseModel
import hashlib,secrets
import sqlite3

conn = sqlite3.connect("blog.db")
conn.execute("""
    CREATE TABLE IF NOT EXISTS articles(
        id  INTEGER PRIMARY KEY AUTOINCREMENT,
        title TEXT, summary TEXT, date TEXT, author TEXT
    )
""")
conn.execute("""
    CREATE TABLE IF NOT EXISTS users(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE,
        password_hash TEXT,
        salt TEXT
    )
""")
conn.commit()
conn.close()

app = FastAPI(docs=None, redoc=None, openapi_url=None)

from fastapi.middleware.cors import CORSMiddleware


@app.get("/api/articles")
def get_articles():
    conn = sqlite3.connect("blog.db")
    rows = conn.execute("SELECT id, title, summary, date, author FROM articles").fetchall()
    conn.close()
    return [{"id": r[0], "title": r[1], "summary": r[2], "date": r[3],"author":r[4]}  for r in rows]

@app.get("/api/time")
def get_time():
    return {"now" : datetime.now()}

class Article(BaseModel):
    title : str
    summary : str
    date : str

@app.post("/api/articles")
def add_article(a: Article, request:Request):
    username = current_user(request)
    conn = sqlite3.connect("blog.db")
    conn.execute("INSERT INTO articles (title, summary, date, author) VALUES (?, ?, ?, ?)", (a.title, a.summary, a.date, username))
    conn.commit()
    conn.close()
    return {"ok":True}

@app.delete("/api/articles/{article_id}")
def del_article(article_id: int, request: Request):
    username = current_user(request)
    conn = sqlite3.connect("blog.db")
    rows = conn.execute("SELECT author FROM articles WHERE id = ?",(article_id,)).fetchone()
    if not rows:
        raise HTTPException(status_code=404,detail="文章不存在")
    if username != rows[0]:
        raise HTTPException(status_code=403,detail="只能删除自己的文章")
    conn.execute("DELETE FROM articles WHERE id=(?)",(article_id,))
    conn.commit()
    conn.close()
    return {"ok":True}

class user_data(BaseModel):
    username : str
    password : str

@app.post("/api/register")
def sign_up(u:user_data):
    salt = make_salt()
    h = hash_password(u.password,salt)
    try:
        conn = sqlite3.connect("blog.db")
        conn.execute("INSERT INTO users (username, password_hash, salt) VALUES (?, ?, ?)", (u.username, h, salt))
        conn.commit()
        conn.close()
    except sqlite3.IntegrityError:
        raise HTTPException(status_code=400, detail="用户名已被占用")
    return {"ok":True}


session = {}
@app.post("/api/login")
def login(u:user_data,response:Response):
    conn = sqlite3.connect("blog.db")
    row = conn.execute(
        "SELECT id, password_hash, salt FROM users WHERE username = ?",(u.username,)
    ).fetchone()
    conn.close()

    if row is None:
        raise HTTPException(status_code=401,detail="用户名或密码错误")
    if hash_password(u.password, row[2]) != row[1]:
        raise HTTPException(status_code=401,detail="用户名或密码错误")
    
    token = secrets.token_hex(16)
    session[token] = u.username
    response.set_cookie(key="session_token",value=token)
    return {"ok":True, "username": u.username}

@app.post("/api/logout")
def login_out(response:Response,request:Request):
    cookie = request.cookies.get("session_token")
    username = current_user(request)
    session.pop(cookie)
    response.delete_cookie(key="session_token")
    return {"ok":True}


@app.get("/api/me")
def me(request:Request):
    username = current_user(request)
    return {"username": username}

def make_salt():
    return secrets.token_hex(16)

def hash_password(password,salt):
    return hashlib.pbkdf2_hmac("sha256",password.encode(),salt.encode(),100_000).hex()

def current_user(request:Request):
    token = request.cookies.get("session_token")
    if token not in session:
        raise HTTPException(status_code=401,detail="未登录")
    return session[token]



from fastapi.staticfiles import StaticFiles
app.mount("/", StaticFiles(directory="static",html=True), name="static")




