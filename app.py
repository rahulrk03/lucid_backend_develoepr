# main.py

from fastapi import FastAPI, Depends, HTTPException
from pydantic import BaseModel
from typing import List
from sqlalchemy import create_engine, Column, Integer, String, DateTime
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from sqlalchemy.sql import func
from jose import JWTError, jwt
from datetime import datetime, timedelta
from cachetools import TTLCache

# SQLAlchemy setup
SQLALCHEMY_DATABASE_URL = "mysql+pymysql://username:password@localhost/dbname"
engine = create_engine(SQLALCHEMY_DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

# JWT setup
SECRET_KEY = "your-secret-key"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

# Caching setup
cache = TTLCache(maxsize=1000, ttl=300)

# Define models
class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    email = Column(String, unique=True, index=True)
    password = Column(String)

class Post(Base):
    __tablename__ = "posts"

    id = Column(Integer, primary_key=True, index=True)
    text = Column(String)
    owner_id = Column(Integer)
    created_at = Column(DateTime, default=func.now())

# Create tables
Base.metadata.create_all(bind=engine)

# FastAPI app instance
app = FastAPI()

# Pydantic schemas
class UserCreate(BaseModel):
    email: str
    password: str

class UserLogin(BaseModel):
    email: str
    password: str

class PostCreate(BaseModel):
    text: str

class TokenData(BaseModel):
    email: str = None

class Token(BaseModel):
    access_token: str
    token_type: str

# Dependency to get DB session
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# Dependency to authenticate user and get token data
async def get_current_user(token: str = Depends()):
    credentials_exception = HTTPException(
        status_code=401,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )

    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        email: str = payload.get("sub")
        if email is None:
            raise credentials_exception
        token_data = TokenData(email=email)
    except JWTError:
        raise credentials_exception

    return token_data

# Signup endpoint
@app.post("/signup/", response_model=Token)
def signup(user: UserCreate, db: Session = Depends(get_db)):
    db_user = db.query(User).filter(User.email == user.email).first()
    if db_user:
        raise HTTPException(status_code=400, detail="Email already registered")
    db_user = User(email=user.email, password=user.password)
    db.add(db_user)
    db.commit()
    return create_access_token(data={"sub": user.email})

# Login endpoint
@app.post("/login/", response_model=Token)
def login(user: UserLogin, db: Session = Depends(get_db)):
    db_user = db.query(User).filter(User.email == user.email).first()
    if db_user is None or db_user.password != user.password:
        raise HTTPException(status_code=401, detail="Incorrect email or password")
    return create_access_token(data={"sub": user.email})

# AddPost endpoint
@app.post("/addPost/", response_model=int)
def add_post(post: PostCreate, current_user: TokenData = Depends(get_current_user), db: Session = Depends(get_db)):
    if len(post.text) > 1024:
        raise HTTPException(status_code=400, detail="Post text too long")

    new_post = Post(text=post.text, owner_id=current_user.email)
    db.add(new_post)
    db.commit()
    return new_post.id

# GetPosts endpoint
@app.get("/getPosts/", response_model=List[Post])
def get_posts(current_user: TokenData = Depends(get_current_user), db: Session = Depends(get_db)):
    if current_user.email in cache:
        return cache[current_user.email]

    posts = db.query(Post).filter(Post.owner_id == current_user.email).all()
    cache[current_user.email] = posts
    return posts

# DeletePost endpoint
@app.delete("/deletePost/{post_id}", response_model=str)
def delete_post(post_id: int, current_user: TokenData = Depends(get_current_user), db: Session = Depends(get_db)):
    post = db.query(Post).filter(Post.id == post_id, Post.owner_id == current_user.email).first()
    if post is None:
        raise HTTPException(status_code=404, detail="Post not found")
    db.delete(post)
    db.commit()
    return "Post deleted successfully"

# Token functions
def create_access_token(data: dict, expires_delta: timedelta = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return Token(access_token=encoded_jwt, token_type="bearer")

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)
