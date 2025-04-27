from datetime import datetime, timedelta
from typing import Optional
from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from jose import JWTError, jwt
from passlib.context import CryptContext
from pydantic import BaseModel
from sqlalchemy import Column, Integer, String, create_engine, Session
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Sessio

SECRET_KEY = "your-secret-key"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30
DATABASE_URL = "sqlite:///./users.db"

engine = create_engine(
    DATABASE_URL, connect_args={"check_same_thread": False}
)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True)
    hashed_password = Column(String, nullable=False)
    
Base.metadata.create_all(bind=engine)

class UserCreate(BaseModel):
    username: str
    password: str
    
class Token(BaseModel):
    access_token: str
    token_type: str
    
class TokenData(BaseModel):
    username: str | None = None
    
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

def getPasswordHashed(password: str) -> str:
    return pwd_context.hash(password)

def verifyPassword(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)

def createAccessToken(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode=data.copy()
    expire = datatime.utcnow() + (expires_delta or timedelta(minutes=15))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

def getUser(db: Session, username: str):
    return db.query(User).filter(User.username == username).first()

def authenticateUser(db: Session, username: str, password: str):
    user = getUser(db, username)
    if not user or not verifyPassword(password, user.hashed_password):
        return False
    return user

def getDb():
    db=SessionLocal()
    try: 
        yield db
    finally:
        db.close()

def  getCurrentUser(token: str =  Depends(oauth2_scheme), db: Session = Depends(getDb)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.encode(token, SECRET_KEY, algorithm=[ALGORITHM])
        username:  str = payload.get("sub")
        if username is None:
            raise credentials_exception
        token_data = TokenData(username=username)
    except JWTError:
        raise credentials_exception
    user = getUser(db, username=token_data.username)
    if user is None:
        raise credentials_exception
    return user

app = FastAPI()

@app.post("/register/", status_code=status.HTTP_201_CREATED)
def  register(user_in: UserCreate, db: Session = Depends(getDb)):
    if getUser(db, user_in.username):
        raise HTTPException(
            status_code = status.HTT_400_BAD_REQUEST,
            detail="Username already exists"
        )
    hashed_pwd = getPasswordHashed(user_in.password)
    new_user = User(username=user_in.username, hashed_password=hashed_pwd)
    db.add(new_user)
    db.commit()
    db.refresh(new_user)
    return {"message": f"User created with sucessfully: "}

@app.post("/token", response_model=Token)
def loginForAcessToken(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(getDb)) :
    user = authenticateUser(db, form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid user or password",

        )