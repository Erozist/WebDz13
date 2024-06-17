from fastapi import APIRouter, Depends, HTTPException, status, UploadFile, File
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy.ext.asyncio import AsyncSession
from datetime import timedelta
from src.database.db import get_db
from src.schemas.schemas import UserCreate, User, Token, UserBase
from src.repository import users
from src.utils.utils import create_access_token, create_refresh_token, authenticate_user, get_current_user, decode_token
from src.utils.cloudinary import upload_image
from src.utils.email import EmailSchema, send_email

router = APIRouter(
    prefix="/auth",
    tags=["auth"]
)

ACCESS_TOKEN_EXPIRE_MINUTES = 60
REFRESH_TOKEN_EXPIRE_MINUTES = 60 * 24 * 7  # 7 days

@router.post("/register/", response_model=User, status_code=status.HTTP_201_CREATED)
async def register(user: UserCreate, db: AsyncSession = Depends(get_db)):
    db_user = await users.get_user_by_email(db, email=user.email)
    if db_user:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Email already registered")
    new_user = await users.create_user(db=db, user=user)
    # Відправка листа для верифікації
    verification_url = f"http://http://127.0.0.1:8000/verify?token={create_access_token({'sub': user.email})}"
    email = EmailSchema(email=[user.email])
    await send_email(email, "Verify your email", f"Please click the link to verify your email: {verification_url}")
    return new_user

@router.post("/login/", response_model=Token)
async def login(body: OAuth2PasswordRequestForm = Depends(), db: AsyncSession = Depends(get_db)):
    user = await authenticate_user(db, email=body.username, password=body.password)
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Incorrect email or password")
    
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    refresh_token_expires = timedelta(minutes=REFRESH_TOKEN_EXPIRE_MINUTES)
    
    access_token = create_access_token(data={"sub": user.email}, expires_delta=access_token_expires)
    refresh_token = create_refresh_token(data={"sub": user.email}, expires_delta=refresh_token_expires)
    
    return {"access_token": access_token, "refresh_token": refresh_token, "token_type": "bearer"}

@router.get("/users/me/", response_model=User)
async def read_users_me(current_user: User = Depends(get_current_user)):
    return current_user

@router.get("/verify")
async def verify_email(token: str, db: AsyncSession = Depends(get_db)):
    email = decode_token(token)
    user = await users.get_user_by_email(db, email=email)
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
    user.is_verified = True
    db.add(user)
    await db.commit()
    return {"message": "Email verified successfully"}

@router.post("/upload-avatar/")
async def upload_avatar(file: UploadFile = File(...), current_user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    url = upload_image(file.file)
    current_user.avatar_url = url
    db.add(current_user)
    await db.commit()
    return {"avatar_url": url}


# @router.post("/send_mail")
# async def send_mail(user: UserBase):

#     verification_url = f"http://http://127.0.0.1:8000/verify?token={create_access_token({'sub': user.email})}"
#     email = EmailSchema(email=[user.email])
#     await send_email(email, "Verify your email", f"Please click the link to verify your email: {verification_url}")
#     message = "Check your email for confirmation."
#     return message
