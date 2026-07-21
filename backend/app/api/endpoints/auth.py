from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.core.security import verify_password, create_access_token
from app.repositories.user_repo import UserRepository
from app.schemas.user import UserCreate, UserOut, Token

router = APIRouter(prefix="/auth", tags=["Auth"])


@router.post("/register", response_model=UserOut, status_code=status.HTTP_201_CREATED)
def register(payload: UserCreate, db: Session = Depends(get_db)):
    """
    Registrasi user baru. Untuk saat ini dipakai single-user
    (Lead Architect), tapi endpoint mendukung multi-user ke depannya.
    """
    user_repo = UserRepository(db)

    if user_repo.username_or_email_exists(payload.username, payload.email):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Username atau email sudah terdaftar.",
        )

    user = user_repo.create_user(payload)
    return user


@router.post("/login", response_model=Token)
def login(
    form_data: OAuth2PasswordRequestForm = Depends(),
    db: Session = Depends(get_db),
):
    """
    Login menggunakan username + password (format OAuth2 standard form,
    bukan JSON body -- ini konvensi FastAPI untuk kompatibilitas dengan
    Swagger UI dan OAuth2PasswordBearer).
    """
    user_repo = UserRepository(db)
    user = user_repo.get_by_username(form_data.username)

    if not user or not verify_password(form_data.password, user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Username atau password salah.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Akun ini tidak aktif.",
        )

    access_token = create_access_token(subject=user.id)
    return Token(access_token=access_token, user=user)