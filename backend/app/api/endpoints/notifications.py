from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.api.deps import get_current_user
from app.core.database import get_db
from app.models.notification import NotificationRecord
from app.models.user import UserRecord
from app.schemas.notifications import NotificationCreate

router = APIRouter(prefix="/notifications", tags=["Notifications"])


def _serialize(row: NotificationRecord) -> dict:
    return {
        "id": row.id,
        "title": row.title,
        "message": row.message,
        "type": row.type,
        "read": row.read,
        "timestamp": int(row.created_at.timestamp() * 1000) if row.created_at else 0,
    }


@router.get("")
def list_notifications(
    db: Session = Depends(get_db),
    current_user: UserRecord = Depends(get_current_user),
):
    rows = (
        db.query(NotificationRecord)
        .filter(NotificationRecord.user_id == current_user.id)
        .order_by(NotificationRecord.created_at.desc())
        .limit(100)
        .all()
    )
    return [_serialize(row) for row in rows]


@router.post("", status_code=201)
def create_notification(
    payload: NotificationCreate,
    db: Session = Depends(get_db),
    current_user: UserRecord = Depends(get_current_user),
):
    row = NotificationRecord(
        user_id=current_user.id,
        title=payload.title,
        message=payload.message,
        type=payload.type,
        read=payload.read,
    )
    db.add(row)
    db.commit()
    db.refresh(row)
    return _serialize(row)


@router.patch("/{notification_id}/read")
def mark_notification_read(
    notification_id: str,
    db: Session = Depends(get_db),
    current_user: UserRecord = Depends(get_current_user),
):
    row = (
        db.query(NotificationRecord)
        .filter(
            NotificationRecord.id == notification_id,
            NotificationRecord.user_id == current_user.id,
        )
        .first()
    )
    if not row:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Notification not found")
    row.read = True
    db.commit()
    return {"ok": True}


@router.delete("")
def clear_notifications(
    db: Session = Depends(get_db),
    current_user: UserRecord = Depends(get_current_user),
):
    db.query(NotificationRecord).filter(NotificationRecord.user_id == current_user.id).delete()
    db.commit()
    return {"ok": True}
