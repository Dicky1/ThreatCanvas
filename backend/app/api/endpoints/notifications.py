from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from app.core.database import get_db
from app.models.notification import NotificationRecord

router = APIRouter(prefix="/notifications", tags=["Notifications"])

@router.get("")
def list_notifications(db: Session = Depends(get_db)):
    rows = db.query(NotificationRecord).order_by(NotificationRecord.created_at.desc()).limit(100).all()
    return [{"id": row.id, "title": row.title, "message": row.message, "type": row.type, "read": row.read, "timestamp": int(row.created_at.timestamp() * 1000) if row.created_at else 0} for row in rows]

@router.post("", status_code=201)
def create_notification(payload: dict, db: Session = Depends(get_db)):
    row = NotificationRecord(title=str(payload.get("title", "Notification")), message=str(payload.get("message", "")), type=str(payload.get("type", "info")), read=bool(payload.get("read", False)))
    db.add(row)
    db.commit()
    db.refresh(row)
    return {"id": row.id, "title": row.title, "message": row.message, "type": row.type, "read": row.read, "timestamp": int(row.created_at.timestamp() * 1000) if row.created_at else 0}

@router.patch("/{notification_id}/read")
def mark_notification_read(notification_id: str, db: Session = Depends(get_db)):
    row = db.query(NotificationRecord).filter(NotificationRecord.id == notification_id).first()
    if row:
        row.read = True
        db.commit()
    return {"ok": True}

@router.delete("")
def clear_notifications(db: Session = Depends(get_db)):
    db.query(NotificationRecord).delete()
    db.commit()
    return {"ok": True}
