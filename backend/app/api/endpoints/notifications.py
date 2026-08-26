from fastapi import APIRouter, Depends, Request
from sqlalchemy.orm import Session
from app.core.database import get_db
from app.models.notification import NotificationRecord

router = APIRouter(prefix="/notifications", tags=["Notifications"])

@router.get("")
def list_notifications(db: Session = Depends(get_db)):
    rows = db.query(NotificationRecord).order_by(NotificationRecord.created_at.desc()).limit(100).all()
    return [{"id": row.id, "title": row.title, "message": row.message, "type": row.type, "read": row.read, "timestamp": int(row.created_at.timestamp() * 1000) if row.created_at else 0} for row in rows]

@router.post("", status_code=201)
async def create_notification(request: Request, db: Session = Depends(get_db)):
    try:
        payload = await request.json()
    except Exception:
        payload = {}
    if not isinstance(payload, dict):
        payload = {}
    notification_type = payload.get("type") if payload.get("type") in {"success", "error", "info"} else "info"
    row = NotificationRecord(title=str(payload.get("title") or "Notification")[:200], message=str(payload.get("message") or "")[:4000], type=notification_type, read=bool(payload.get("read", False)))
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
