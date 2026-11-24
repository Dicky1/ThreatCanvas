"""Team workspaces: share scenarios with colleagues (owner / editor / viewer)."""

from typing import Literal

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.api.deps import get_current_user
from app.core.database import get_db
from app.models.scenario import ScenarioRecord
from app.models.user import UserRecord
from app.models.workspace import Workspace, WorkspaceMember
from app.repositories.user_repo import UserRepository

router = APIRouter(prefix="/workspaces", tags=["Workspaces"])

MAX_OWNED_WORKSPACES = 50
MAX_MEMBERS = 200
Role = Literal["owner", "editor", "viewer"]


class WorkspaceCreate(BaseModel):
    name: str = Field(..., min_length=1, max_length=80)


class MemberAdd(BaseModel):
    username: str = Field(..., min_length=1, max_length=100)
    role: Role = "viewer"


class MemberUpdate(BaseModel):
    role: Role


def _membership(db: Session, workspace_id: str, user_id: str) -> WorkspaceMember | None:
    return (
        db.query(WorkspaceMember)
        .filter(WorkspaceMember.workspace_id == workspace_id, WorkspaceMember.user_id == user_id)
        .first()
    )


def _require(db: Session, workspace_id: str, user: UserRecord, owner: bool = False) -> WorkspaceMember:
    member = _membership(db, workspace_id, user.id)
    if member is None:
        raise HTTPException(status_code=404, detail="Workspace not found")  # don't reveal existence
    if owner and member.role != "owner":
        raise HTTPException(status_code=403, detail="Only workspace owners can do this")
    return member


def _owner_count(db: Session, workspace_id: str) -> int:
    return db.query(WorkspaceMember).filter(WorkspaceMember.workspace_id == workspace_id, WorkspaceMember.role == "owner").count()


def _summary(db: Session, workspace: Workspace, role: str) -> dict:
    return {
        "id": workspace.id,
        "name": workspace.name,
        "role": role,
        "members": db.query(WorkspaceMember).filter(WorkspaceMember.workspace_id == workspace.id).count(),
        "scenarios": db.query(ScenarioRecord).filter(ScenarioRecord.workspace_id == workspace.id).count(),
        "created_at": workspace.created_at,
    }


@router.get("")
def list_workspaces(db: Session = Depends(get_db), current_user: UserRecord = Depends(get_current_user)):
    rows = (
        db.query(Workspace, WorkspaceMember.role)
        .join(WorkspaceMember, WorkspaceMember.workspace_id == Workspace.id)
        .filter(WorkspaceMember.user_id == current_user.id)
        .order_by(Workspace.name)
        .all()
    )
    return [_summary(db, workspace, role) for workspace, role in rows]


@router.post("", status_code=201)
def create_workspace(request: WorkspaceCreate, db: Session = Depends(get_db), current_user: UserRecord = Depends(get_current_user)):
    owned = db.query(Workspace).filter(Workspace.created_by == current_user.id).count()
    if owned >= MAX_OWNED_WORKSPACES:
        raise HTTPException(status_code=400, detail=f"You can create at most {MAX_OWNED_WORKSPACES} workspaces")
    workspace = Workspace(name=request.name.strip(), created_by=current_user.id)
    db.add(workspace)
    db.flush()
    db.add(WorkspaceMember(workspace_id=workspace.id, user_id=current_user.id, role="owner"))
    db.commit()
    db.refresh(workspace)
    return _summary(db, workspace, "owner")


@router.patch("/{workspace_id}")
def rename_workspace(workspace_id: str, request: WorkspaceCreate, db: Session = Depends(get_db), current_user: UserRecord = Depends(get_current_user)):
    _require(db, workspace_id, current_user, owner=True)
    workspace = db.get(Workspace, workspace_id)
    workspace.name = request.name.strip()
    db.commit()
    return _summary(db, workspace, "owner")


@router.delete("/{workspace_id}")
def delete_workspace(workspace_id: str, db: Session = Depends(get_db), current_user: UserRecord = Depends(get_current_user)):
    _require(db, workspace_id, current_user, owner=True)
    # Shared scenarios go back to being personal scenarios of their creators.
    unshared = (
        db.query(ScenarioRecord)
        .filter(ScenarioRecord.workspace_id == workspace_id)
        .update({ScenarioRecord.workspace_id: None}, synchronize_session=False)
    )
    db.query(WorkspaceMember).filter(WorkspaceMember.workspace_id == workspace_id).delete()
    db.query(Workspace).filter(Workspace.id == workspace_id).delete()
    db.commit()
    return {"message": "Workspace deleted", "scenarios_unshared": unshared}


@router.get("/{workspace_id}/members")
def list_members(workspace_id: str, db: Session = Depends(get_db), current_user: UserRecord = Depends(get_current_user)):
    _require(db, workspace_id, current_user)
    members = db.query(WorkspaceMember).filter(WorkspaceMember.workspace_id == workspace_id).all()
    users = {u.id: u for u in db.query(UserRecord).filter(UserRecord.id.in_([m.user_id for m in members])).all()}
    return [
        {
            "user_id": member.user_id,
            "username": users[member.user_id].username if member.user_id in users else "(deleted user)",
            "full_name": users[member.user_id].full_name if member.user_id in users else None,
            "role": member.role,
            "you": member.user_id == current_user.id,
        }
        for member in sorted(members, key=lambda m: (m.role != "owner", users.get(m.user_id).username if m.user_id in users else ""))
    ]


@router.post("/{workspace_id}/members", status_code=201)
def add_member(workspace_id: str, request: MemberAdd, db: Session = Depends(get_db), current_user: UserRecord = Depends(get_current_user)):
    _require(db, workspace_id, current_user, owner=True)
    user = UserRepository(db).get_by_username(request.username.strip())
    if user is None or not user.is_active:
        raise HTTPException(status_code=404, detail="User not found")
    if _membership(db, workspace_id, user.id):
        raise HTTPException(status_code=409, detail="User is already a member")
    if db.query(WorkspaceMember).filter(WorkspaceMember.workspace_id == workspace_id).count() >= MAX_MEMBERS:
        raise HTTPException(status_code=400, detail=f"A workspace can have at most {MAX_MEMBERS} members")
    db.add(WorkspaceMember(workspace_id=workspace_id, user_id=user.id, role=request.role))
    db.commit()
    return {"user_id": user.id, "username": user.username, "role": request.role}


@router.patch("/{workspace_id}/members/{user_id}")
def update_member(workspace_id: str, user_id: str, request: MemberUpdate, db: Session = Depends(get_db), current_user: UserRecord = Depends(get_current_user)):
    _require(db, workspace_id, current_user, owner=True)
    member = _membership(db, workspace_id, user_id)
    if member is None:
        raise HTTPException(status_code=404, detail="Member not found")
    if member.role == "owner" and request.role != "owner" and _owner_count(db, workspace_id) <= 1:
        raise HTTPException(status_code=400, detail="A workspace needs at least one owner")
    member.role = request.role
    db.commit()
    return {"user_id": user_id, "role": member.role}


@router.delete("/{workspace_id}/members/{user_id}")
def remove_member(workspace_id: str, user_id: str, db: Session = Depends(get_db), current_user: UserRecord = Depends(get_current_user)):
    me = _require(db, workspace_id, current_user)
    if user_id != current_user.id and me.role != "owner":
        raise HTTPException(status_code=403, detail="Only workspace owners can remove other members")
    member = _membership(db, workspace_id, user_id)
    if member is None:
        raise HTTPException(status_code=404, detail="Member not found")
    if member.role == "owner" and _owner_count(db, workspace_id) <= 1:
        raise HTTPException(status_code=400, detail="A workspace needs at least one owner; delete it instead")
    db.delete(member)
    db.commit()
    return {"message": "Member removed"}
