import uuid

from sqlalchemy import JSON, Column, DateTime, String
from sqlalchemy.sql import func

from app.core.database import Base


class PurpleRun(Base):
    """Result of matching a scenario's rules against telemetry captured while
    its Atomic Red Team / Caldera plan was executed. Private to its owner."""

    __tablename__ = "purple_runs"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()), index=True)
    owner_id = Column(String, nullable=False, index=True)
    scenario_id = Column(String, nullable=False, index=True)
    dataset_id = Column(String, nullable=False)
    dataset_name = Column(String, nullable=False)
    platform = Column(String, nullable=True)
    summary = Column(JSON, nullable=False)
    techniques = Column(JSON, nullable=False)
    executions = Column(JSON, nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
