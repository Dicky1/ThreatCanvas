import uuid

from sqlalchemy import JSON, Column, DateTime, String, Text
from sqlalchemy.sql import func

from app.core.database import Base


class BenchmarkRun(Base):
    """A model-comparison benchmark run (owner-scoped)."""

    __tablename__ = "benchmark_runs"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()), index=True)
    owner_id = Column(String, nullable=False, index=True)
    status = Column(String, nullable=False, default="queued")  # queued | running | done | failed
    profiles = Column(JSON, nullable=False)
    case_ids = Column(JSON, nullable=True)
    report = Column(JSON, nullable=True)
    error = Column(Text, nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    finished_at = Column(DateTime(timezone=True), nullable=True)
