import uuid

from sqlalchemy import JSON, Column, DateTime, Integer, String
from sqlalchemy.sql import func

from app.core.database import Base


class DetectionDataset(Base):
    """Uploaded log dataset (e.g. OTRF / Atomic Red Team) used to measure
    detection rules. Private to its owner."""

    __tablename__ = "detection_datasets"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()), index=True)
    owner_id = Column(String, nullable=False, index=True)
    name = Column(String, nullable=False)
    # "malicious": attack recording; "benign": baseline activity
    label = Column(String, nullable=False)
    technique_ids = Column(JSON, nullable=False, default=list)
    source_filename = Column(String, nullable=True)
    event_count = Column(Integer, nullable=False)
    events = Column(JSON, nullable=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
