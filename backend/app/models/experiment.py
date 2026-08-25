from sqlalchemy import Column, DateTime, Integer, JSON, String, Float
from sqlalchemy.sql import func
from app.core.database import Base
import uuid


class ExperimentMetric(Base):
    __tablename__ = "experiment_metrics"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    scenario_id = Column(String, nullable=True, index=True)
    operation = Column(String, nullable=False, index=True)
    duration_ms = Column(Float, nullable=False)
    status = Column(String, nullable=False)
    node_count = Column(Integer, nullable=True)
    edge_count = Column(Integer, nullable=True)
    details = Column(JSON, nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
