from sqlalchemy import Column, String, DateTime, JSON
from sqlalchemy.sql import func
from app.core.database import Base
import uuid

class ScenarioRecord(Base):
    """
    SQLAlchemy Entity representing a stored Attack Scenario and its generated CIR graph.
    """
    __tablename__ = "scenarios"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()), index=True)
    original_input = Column(String, nullable=False)
    cir_graph_data = Column(JSON, nullable=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now())