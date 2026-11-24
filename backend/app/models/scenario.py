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
    # Owning user. Nullable only for rows created before ownership existed;
    # such rows are invisible until adopted (see app.core.migrations).
    owner_id = Column(String, nullable=True, index=True)
    # Optional team workspace the scenario is shared into (None = personal).
    workspace_id = Column(String, nullable=True, index=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())