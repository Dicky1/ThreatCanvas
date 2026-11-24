import uuid

from sqlalchemy import JSON, Column, DateTime, String
from sqlalchemy.sql import func

from app.core.database import Base


class InventoryRule(Base):
    """A detection rule the organisation already runs (imported Sigma or CSV)."""

    __tablename__ = "inventory_rules"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()), index=True)
    owner_id = Column(String, nullable=False, index=True)
    title = Column(String, nullable=False)
    rule_id = Column(String, nullable=True)
    techniques = Column(JSON, nullable=False, default=list)
    logsource = Column(JSON, nullable=True)
    status = Column(String, nullable=True)
    level = Column(String, nullable=True)
    source = Column(String, nullable=False)  # "sigma" | "csv"
    source_file = Column(String, nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())


class DataSourceProfile(Base):
    """Which ATT&CK data components the organisation actually collects."""

    __tablename__ = "data_source_profiles"

    owner_id = Column(String, primary_key=True)
    components = Column(JSON, nullable=False, default=list)
    source = Column(String, nullable=False, default="manual")  # "manual" | "dettect"
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())
