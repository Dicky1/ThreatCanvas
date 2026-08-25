from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from app.core.database import get_db
from app.models.experiment import ExperimentMetric

router = APIRouter(prefix="/research", tags=["Research"])


@router.get("/metrics/{scenario_id}")
def get_metrics(scenario_id: str, db: Session = Depends(get_db)):
    rows = db.query(ExperimentMetric).filter(
        ExperimentMetric.scenario_id == scenario_id
    ).order_by(ExperimentMetric.created_at.asc()).all()
    if not rows:
        raise HTTPException(status_code=404, detail="No experiment metrics available")
    return {
        "scenario_id": scenario_id,
        "runs": [
            {
                "operation": row.operation,
                "duration_ms": row.duration_ms,
                "status": row.status,
                "node_count": row.node_count,
                "edge_count": row.edge_count,
                "details": row.details or {},
                "created_at": row.created_at,
            }
            for row in rows
        ],
    }
