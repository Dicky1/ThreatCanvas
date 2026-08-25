import re
from datetime import datetime, timezone

from app.schemas.cir import CIRSpecification, Evidence


class EvidenceProvenanceEngine:
    """Enrich CIR evidence with provenance and remove secret-like values."""

    SECRET_PATTERNS = (
        re.compile(
            r"(?i)(api[_-]?key|access[_-]?token|auth(?:orization)?|password|passwd|secret|token)"
            r"\s*[:=]\s*[\"']?[^\s,;\"']+"
        ),
        re.compile(r"(?i)bearer\s+[A-Za-z0-9._~+/=-]+"),
        re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b"),
        re.compile(r"\b(?:gh[pousr]|sk)-[A-Za-z0-9_-]{10,}\b"),
    )

    @classmethod
    def _redact(cls, value: str) -> str:
        for pattern in cls.SECRET_PATTERNS:
            value = pattern.sub("[REDACTED]", value)
        return value

    @classmethod
    def _sanitize(cls, evidence: Evidence) -> Evidence:
        values = evidence.model_dump()
        for key, value in values.items():
            if isinstance(value, str):
                values[key] = cls._redact(value)
        return Evidence.model_validate(values)

    @classmethod
    def enrich(
        cls,
        cir: CIRSpecification,
        *,
        source: str = "narrative",
        inference_method: str = "LLM_INFERENCE",
        now: datetime | None = None,
    ) -> CIRSpecification:
        enriched_cir = cir.model_copy(deep=True)
        timestamp = now or datetime.now(timezone.utc)

        for node in enriched_cir.attack_graph.nodes:
            for evidence in node.evidence:
                if evidence.evidence_text is None:
                    evidence.evidence_text = evidence.description
                if evidence.source is None:
                    evidence.source = source
                if evidence.timestamp is None:
                    evidence.timestamp = timestamp
                if evidence.asset is None:
                    evidence.asset = node.target
                if evidence.inference_method is None:
                    evidence.inference_method = inference_method
                if evidence.validation_state == "UNVERIFIED":
                    evidence.validation_state = "LLM_INFERRED"
                sanitized = cls._sanitize(evidence)
                evidence.__dict__.update(sanitized.__dict__)

        return enriched_cir