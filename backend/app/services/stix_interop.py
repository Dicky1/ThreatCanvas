from datetime import datetime
from typing import Any
from uuid import UUID

from app.schemas.cir import (
    CIRNode,
    CIRRelationship,
    CIRSpecification,
    CIREntity,
    Evidence,
)


SUPPORTED_TYPES = {
    "attack-pattern",
    "indicator",
    "malware",
    "threat-actor",
    "intrusion-set",
    "vulnerability",
    "relationship",
    "observed-data",
}

ENTITY_TYPES = {
    "attack-pattern": "technique",
    "indicator": "observable",
    "malware": "malware",
    "threat-actor": "threat_actor",
    "intrusion-set": "intrusion_set",
    "vulnerability": "vulnerability",
    "observed-data": "observable",
}

TACTIC_IDS = {
    "reconnaissance": "TA0043",
    "resource-development": "TA0042",
    "initial-access": "TA0001",
    "execution": "TA0002",
    "persistence": "TA0003",
    "privilege-escalation": "TA0004",
    "defense-evasion": "TA0005",
    "credential-access": "TA0006",
    "discovery": "TA0007",
    "lateral-movement": "TA0008",
    "collection": "TA0009",
    "command-and-control": "TA0011",
    "exfiltration": "TA0010",
    "impact": "TA0040",
}


class STIXInteropError(ValueError):
    pass


class STIXInteropService:
    def import_bundle(self, bundle: dict[str, Any], scenario_id: str) -> CIRSpecification:
        self._validate_bundle(bundle)
        objects = bundle["objects"]
        object_ids = [obj["id"] for obj in objects]
        if len(object_ids) != len(set(object_ids)):
            raise STIXInteropError("STIX bundle contains duplicate object IDs")

        entities = []
        nodes = []
        relationships = []
        for obj in objects:
            if obj["type"] == "relationship":
                relationships.append(self._relationship(obj))
                continue
            entity = self._entity(obj)
            entities.append(entity)
            if obj["type"] == "attack-pattern":
                nodes.append(self._node(obj, entity))

        entity_ids = {entity.id for entity in entities}
        for relationship in relationships:
            if relationship.source not in entity_ids or relationship.target not in entity_ids:
                raise STIXInteropError(
                    f"Relationship references an unknown object: {relationship.source}->{relationship.target}"
                )

        graph_edges = [
            {
                "from": relation.source,
                "to": relation.target,
                "relationship": relation.relationship,
            }
            for relation in relationships
            if relation.source in {node.step_id for node in nodes}
            and relation.target in {node.step_id for node in nodes}
        ]
        return CIRSpecification(
            cir_version="2.0",
            scenario_id=scenario_id,
            attack_version=bundle.get("x_threatcanvas_attack_version"),
            entities=entities,
            relationships=relationships,
            attack_graph={"nodes": nodes, "edges": graph_edges},
        )

    def export_bundle(self, cir: CIRSpecification) -> dict[str, Any]:
        objects: dict[str, dict[str, Any]] = {}
        for entity in cir.entities:
            object_id = entity.stix_id or entity.id
            if object_id in objects:
                continue
            if entity.stix_data:
                obj = dict(entity.stix_data)
            else:
                obj = self._entity_to_stix(entity, object_id)
            obj["id"] = object_id
            objects[object_id] = obj

        for relation in cir.relationships:
            object_id = relation.stix_id or self._relationship_id(relation)
            if object_id in objects:
                continue
            if relation.stix_data:
                obj = dict(relation.stix_data)
            else:
                obj = {
                    "type": "relationship",
                    "spec_version": "2.1",
                    "id": object_id,
                    "relationship_type": relation.relationship.lower(),
                    "source_ref": relation.source,
                    "target_ref": relation.target,
                }
            obj["id"] = object_id
            objects[object_id] = obj

        return {
            "type": "bundle",
            "id": f"bundle--{self._uuid(cir.scenario_id)}",
            "spec_version": "2.1",
            "x_threatcanvas_attack_version": cir.attack_version,
            "objects": list(objects.values()),
        }

    def _validate_bundle(self, bundle: dict[str, Any]) -> None:
        if bundle.get("type") != "bundle" or bundle.get("spec_version") != "2.1":
            raise STIXInteropError("Only STIX 2.1 bundles are supported")
        if not isinstance(bundle.get("objects"), list):
            raise STIXInteropError("STIX bundle objects must be a list")
        for obj in bundle["objects"]:
            if obj.get("type") not in SUPPORTED_TYPES:
                raise STIXInteropError(f"Unsupported STIX object type: {obj.get('type')}")
            if not self._valid_stix_id(obj.get("id", "")):
                raise STIXInteropError(f"Invalid STIX object ID: {obj.get('id')}")
            if obj.get("type") == "relationship":
                if not obj.get("source_ref") or not obj.get("target_ref"):
                    raise STIXInteropError("STIX relationship requires source_ref and target_ref")

    def _entity(self, obj: dict[str, Any]) -> CIREntity:
        return CIREntity(
            id=obj["id"],
            stix_id=obj["id"],
            stix_type=obj["type"],
            entity_type=ENTITY_TYPES[obj["type"]],
            name=obj.get("name") or obj.get("id"),
            description=obj.get("description"),
            confidence=self._confidence(obj.get("confidence")),
            created_at=self._time(obj.get("created")),
            updated_at=self._time(obj.get("modified")),
            observed_at=self._time(obj.get("first_observed")),
            attributes={key: value for key, value in obj.items() if key not in {"id", "type", "name", "description", "confidence", "created", "modified", "first_observed"}},
            stix_data=dict(obj),
        )

    def _node(self, obj: dict[str, Any], entity: CIREntity) -> CIRNode:
        technique_id = next(
            (ref.get("external_id") for ref in obj.get("external_references", []) if ref.get("external_id", "").startswith("T")),
            "UNKNOWN",
        )
        tactics = [
            TACTIC_IDS[phase["phase_name"]]
            for phase in obj.get("kill_chain_phases", [])
            if phase.get("kill_chain_name") == "mitre-attack" and phase.get("phase_name") in TACTIC_IDS
        ]
        tactic = tactics[0] if tactics else "TA0002"
        return CIRNode(
            step_id=obj["id"],
            tactic=tactic,
            technique=technique_id,
            target=entity.name or obj["id"],
            action_type=entity.name or "ATT&CK technique",
            evidence=[Evidence(description=obj.get("description"), source=obj["id"])],
            entity_refs=[obj["id"]],
            confidence=self._confidence(obj.get("confidence")),
            created_at=self._time(obj.get("created")),
            updated_at=self._time(obj.get("modified")),
        )

    def _relationship(self, obj: dict[str, Any]) -> CIRRelationship:
        return CIRRelationship(
            **{"from": obj["source_ref"], "to": obj["target_ref"]},
            relationship=obj["relationship_type"].upper(),
            stix_id=obj["id"],
            confidence=obj.get("confidence"),
            created_at=self._time(obj.get("created")),
            updated_at=self._time(obj.get("modified")),
            stix_data=dict(obj),
        )

    def _entity_to_stix(self, entity: CIREntity, object_id: str) -> dict[str, Any]:
        stix_type = entity.stix_type or {
            "technique": "attack-pattern",
            "observable": "observed-data",
            "threat_actor": "threat-actor",
            "intrusion_set": "intrusion-set",
            "malware": "malware",
            "vulnerability": "vulnerability",
        }.get(entity.entity_type, "observed-data")
        obj = {
            "type": stix_type,
            "spec_version": "2.1",
            "id": object_id,
            "name": entity.name,
            "description": entity.description,
            "confidence": self._stix_confidence(entity.confidence),
            "created": self._iso(entity.created_at),
            "modified": self._iso(entity.updated_at),
        }
        obj.update(entity.attributes)
        return {key: value for key, value in obj.items() if value is not None}

    @staticmethod
    def _valid_stix_id(value: str) -> bool:
        try:
            prefix, identifier = value.split("--", 1)
            UUID(identifier)
            return bool(prefix)
        except (ValueError, AttributeError):
            return False

    @staticmethod
    def _uuid(value: str) -> str:
        import uuid

        return str(uuid.uuid5(uuid.NAMESPACE_URL, value))

    @staticmethod
    def _relationship_id(relation: CIRRelationship) -> str:
        return f"relationship--{STIXInteropService._uuid(relation.source + relation.target + relation.relationship)}"

    @staticmethod
    def _time(value: str | None) -> datetime | None:
        return datetime.fromisoformat(value.replace("Z", "+00:00")) if value else None

    @staticmethod
    def _iso(value: datetime | None) -> str | None:
        return value.isoformat().replace("+00:00", "Z") if value else None

    @staticmethod
    def _confidence(value: int | float | None) -> float | None:
        if value is None:
            return None
        return float(value) / 100 if value > 1 else float(value)

    @staticmethod
    def _stix_confidence(value: float | None) -> int | None:
        return round(value * 100) if value is not None else None