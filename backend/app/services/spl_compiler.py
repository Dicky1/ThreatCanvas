from app.schemas.cir import CIRSpecification
from app.services.detection_observables import (
    FILE,
    NETWORK,
    PROCESS,
    REGISTRY,
    Observable,
    node_observable_groups,
)

SYSMON = 'sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"'
# Sysmon event IDs per telemetry category.
EVENT_CODES = {
    PROCESS: "EventCode=1",
    NETWORK: "EventCode=3",
    FILE: "EventCode=11",
    REGISTRY: "EventCode IN (12, 13, 14)",
}


def spl_string(value: str) -> str:
    """Double-quoted SPL string literal; backslash and quote are escaped."""
    return '"' + value.replace("\\", "\\\\").replace('"', '\\"') + '"'


def _condition(observable: Observable) -> str:
    value = observable.value
    if observable.op == "endswith":
        value = "*" + value
    elif observable.op == "contains":
        value = f"*{value}*"
    return f"{observable.field}={spl_string(value)}"


class SPLCompiler:
    def __init__(self, cir_data: CIRSpecification, index: str = "*"):
        self.cir_data = cir_data
        self.index = index

    def compile(self) -> str:
        """Mengubah CIR Graph menjadi satu pencarian SPL (Splunk, data Sysmon) yang valid."""
        searches: list[str] = []
        for node in self.cir_data.attack_graph.nodes:
            for group in node_observable_groups(node):
                conditions = " ".join(_condition(o) for o in group.observables)
                searches.append(
                    f"search index={self.index} {SYSMON} {EVENT_CODES[group.category]} {conditions}"
                    f" | eval step_id={spl_string(node.step_id)}, tactic={spl_string(node.tactic)},"
                    f" technique={spl_string(node.technique)}"
                )

        if not searches:
            return '| makeresults | eval message="ThreatCanvas: no detectable observable in scenario evidence"'
        first, *rest = searches
        return "\n".join([first, *(f"| append [ {search} ]" for search in rest)])
