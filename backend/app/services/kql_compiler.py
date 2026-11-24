from app.schemas.cir import CIRSpecification
from app.services.detection_observables import (
    FILE,
    NETWORK,
    PROCESS,
    REGISTRY,
    Observable,
    node_observable_groups,
)

# Sigma/Sysmon field -> (Microsoft Defender XDR advanced hunting table, column)
TABLES = {
    PROCESS: "DeviceProcessEvents",
    REGISTRY: "DeviceRegistryEvents",
    FILE: "DeviceFileEvents",
    NETWORK: "DeviceNetworkEvents",
}
COLUMNS = {
    "Image": "FileName",
    "CommandLine": "ProcessCommandLine",
    "Hashes": "SHA256",
    "TargetObject": "RegistryKey",
    "Details": "RegistryValueData",
    "TargetFilename": "FileName",
    "DestinationIp": "RemoteIP",
    "DestinationHostname": "RemoteUrl",
}


def kql_string(value: str) -> str:
    """Double-quoted KQL string literal with backslash escaping."""
    return '"' + value.replace("\\", "\\\\").replace('"', '\\"') + '"'


def _condition(observable: Observable) -> str:
    column = COLUMNS[observable.field]
    value = observable.value
    if observable.field in {"Image", "TargetFilename"}:
        # FileName holds the bare file name, so compare case-insensitively.
        return f"{column} =~ {kql_string(value.lstrip(chr(92)))}"
    if observable.field == "Hashes":
        return f"{column} =~ {kql_string(value.split('=', 1)[-1])}"
    if observable.op == "equals":
        return f"{column} == {kql_string(value)}"
    return f"{column} contains {kql_string(value)}"


class KQLCompiler:
    def __init__(self, cir_data: CIRSpecification):
        self.cir_data = cir_data

    def compile(self) -> str:
        """Mengubah CIR Graph menjadi satu query KQL (Defender XDR / Sentinel) yang valid."""
        queries: list[str] = []
        skipped: list[str] = []
        for node in self.cir_data.attack_graph.nodes:
            groups = node_observable_groups(node)
            if not groups:
                skipped.append(f"{node.step_id} ({node.technique})")
                continue
            for group in groups:
                where = " and ".join(_condition(o) for o in group.observables)
                queries.append(
                    f"{TABLES[group.category]}\n"
                    f"| where {where}\n"
                    f"| extend StepId={kql_string(node.step_id)}, "
                    f"Tactic={kql_string(node.tactic)}, Technique={kql_string(node.technique)}"
                )

        header = ["// KQL Deteksi Otomatis untuk ThreatCanvas"]
        if skipped:
            header.append("// No detectable observable in evidence for steps: " + ", ".join(skipped))
        if not queries:
            return "\n".join(header)
        if len(queries) == 1:
            body = queries[0]
        else:
            indented = ["    (" + q.replace("\n", "\n     ") + ")" for q in queries]
            body = "union\n" + ",\n".join(indented)
        return "\n".join(header) + "\n" + body
