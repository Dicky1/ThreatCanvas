from app.schemas.cir import CIRSpecification


class KQLCompiler:
    def __init__(self, cir_data: CIRSpecification):
        self.cir_data = cir_data

    def compile(self) -> str:
        # Mengubah CIR Graph menjadi KQL (Kusto Query Language)
        queries = []
        for node in self.cir_data.attack_graph.nodes:
            # Contoh pemetaan logika ke tabel DeviceProcessEvents
            query = f"DeviceProcessEvents | where FileName endswith '{node.action_type}' or ProcessCommandLine contains '{node.target}' | extend Tactic='{node.tactic}', Technique='{node.technique}'"
            queries.append(query)

        return "// KQL Deteksi Otomatis untuk ThreatCanvas\n" + "\n| union\n".join(
            queries
        )
