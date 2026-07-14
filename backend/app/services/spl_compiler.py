from app.schemas.cir import CIRSpecification

class SPLCompiler:
    def __init__(self, cir_data: CIRSpecification):
        self.cir_data = cir_data

    def compile(self) -> str:
        # Mengubah CIR Graph menjadi SPL (Splunk Processing Language)
        queries = []
        for node in self.cir_data.attack_graph.nodes:
            query = f'index=main sourcetype=WinEventLog:Security | search Image="*{node.action_type}*" OR CommandLine="*{node.target}*" | eval tactic="{node.tactic}", technique="{node.technique}"'
            queries.append(query)
            
        return " | ".join(queries)