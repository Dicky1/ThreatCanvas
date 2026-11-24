import yaml

from app.schemas.cir import CIRSpecification
from app.services.sigma_compiler import SigmaCompiler
from app.services.sigma_conversion import convert


def spl_string(value: str) -> str:
    """Double-quoted SPL string literal; backslash and quote are escaped."""
    return '"' + value.replace("\\", "\\\\").replace('"', '\\"') + '"'


class SPLCompiler:
    """CIR -> Sigma (from evidence) -> SPL via the pySigma Splunk backend
    (Sysmon + Splunk Windows pipelines). Each rule is a subsearch tagged with
    its CIR step / ATT&CK mapping."""

    def __init__(self, cir_data: CIRSpecification):
        self.cir_data = cir_data

    def compile(self) -> str:
        sigma = SigmaCompiler(self.cir_data)
        searches: list[str] = []
        for node in self.cir_data.attack_graph.nodes:
            rules = sigma.rules_for_node(node)
            if not rules:
                continue
            result = convert(yaml.safe_dump_all(rules, sort_keys=False), "splunk")
            for rule in result.rules:
                if rule.error:
                    continue
                for query in rule.queries:
                    searches.append(
                        f"search {query}"
                        f" | eval step_id={spl_string(node.step_id)}, tactic={spl_string(node.tactic)},"
                        f" technique={spl_string(node.technique)}"
                    )

        if not searches:
            return '| makeresults | eval message="ThreatCanvas: no detectable observable in scenario evidence"'
        first, *rest = searches
        return "\n".join([first, *(f"| append [ {search} ]" for search in rest)])
