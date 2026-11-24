"""Run the ThreatCanvas model benchmark from the command line.

Uses the LLM profiles configured in .env (LLM_PROFILES / LLM_MODEL) and the
bundled cases in app/data/benchmark/cases.json. Each profile x case costs
1-3 LLM calls.

Usage (from backend/):

    python scripts/run_benchmark.py                       # default profile, all cases
    python scripts/run_benchmark.py -p gpt-4o -p llama-local -o results.json
    python scripts/run_benchmark.py -c web-shell-exfiltration -c macos-infostealer
"""

import argparse
import asyncio
import json
import sys
from functools import partial
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.services import llm_parser  # noqa: E402
from app.services.attack_knowledge import ATTACKKnowledgeService  # noqa: E402
from app.services.benchmark_runner import run_benchmark  # noqa: E402
from app.services.llm_client import default_profile, get_profile  # noqa: E402


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("-p", "--profile", action="append", help="LLM profile name (repeatable)")
    parser.add_argument("-c", "--case", action="append", help="Benchmark case id (repeatable)")
    parser.add_argument("-o", "--output", type=Path, help="Write the full JSON report here")
    args = parser.parse_args()

    profiles = args.profile or [default_profile().name]
    for name in profiles:
        get_profile(name)  # fail fast on typos

    def progress(report: dict) -> None:
        for name, data in report["profiles"].items():
            done = data["summary"]["cases"]
            print(f"\r{name}: {done}/{len(report['cases'])} cases", end="", file=sys.stderr)

    report = asyncio.run(run_benchmark(
        profiles,
        args.case,
        lambda name: partial(llm_parser.parse_narrative_to_cir, profile=name),
        ATTACKKnowledgeService(),
        progress,
    ))
    print(file=sys.stderr)
    header = f"{'profile':<24}{'valid':>7}{'F1':>7}{'parentF1':>10}{'order':>7}{'repairs':>9}{'latency':>9}"
    print(header)
    for name, data in report["profiles"].items():
        s = data["summary"]
        print(f"{name:<24}{s['valid_rate']:>7.0%}{s['exact_f1']:>7.2f}{s['parent_f1']:>10.2f}{s['ordering']:>7.2f}"
              f"{s['avg_repair_attempts']:>9.2f}{s['avg_latency_ms']:>8}ms")
    if args.output:
        args.output.write_text(json.dumps(report, indent=2), encoding="utf-8")
        print(f"Report written to {args.output}")


if __name__ == "__main__":
    main()
