"""`solarflare sample`: a tour of the bundled sample. It runs the real commands on
the sample, with a short explanation before each; nothing calls Cloudflare or costs anything."""
import json
import os

from .options import SAMPLE_DIR

RULE = "=" * 78


def section(title: str, text: str) -> None:
    print(f"\n{RULE}\n{title}\n{'-' * 78}\n{text}\n")


def run(run_command) -> int:
    """run_command: the CLI's main(), to run each step exactly as a user would type it."""
    print("The sample is a real incident from a real Cloudflare account, anonymized: names, IDs and\n"
          "IPs are made up, the traffic and the scanners' behaviour are real. Nothing here calls\n"
          "Cloudflare or costs anything.")

    section("1. solarflare summary sample",
            "The daily briefing: what moved against each resource's previous week, bursts, new\n"
            "resources, probes, deploys. Plain SQL, no AI.")
    run_command(["summary", "sample", "--quiet"])

    section("2. solarflare security sample",
            "Who was scanning, what happened to their probes, and whether any reached code that\n"
            "runs (and can be billed).")
    run_command(["security", "sample", "--quiet"])

    question = json.loads((SAMPLE_DIR / "replay.json").read_text())["question"]
    title = f'3. An investigation of the flagged burst\n   solarflare investigate sample "{question}"'
    if os.environ.get("SOLARI_API_KEY"):
        section(title,
                "The flagged burst, investigated. A recorded run of the AI agent is replayed: every one\n"
                "of its queries runs live now in a hardened (no network) Solari sandbox, and is checked\n"
                "against the recording. The model's decisions are replayed, so this needs no model key.")
        run_command(["investigate", "sample", "--replay"])
    else:
        section(title,
                "Skipped: add SOLARI_API_KEY to .env to see the flagged burst investigated, with each of\n"
                "the agent's queries running live in a hardened Solari sandbox.")

    print("\nOn your own account: add CLOUDFLARE_API_TOKEN to .env and run `solarflare summary`.")
    return 0
