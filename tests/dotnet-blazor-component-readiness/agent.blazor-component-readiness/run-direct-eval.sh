#!/usr/bin/env bash
set -euo pipefail

repo="$(cd "$(dirname "$0")/../../.." && pwd)"
source_eval="$repo/tests/dotnet-blazor-component-readiness/agent.blazor-component-readiness/eval.yaml"
scratch="$repo/artifacts/blazor-readiness-agent-eval"
tests="$scratch/tests/agent.blazor-component-readiness"
results="${RESULTS_DIR:-$scratch/results}"
model="${MODEL:-gpt-5-mini}"
judge_model="${JUDGE_MODEL:-$model}"

# Agent tool permissions compare physical paths, so normalize macOS's
# /var -> /private/var temporary-directory alias before workdirs are created.
physical_tmp="$(cd "${TMPDIR:-/tmp}" && pwd -P)"
export TMPDIR="$physical_tmp/"

rm -rf "$scratch"
mkdir -p "$tests" "$results" "$scratch/dotnet-home"

SOURCE_EVAL="$source_eval" OUTPUT_EVAL="$tests/eval.yaml" SMOKE="${DIRECT_EVAL_SMOKE:-0}" python3 - <<'PY'
import os
import json
import shutil
from pathlib import Path
import yaml

source = Path(os.environ["SOURCE_EVAL"])
target = Path(os.environ["OUTPUT_EVAL"])
spec = yaml.safe_load(source.read_text(encoding="utf-8"))
stimuli = spec["stimuli"][:1] if os.environ["SMOKE"] == "1" else spec["stimuli"]

def seconds(value):
    value = str(value)
    if value.endswith("m"):
        return int(value[:-1]) * 60
    if value.endswith("s"):
        return int(value[:-1])
    return int(value)

grader_map = {
    "file-exists": "file_exists",
    "file-not-exists": "file_not_exists",
    "file-contains": "file_contains",
    "file-not-contains": "file_not_contains",
    "output-contains": "output_contains",
    "output-not-contains": "output_not_contains",
    "output-matches": "output_matches",
    "output-not-matches": "output_not_matches",
    "exit-success": "exit_success",
    "run-command": "run_command_and_assert",
}

scenarios = []
for stimulus_index, stimulus in enumerate(stimuli):
    scenario = {
        "name": stimulus["name"],
        "prompt": stimulus["prompt"],
        "setup": {
            "copy_test_files": True,
            "files": [],
            "commands": [],
            "additional_required_skills": ["blazor-component-readiness"],
            "additional_required_agents": ["blazor-component-readiness-worker"],
        },
        "assertions": [],
        "rubric": stimulus.get("rubric", []),
        "timeout": seconds(spec.get("defaults", {}).get("timeout", "20m")),
        "max_turns": 60,
    }
    for file_index, item in enumerate(stimulus.get("environment", {}).get("files", [])):
        source_path = (source.parent / item["src"]).resolve()
        staged_path = target.parent / "fixtures" / (
            f"{stimulus_index:02d}-{file_index:02d}-{source_path.name}"
        )
        staged_path.parent.mkdir(parents=True, exist_ok=True)
        if source_path.is_dir():
            shutil.copytree(source_path, staged_path)
        else:
            shutil.copy2(source_path, staged_path)
        staged_relative = staged_path.relative_to(target.parent).as_posix()
        destination = item["dest"]
        destination_parent = Path(destination).parent.as_posix()
        scenario["setup"]["commands"].append(
            f"mkdir -p {destination_parent} && cp -R {staged_relative} {destination}"
        )
    scenario["setup"]["commands"].extend(
        stimulus.get("environment", {}).get("commands", [])
    )
    for grader in stimulus.get("graders", []):
        if grader["type"] == "prompt":
            continue
        config = grader.get("config", {})
        assertion = {"type": grader_map[grader["type"]]}
        if grader["type"] in ("file-exists", "file-not-exists"):
            assertion["path"] = config["path"]
        elif grader["type"] in ("file-contains", "file-not-contains"):
            assertion.update(path=config["path"], value=config["value"])
        elif grader["type"] in ("output-contains", "output-not-contains"):
            assertion["value"] = config["substring"]
        elif grader["type"] in ("output-matches", "output-not-matches"):
            assertion["pattern"] = config["pattern"]
        elif grader["type"] == "run-command":
            assertion["command_to_run"] = "bash"
            assertion["command_arguments"] = "-lc " + json.dumps(config["command"])
            assertion["expected_exit_code"] = config.get("expected_exit_code", 0)
            if "stdout_matches" in config:
                assertion["expected_std_output_matches"] = config["stdout_matches"]
            assertion["command_timeout"] = seconds(config.get("timeout", "2m"))
        scenario["assertions"].append(assertion)
    scenarios.append(scenario)

target.write_text(yaml.safe_dump({"scenarios": scenarios}, sort_keys=False), encoding="utf-8")
PY

if [ "${GENERATE_ONLY:-0}" = "1" ]; then
  echo "$tests/eval.yaml"
  exit 0
fi

export DOTNET_CLI_HOME="$scratch/dotnet-home"
export DOTNET_NOLOGO=1
export DOTNET_CLI_TELEMETRY_OPTOUT=1

args=(
  evaluate
  "$repo/plugins/dotnet-blazor-component-readiness/agents/blazor-component-readiness.agent.md"
  --tests-dir "$scratch/tests"
  --results-dir "$results"
  --model "$model"
  --judge-model "$judge_model"
  --runs 1
  --parallel-skills 1
  --parallel-scenarios 1
  --parallel-runs 1
  --no-overfitting-check
  --keep-sessions
  --verbose
)
if [ "${NO_JUDGE:-0}" = "1" ]; then
  args+=(--no-judge)
else
  args+=(--judge-mode pairwise --verdict-warn-only)
fi

validator_dll="$repo/artifacts/bin/SkillValidator/debug/skill-validator.dll"
if [ -f "$validator_dll" ]; then
  set +e
  dotnet "$validator_dll" "${args[@]}"
  evaluate_status=$?
  set -e
else
  set +e
  dotnet run \
    --project "$repo/eng/skill-validator/src/SkillValidator.csproj" \
    --no-restore \
    -p:CopilotCliBinaryPath="${COPILOT_CLI:-/opt/homebrew/bin/copilot}" \
    -- "${args[@]}"
  evaluate_status=$?
  set -e
fi

RESULTS_ROOT="$results" python3 - <<'PY'
import json
import os
from pathlib import Path

results_root = Path(os.environ["RESULTS_ROOT"])
result_files = sorted(results_root.glob("*/results.json"))
if not result_files:
    raise SystemExit("direct evaluation did not produce results.json")

payload = json.loads(result_files[-1].read_text(encoding="utf-8"))
scenarios = [
    scenario
    for verdict in payload["verdicts"]
    for scenario in verdict["scenarios"]
    if scenario["scenarioName"] == "Fail closed before a blind worker starts"
]
for scenario in scenarios:
    for arm in ("subagentActivationIsolated", "subagentActivationPlugin"):
        invoked = scenario.get(arm, {}).get("invokedAgents", [])
        worker_count = sum(
            name.casefold() == "blazor-component-readiness-worker"
            for name in invoked
        )
        if worker_count != 0:
            raise SystemExit(
                f"{scenario['scenarioName']} {arm} invoked the readiness worker "
                f"{worker_count} time(s)"
            )

if scenarios:
    print("Blind input gate invoked the readiness worker 0 times in isolated and plugin arms.")
PY

exit "$evaluate_status"
