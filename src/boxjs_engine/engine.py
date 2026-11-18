"""BoxJsEngine — run box-js on a JScript/JS sample and seal what it observed.

box-js emulates a Windows Script Host environment in-process, inside vm2. That is a
JavaScript-level sandbox with a documented escape history, so it is NOT the security
boundary here: the disposable blastbox worker is. This engine deliberately does no
isolation of its own — it shells out to `node run.js` under the worker's Limits and
hands the results back inside the typed Envelope. Pooling, warm/cold tier selection,
queue sizing, egress policy and output sealing are all the framework's job.

What it adds over the generic DetonateEngine: box-js does not answer on stdout. It
writes a `<sample>.results/` directory containing IOC.json, urls.json, snippets.json
and every file the sample dropped. This engine locates that directory, declares those
as artifacts, and lifts a summary into the sealed payload so a consumer can rank a
sample without re-reading the artifacts.

Egress is taken from the worker, not guessed. `Limits.net_egress` decides between
`--download` (really fetch the next stage) and `--fake-download` (return a synthetic
200). An engine that fetched live payloads while the worker believed it was offline
would be lying to the operator about what just happened on their network.
"""
from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
from pathlib import Path

from blastbox.contract import DeclaredArtifact, Detection, Record, Warning
from blastbox.limits import Limits
from blastbox.worker.engine import DetonationResult

#: Where the box-js checkout lives inside the worker image. The Dockerfiles build
#: OUR FORK at a pinned commit — never `npm install box-js`, which resolves to the
#: upstream package and lacks the fork's encoding, timeout and vm2 fixes.
RUN_JS_ENV = "BOXJS_RUN_JS"
DEFAULT_RUN_JS = "/opt/box-js/run.js"

#: Extra argv appended verbatim, JSON list, for operators who need to tune a run
#: without rebuilding the image. Never job-derived: an attacker-influenced flag list
#: would let a sample choose its own analysis options.
EXTRA_ARGV_ENV = "BOXJS_EXTRA_ARGV"

#: Version of the payload Record shape, on every payload (ok and engine_error) under
#: `schema_version`. Bump it when a field is added, removed or changes meaning.
SCHEMA_VERSION = "boxjs.result/1"

#: box-js's own analysis output, declared first and as kind `analysis`. env_vars.json is
#: box-js's record of the environment variables the sample set, not a file it dropped.
_ANALYSIS_FILES = ("IOC.json", "urls.json", "snippets.json", "resources.json",
                   "active_urls.json", "env_vars.json", "analysis.log")

#: box-js flags this engine always passes. --no-kill and --no-shell-error keep the
#: emulator going after an unimplemented feature instead of aborting the analysis,
#: which is what we want for bulk triage. The per-stage timeouts are derived from
#: Limits below rather than hardcoded.
_BASE_ARGV = [
    "--prepended-code=default",
    "--encoding=utf8",
    "--preprocess",
    "--rewrite-loops",
    "--activex-as-ioc",
    "--no-kill",
    "--no-shell-error",
    "--extract-conditional-code",
    "--ignore-wscript-quit",
    "--loglevel=info",
]

#: IOC types box-js emits that mean "the sample launched something". Kept in step with
#: the logIOC call sites in analyze.js/lib.js/emulator/ — a missing entry silently
#: drops execution evidence from the summary.
_EXEC_IOCS = frozenset({
    "run", "commandexec", "wmi.getobject.run", "wmi.getobject.create",
    "createshortcut", "task", "task path", "task arguments",
})
_WRITE_IOCS = frozenset({"filewrite", "newresource", "adodbstream"})
_URL_IOCS = frozenset({"urlfetch", "xmlhttp", "fetch"})


def _run_js() -> str:
    return os.environ.get(RUN_JS_ENV, DEFAULT_RUN_JS)


def _extra_argv() -> list[str]:
    raw = os.environ.get(EXTRA_ARGV_ENV, "").strip()
    if not raw:
        return []
    try:
        got = json.loads(raw)
    except json.JSONDecodeError:
        return []
    return [str(x) for x in got] if isinstance(got, list) else []


def _results_dir(outdir: Path) -> Path | None:
    """box-js writes `<outdir>/<sample name>.results/`, and appends `.1`, `.2` … if
    that already exists. We give it a fresh outdir per job, so there is normally
    exactly one; take the newest if a retry left more behind."""
    found = sorted(
        (p for p in outdir.iterdir() if p.is_dir() and p.name.endswith(".results")),
        key=lambda p: p.stat().st_mtime,
    )
    return found[-1] if found else None


def _load_json(path: Path, default):
    try:
        return json.loads(path.read_text(errors="replace"))
    except (OSError, ValueError):   # unreadable, or not JSON (JSONDecodeError)
        return default


def _summarise(results: Path) -> dict:
    """Lift counts out of IOC.json so a consumer can triage without opening artifacts."""
    iocs = _load_json(results / "IOC.json", [])
    urls = _load_json(results / "urls.json", [])
    if not isinstance(iocs, list):
        iocs = []
    if not isinstance(urls, list):
        urls = []

    n_exec = n_write = n_url = 0
    for entry in iocs:
        if not isinstance(entry, dict):
            continue
        t = str(entry.get("type", "")).lower()
        if t in _EXEC_IOCS:
            n_exec += 1
        elif t in _WRITE_IOCS:
            n_write += 1
        elif t in _URL_IOCS:
            n_url += 1

    return {
        "ioc_count": len(iocs),
        "exec_iocs": n_exec,
        "write_iocs": n_write,
        "url_iocs": n_url,
        "url_count": len([u for u in urls if isinstance(u, str)]),
    }


# JScript.Encode's marker: the encoded body starts "#@~^" (optionally after a BOM/whitespace).
_JSE_MARKER = b"#@~^"


def _is_jscript_encoded(path: Path) -> bool:
    with path.open("rb") as f:
        head = f.read(4096)
    return head.lstrip(b"\xef\xbb\xbf \t\r\n").startswith(_JSE_MARKER)


_UUID = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")


def _snippet_names(results: Path) -> set[str]:
    """Names of the code snippets box-js wrote: box-js output, not files the sample wrote.

    box-js keys snippets.json by snippet file name. It writes each snippet's file before
    rewriting the index, so a run killed in between leaves a snippet the index lacks; those
    are also recognised by how box-js writes them: lib.logJS saves eval'd JS as `<uuid4>.js`
    (logResource names the sample's files with a bare uuid4), and runShellCommand saves each
    command, verbatim, as a bare `<uuid4>` alongside a Run IOC carrying the same text.
    """
    index = _load_json(results / "snippets.json", {})
    names = {str(k) for k in index} if isinstance(index, dict) else set()
    # The sample's own writes, which the content match below must never claim.
    written = _load_json(results / "resources.json", {})
    resources = {str(k) for k in written} if isinstance(written, dict) else set()
    iocs = _load_json(results / "IOC.json", [])
    commands = {
        e["value"]["command"] for e in (iocs if isinstance(iocs, list) else [])
        if isinstance(e, dict) and str(e.get("type", "")).lower() == "run"
        and isinstance(e.get("value"), dict) and isinstance(e["value"].get("command"), str)
    }
    longest = max((len(c.encode("utf-8", "replace")) for c in commands), default=-1)
    for p in results.iterdir():
        if not p.is_file():
            continue
        logged_js = p.suffix == ".js" and _UUID.fullmatch(p.stem)
        run_command = (_UUID.fullmatch(p.name) and p.stat().st_size <= longest
                       and p.read_bytes().decode("utf-8", "replace") in commands)
        if (logged_js or run_command) and p.name not in resources:
            names.add(p.name)
    return names


def _declare_artifacts(results: Path, outdir: Path, limits: Limits,
                       warnings: list[Warning]) -> list[DeclaredArtifact]:
    """Declare the result files, newest-first, inside the worker's artifact budget.

    The JSON summaries come first deliberately: if a sample drops hundreds of files
    and we hit `max_artifacts`, the thing worth keeping is the analysis, not the
    three-hundredth dropped blob.
    """
    artifacts: list[DeclaredArtifact] = []
    total = 0
    snippets = _snippet_names(results)

    def add(path: Path, kind: str) -> bool:
        nonlocal total
        if len(artifacts) >= limits.max_artifacts:
            return False
        size = path.stat().st_size
        if size > limits.max_artifact_bytes:
            warnings.append(Warning(
                code="artifact_too_large",
                message=f"{path.name} is {size} bytes, over max_artifact_bytes",
            ))
            return True
        if total + size > limits.max_total_artifact_bytes:
            return False
        total += size
        artifacts.append(DeclaredArtifact(
            id=path.name.replace("/", "_")[:128],
            path=str(path.relative_to(outdir)),
            kind=kind,
        ))
        return True

    for name in _ANALYSIS_FILES:
        p = results / name
        # A refused analysis file is never silent, and a smaller one after it may fit.
        if p.is_file() and not add(p, "analysis"):
            warnings.append(Warning(
                code="artifacts_truncated",
                message=f"analysis file {name} omitted: artifact budget exhausted",
            ))

    dropped = sorted((p for p in results.iterdir()
                      if p.is_file() and p.name not in _ANALYSIS_FILES),
                     key=lambda p: p.stat().st_size)
    for p in dropped:
        if not add(p, "snippet" if p.name in snippets else "dropped"):
            warnings.append(Warning(
                code="artifacts_truncated",
                message="dropped files omitted: artifact budget exhausted",
            ))
            break
    return artifacts


class BoxJsEngine:
    """Detonate a JScript/JS sample with box-js and seal its IOCs and dropped files."""

    name = "boxjs"
    # No vbs: box-js has no VBScript interpreter (acorn rejects the source, and HTA
    # <script language=vbscript> blocks are skipped), so a .vbs run is a silent no-op.
    formats = frozenset({"js", "jse", "wsf", "wsh", "hta"})

    def detect(self, input: Path) -> Detection:
        # box-js is dispatched by the host on content gating; this is a nominal
        # answer, not an identification claim. Confidence stays low so nothing
        # downstream mistakes it for a real file-type verdict (that is Magika's job).
        return Detection(label="script", mime="text/javascript",
                         confidence=0.1, source=self.name)

    def detonate(self, input: Path, outdir: Path, limits: Limits) -> DetonationResult:
        run_js = _run_js()
        if not Path(run_js).is_file():
            return DetonationResult(
                payload=Record(fields={"schema_version": SCHEMA_VERSION,
                                   "error": "box_js_missing", "path": run_js}),
                artifacts=[],
                detected=self.detect(input),
                warnings=[Warning(code="box_js_missing",
                                  message=f"no box-js entrypoint at {run_js}")],
                status="engine_error",
            )
        if shutil.which("node") is None:
            return DetonationResult(
                payload=Record(fields={"schema_version": SCHEMA_VERSION, "error": "node_missing"}),
                artifacts=[],
                detected=self.detect(input),
                warnings=[Warning(code="node_missing", message="node not on PATH")],
                status="engine_error",
            )

        if _is_jscript_encoded(input):
            # box-js has no JScript.Encode decoder: it exits 4 asking for an external one,
            # after creating its results dir, which would read as a clean, empty analysis.
            return DetonationResult(
                payload=Record(fields={"schema_version": SCHEMA_VERSION,
                                       "error": "jscript_encoded"}),
                artifacts=[],
                detected=self.detect(input),
                warnings=[Warning(code="jscript_encoded",
                                  message="JScript.Encode script: box-js cannot decode it")],
                status="rejected",
            )

        warnings: list[Warning] = []

        # Split the worker's budget across box-js's stages. box-js defaults each
        # per-stage timeout to a slice of --timeout (upstream commit f74ce6d); we
        # pass them explicitly so the emulation budget is derived from the worker's
        # Limits rather than from box-js's own default, and always leave the VM the
        # largest share. Floor at 1s so a tiny Limits cannot produce --timeout=0.
        vm_timeout = max(1, int(limits.timeout_s * 0.6))
        strip_timeout = max(1, int(limits.timeout_s * 0.1))
        pre_timeout = max(1, int(limits.timeout_s * 0.2))

        argv = [
            "node", run_js, str(input),
            f"--output-dir={outdir}",
            f"--timeout={vm_timeout}",
            f"--strip-timeout={strip_timeout}",
            f"--preprocess-timeout={pre_timeout}",
            # Egress is the worker's decision, never the engine's. With no egress the
            # emulator must not attempt a real fetch; with egress it should, so the
            # next stage is actually retrieved and sealed.
            "--download" if limits.net_egress else "--fake-download",
            *_BASE_ARGV,
            *_extra_argv(),
        ]

        killed = False
        try:
            # NEVER shell=True; argv is a fixed list. The worker is the sandbox.
            # Wall-clock guard sits above box-js's own budget so a wedged node
            # process cannot outlive the job.
            proc = subprocess.run(  # fixed argv, no shell
                argv, capture_output=True, check=False,
                timeout=limits.timeout_s + 10,
            )
            code, stderr = proc.returncode, proc.stderr
        except subprocess.TimeoutExpired as exc:
            killed, code, stderr = True, -9, (exc.stderr or b"")
            warnings.append(Warning(
                code="timeout",
                message=f"box-js exceeded {limits.timeout_s + 10}s wall clock",
            ))

        results = _results_dir(outdir)
        if results is None:
            # box-js produced no results directory at all. This is the failure mode
            # violet_svg used to report as a vague "no results": surface the exit
            # code and stderr tail so a broken image or dependency tree is
            # diagnosable instead of looking like a clean run that found nothing.
            return DetonationResult(
                payload=Record(fields={
                    "schema_version": SCHEMA_VERSION,
                    "error": "no_results_dir",
                    "exit_code": code,
                    "stderr_tail": stderr[-2000:].decode("utf-8", "replace"),
                }),
                artifacts=[],
                detected=self.detect(input),
                warnings=[*warnings, Warning(
                    code="no_results_dir",
                    message="box-js wrote no .results directory",
                )],
                status="engine_error",
            )

        summary = _summarise(results)
        artifacts = _declare_artifacts(results, outdir, limits, warnings)

        if summary["ioc_count"] <= 1:
            # box-js always logs a "Sample Name" IOC, so <=1 means it emulated
            # nothing. Not an error — plenty of samples are inert or bail early —
            # but a consumer ranking by ioc_count should be told it was silent
            # rather than left to infer it.
            warnings.append(Warning(
                code="no_observable_behaviour",
                message="box-js produced no IOCs beyond the sample name",
            ))

        return DetonationResult(
            payload=Record(fields={
                "schema_version": SCHEMA_VERSION,
                "exit_code": code,
                "killed": killed,
                "net_egress": limits.net_egress,
                "results_dir": results.name,
                **summary,
            }),
            artifacts=artifacts,
            detected=self.detect(input),
            warnings=warnings,
            status="ok",
        )


if __name__ == "__main__":
    import sys

    from blastbox.worker.harness import main

    # detect/warmup are optional (the harness hasattr-checks them); the Engine
    # Protocol over-declares them, so this is correct at runtime.
    sys.exit(main(BoxJsEngine()))  # type: ignore[arg-type]
