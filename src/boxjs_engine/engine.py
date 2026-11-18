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
import signal
import stat
import subprocess
import threading
import time
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
    if not isinstance(got, list):
        return []
    # The budget flags are the engine's: box-js takes the last one given, so an extra
    # --timeout would replace the emulation budget the timeout warning is measured against.
    out: list[str] = []
    skip = False
    for x in map(str, got):
        if skip:
            skip = False
            continue
        flag = x.split("=", 1)[0]
        if flag in _BUDGET_FLAGS:
            skip = "=" not in x
            continue
        out.append(x)
    return out


_BUDGET_FLAGS = frozenset({"--timeout", "--strip-timeout", "--preprocess-timeout"})


def _results_dir(outdir: Path, sample: Path, before: set[str] | frozenset[str] = frozenset()
                 ) -> Path | None:
    """box-js writes `<outdir>/<sample name>.results/`, or `<name>.<i>.results` for the first
    free i (_run.js). Only those names are the run's, and of the ones that were not there
    before the run (`before`), the lowest index is the one box-js took: the sample can write
    anywhere in outdir, so another *.results dir, or a higher index it planted later, is never
    taken."""
    pattern = re.compile(re.escape(sample.name) + r"(?:\.([1-9][0-9]{0,5}))?\.results")
    found = []
    for p in outdir.iterdir():
        m = pattern.fullmatch(p.name)
        if m and p.name not in before and _is_dir(p):
            found.append((int(m.group(1) or 0), p))
    return min(found)[1] if found else None


def _is_dir(p: Path) -> bool:
    try:
        return stat.S_ISDIR(p.lstat().st_mode)
    except OSError:
        return False


def _is_regular(p: Path) -> bool:
    """A regular file, not a symlink, FIFO or device the sample planted in its results dir."""
    try:
        return stat.S_ISREG(p.lstat().st_mode)
    except OSError:
        return False


#: box-js's JSON files are small; anything bigger is not worth parsing for counts.
_MAX_JSON_BYTES = 64 << 20


def _load_json(path: Path, default, max_bytes: int = _MAX_JSON_BYTES):
    if not _is_regular(path) or path.lstat().st_size > max_bytes:
        return default
    try:
        return json.loads(path.read_text(errors="replace"))
    except (OSError, ValueError, RecursionError):   # unreadable, not JSON, or too deep
        return default


def _summarise(results: Path, max_json_bytes: int = _MAX_JSON_BYTES) -> dict:
    """Lift counts out of IOC.json so a consumer can triage without opening artifacts."""
    iocs = _load_json(results / "IOC.json", [], max_json_bytes)
    urls = _load_json(results / "urls.json", [], max_json_bytes)
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


# A JScript.Encode block: "#@~^", a 6-char base64 length, "==", the body, a 6-char checksum,
# "==^#~@". screnc keeps the text before //**Start Encode** plain, so the block need not
# start the file. A match only matters if box-js then logs nothing (see detonate).
_JSE_START = re.compile(rb"#@~\^[A-Za-z0-9+/]{6}==")
_JSE_TAIL = re.compile(rb"[A-Za-z0-9+/]{6}==\^#~@")


def _is_jscript_encoded(path: Path) -> bool:
    """An opener followed, anywhere later, by a checksummed terminator. Both patterns are
    fixed-length, so this is linear (a lazy `.*?` between them was quadratic). The whole
    input is scanned (it is bounded by the worker's Limits.max_input_bytes)."""
    with path.open("rb") as f:
        head = f.read()
    start = _JSE_START.search(head)
    return start is not None and _JSE_TAIL.search(head, start.end()) is not None


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
    # Each file's bytes are read at most once per inode (hard links share one), so planted
    # links cannot multiply the reading.
    seen: dict[tuple[int, int], bool] = {}
    for p in results.iterdir():
        if not _is_regular(p):
            continue
        logged_js = p.suffix == ".js" and _UUID.fullmatch(p.stem)
        run_command = False
        if _UUID.fullmatch(p.name):
            st = p.lstat()
            if st.st_size <= longest:
                key = (st.st_dev, st.st_ino)
                if key not in seen:
                    seen[key] = p.read_bytes().decode("utf-8", "replace") in commands
                run_command = seen[key]
        if (logged_js or run_command) and p.name not in resources:
            names.add(p.name)
    return names


#: blastbox's sealed envelope holds at most this many artifacts, whatever Limits says.
_ENVELOPE_MAX_ARTIFACTS = 16384


def _artifact_id(name: str, taken: dict[str, int]) -> str:
    """A unique artifact id in blastbox's [A-Za-z0-9._-]{1,128} for a file name the sample
    may have chosen (a download keeps its own name: "Invoice (1).pdf"). `taken` maps each
    id handed out to the next suffix to try for that base, so collisions stay linear."""
    base = re.sub(r"[^A-Za-z0-9._-]", "_", name)[:120] or "_"
    candidate, n = base, taken.get(base, 1)
    while candidate in taken:
        n += 1
        candidate = f"{base}-{n}"
    taken[base] = n
    taken.setdefault(candidate, 1)
    return candidate


def _declare_artifacts(results: Path, outdir: Path, limits: Limits,
                       warnings: list[Warning]) -> list[DeclaredArtifact]:
    """Declare the result files, newest-first, inside the worker's artifact budget.

    The JSON summaries come first deliberately: if a sample drops hundreds of files
    and we hit `max_artifacts`, the thing worth keeping is the analysis, not the
    three-hundredth dropped blob.
    """
    artifacts: list[DeclaredArtifact] = []
    ids: dict[str, int] = {}
    total = 0
    snippets = _snippet_names(results)

    def add(path: Path, kind: str) -> bool:
        nonlocal total
        if len(artifacts) >= min(limits.max_artifacts, _ENVELOPE_MAX_ARTIFACTS):
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
            id=_artifact_id(path.name, ids),
            path=str(path.relative_to(outdir)),
            kind=kind,
        ))
        return True

    for name in _ANALYSIS_FILES:
        p = results / name
        # A refused analysis file is never silent, and a smaller one after it may fit.
        if _is_regular(p) and not add(p, "analysis"):
            warnings.append(Warning(
                code="artifacts_truncated",
                message=f"analysis file {name} omitted: artifact budget exhausted",
            ))

    dropped = sorted((p for p in results.iterdir()
                      if _is_regular(p) and p.name not in _ANALYSIS_FILES),
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
    # No vbs: box-js has no VBScript interpreter. wsf/wsh/hta are listed because Loadout
    # routes them here, but box-js parses raw JScript only: those containers make it exit 4,
    # which the engine returns as rejected/unparseable (contract gap containers-not-unpacked).
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

        encoded = _is_jscript_encoded(input)
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
        before = {p.name for p in outdir.iterdir()}
        # stdout is not needed (box-js logs to analysis.log) and the sample can flood it, so it
        # goes to /dev/null; stderr goes through a pipe whose reader keeps only the last 2000
        # bytes, so nothing the sample prints is spooled. When box-js's own timeout fires,
        # _run.js SIGTERMs analyze.js and its sync-rpc worker (stdio inherited) is orphaned,
        # still holding the pipe: box-js runs in its own session, and the whole group is
        # killed once _run.js exits, which ends the pipe.
        tail = bytearray()

        def keep_tail(pipe) -> None:
            for chunk in iter(lambda: pipe.read(65536), b""):
                tail.extend(chunk)
                del tail[:-2000]

        # NEVER shell=True; argv is a fixed list. The worker is the sandbox.
        started = time.monotonic()
        proc = subprocess.Popen(  # fixed argv, no shell
            argv, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE,
            start_new_session=True, bufsize=0)  # raw pipe: no buffer lock for close() to wait on
        reader = threading.Thread(target=keep_tail, args=(proc.stderr,), daemon=True)
        reader.start()
        try:
            # Wall-clock guard above box-js's own budget, so a wedged node process cannot
            # outlive the job.
            code = proc.wait(timeout=limits.timeout_s + 10)
            elapsed = time.monotonic() - started
        except subprocess.TimeoutExpired:
            killed, code, elapsed = True, -9, float(limits.timeout_s + 10)
            warnings.append(Warning(
                code="timeout",
                message=f"box-js exceeded {limits.timeout_s + 10}s wall clock",
            ))
        finally:
            try:
                os.killpg(proc.pid, signal.SIGKILL)
            except (ProcessLookupError, PermissionError):
                pass
            proc.wait()
            # A process that left the session (setsid) may still hold the pipe: give up on the
            # tail after a bound rather than wait for it, and leave the daemon reader behind.
            reader.join(timeout=5)
            if not reader.is_alive():
                proc.stderr.close()
        stderr = bytes(tail)
        # box-js's own --timeout makes _run.js print a line and exit 0. stdout is the sample's
        # to write too (console.log), so it is judged by the clock instead: a run that lasted
        # its whole emulation budget was cut short (or ended at the wire; flagged either way).
        if not killed and elapsed >= vm_timeout:
            warnings.append(Warning(
                code="timeout",
                message=f"box-js's own {vm_timeout}s timeout ended the analysis; results are partial",
            ))

        results = _results_dir(outdir, input, before)
        # Judged on what box-js produced, not on the exit code or a marker alone: a sample can
        # exit 4 itself (host require), and a plain script can quote a JSE marker.
        summary = (_summarise(results, max(_MAX_JSON_BYTES, limits.max_artifact_bytes))
                   if results is not None else None)
        # Nothing logged and nothing written but box-js's own log/index files.
        silent = summary is None or (
            summary["ioc_count"] <= 1
            and all(p.name in ("analysis.log", "IOC.json") for p in results.iterdir()))
        if encoded and silent and code == 4 and not killed and results is not None:
            # box-js has no JScript.Encode decoder: the encoded body is a parse error (exit 4).
            # (After a //**Start Encode** header it is one long comment that parses: that run
            # is ok with warning jscript_encoded_not_decoded, below, as is a plain script that
            # merely quotes a block; the two cannot be told apart without lexing.)
            return DetonationResult(
                payload=Record(fields={"schema_version": SCHEMA_VERSION,
                                       "error": "jscript_encoded"}),
                artifacts=[],
                detected=self.detect(input),
                warnings=[Warning(code="jscript_encoded",
                                  message="JScript.Encode script: box-js cannot decode it")],
                status="rejected",
            )
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

        if code == 4 and not killed and silent:
            # Acorn could not parse the input (box-js's exit 4): a WSF/HTA container, a .wsh,
            # an encoded or broken script. box-js still made its results dir, which would read
            # as a clean, empty analysis.
            return DetonationResult(
                payload=Record(fields={"schema_version": SCHEMA_VERSION, "error": "unparseable",
                                       "exit_code": code}),
                artifacts=[],
                detected=self.detect(input),
                warnings=[Warning(code="unparseable",
                                  message="box-js could not parse the input (or its own "
                                          "rewrite of it) as JScript")],
                status="rejected",
            )

        if code not in (0, 4) and not killed and silent:
            # box-js failed before emulating anything (exit 3: its own rewrite failed; or a
            # signal killed it, a negative code). Not a
            # verdict on the input, and not an empty analysis either.
            return DetonationResult(
                payload=Record(fields={"schema_version": SCHEMA_VERSION, "error": "box_js_failed",
                                       "exit_code": code,
                                       "stderr_tail": stderr[-2000:].decode("utf-8", "replace")}),
                artifacts=[],
                detected=self.detect(input),
                warnings=[Warning(code="box_js_failed",
                                  message=f"box-js exited {code} having logged nothing")],
                status="engine_error",
            )

        assert summary is not None
        if encoded:
            warnings.append(Warning(
                code="jscript_encoded_not_decoded",
                message="the input holds a JScript.Encode block box-js cannot decode; "
                        "results cover only its plain text",
            ))
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
