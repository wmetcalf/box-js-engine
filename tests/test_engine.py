"""Unit tests for BoxJsEngine that do not need node or blastbox's runtime."""
import json
from pathlib import Path

from boxjs_engine.engine import _declare_artifacts, _results_dir, _summarise


def _results(tmp_path: Path, iocs, urls=None) -> Path:
    r = tmp_path / "sample.js.results"
    r.mkdir()
    (r / "IOC.json").write_text(json.dumps(iocs))
    (r / "urls.json").write_text(json.dumps(urls or []))
    return r


def test_results_dir_is_the_samples_own(tmp_path):
    """A decoy *.results dir (newer mtime, another name) must not be taken for the run's."""
    (tmp_path / "sample.js.results").mkdir()
    (tmp_path / "sample.js.results.1").mkdir()
    (tmp_path / "zzz.results").mkdir()
    (tmp_path / "not-results").mkdir()
    assert _results_dir(tmp_path, Path("sample.js")).name == "sample.js.results.1"


def test_results_dir_none_when_absent(tmp_path):
    (tmp_path / "other.js.results").mkdir()
    assert _results_dir(tmp_path, Path("sample.js")) is None


def test_summarise_classifies_ioc_families(tmp_path):
    r = _results(tmp_path, [
        {"type": "Sample Name", "value": {}},
        {"type": "Run", "value": {"command": "cmd /c echo hi"}},
        {"type": "WMI.GetObject.Create", "value": "powershell"},
        {"type": "FileWrite", "value": {"file": "a.ps1"}},
        {"type": "UrlFetch", "value": {"url": "http://x/"}},
    ], urls=["http://x/"])
    s = _summarise(r)
    assert s["ioc_count"] == 5
    assert s["exec_iocs"] == 2      # Run + WMI.GetObject.Create
    assert s["write_iocs"] == 1
    assert s["url_iocs"] == 1
    assert s["url_count"] == 1


def test_summarise_survives_malformed_json(tmp_path):
    r = tmp_path / "x.js.results"
    r.mkdir()
    (r / "IOC.json").write_text("{not json")
    s = _summarise(r)
    assert s["ioc_count"] == 0


class _Limits:
    max_artifacts = 1000
    max_artifact_bytes = 1024
    max_total_artifact_bytes = 4096


def test_analysis_files_declared_before_dropped(tmp_path):
    r = _results(tmp_path, [{"type": "Run", "value": {}}])
    (r / "dropped.bin").write_bytes(b"x" * 10)
    warns = []
    arts = _declare_artifacts(r, tmp_path, _Limits(), warns)
    assert arts[0].id == "IOC.json", "analysis output must outrank dropped files"
    assert any(a.kind == "dropped" for a in arts)


def test_oversize_artifact_is_warned_not_declared(tmp_path):
    r = _results(tmp_path, [])
    (r / "huge.bin").write_bytes(b"x" * 2048)   # > max_artifact_bytes
    warns = []
    arts = _declare_artifacts(r, tmp_path, _Limits(), warns)
    assert "huge.bin" not in {a.id for a in arts}
    assert any(w.code == "artifact_too_large" for w in warns)


def test_every_payload_carries_a_schema_version(tmp_path, monkeypatch):
    from blastbox.limits import Limits

    from boxjs_engine.engine import RUN_JS_ENV, SCHEMA_VERSION, BoxJsEngine

    assert SCHEMA_VERSION == "boxjs.result/1"
    monkeypatch.setenv(RUN_JS_ENV, str(tmp_path / "absent" / "run.js"))
    sample = tmp_path / "s.js"
    sample.write_text("var a = 1;")
    res = BoxJsEngine().detonate(sample, tmp_path, Limits())
    assert res.payload.fields["schema_version"] == SCHEMA_VERSION


def test_snippets_and_env_vars_are_not_declared_as_dropped(tmp_path):
    """A snippets.json without the snippets (a run killed between writing a snippet and
    rewriting the index): snippets are still told apart by what box-js names and writes."""
    r = _results(tmp_path, [{"type": "Run", "value": {"command": "cmd /c echo hi"}}])
    (r / "snippets.json").write_text("{}")
    js = "566349bb-7d1c-4aa2-8915-f20332fcd07d.js"         # lib.logJS: eval'd JS
    cmd = "ab2dee1c-06b2-4f7e-901b-8273d423d049"           # runShellCommand: the command
    res = "8c1dd676-f228-4159-bb73-87cc827a2571"           # logResource: the sample's file
    (r / js).write_text("eval('1')")
    (r / cmd).write_text("cmd /c echo hi")
    (r / res).write_text("dropped\r\n")
    (r / "env_vars.json").write_text(json.dumps({"X": "y"}))
    kinds = {a.id: a.kind for a in _declare_artifacts(r, tmp_path, _Limits(), [])}
    assert kinds[js] == "snippet"
    assert kinds[cmd] == "snippet"
    assert kinds[res] == "dropped"
    assert kinds["env_vars.json"] == "analysis"


def test_a_name_keyed_snippets_index_is_honoured(tmp_path):
    """Upstream box-js writes snippets.json as {file name: {as: ...}}."""
    r = _results(tmp_path, [])
    (r / "snippets.json").write_text(json.dumps({"abc": {"as": "WScript code"}}))
    (r / "abc").write_text("whatever")
    kinds = {a.id: a.kind for a in _declare_artifacts(r, tmp_path, _Limits(), [])}
    assert kinds["abc"] == "snippet"


def test_an_analysis_file_refused_for_budget_is_warned_and_smaller_ones_still_kept(tmp_path):
    r = _results(tmp_path, [{"type": "Run", "value": {}}])
    (r / "snippets.json").write_text("x" * 1000)     # within max_artifact_bytes, over the total
    (r / "analysis.log").write_text("small")

    class Tight(_Limits):
        max_total_artifact_bytes = 600

    warns = []
    ids = {a.id for a in _declare_artifacts(r, tmp_path, Tight(), warns)}
    assert "snippets.json" not in ids
    assert "analysis.log" in ids
    assert any(w.code == "artifacts_truncated" and "snippets.json" in w.message for w in warns)


def test_vbs_is_not_claimed_box_js_has_no_vbscript_interpreter():
    from boxjs_engine.engine import BoxJsEngine

    assert "vbs" not in BoxJsEngine.formats


def test_a_jscript_encoded_script_is_rejected_not_reported_ok(tmp_path, monkeypatch):
    """box-js does not decode JScript.Encode (it exits 4 asking for an external decoder), so
    an encoded script must not come back as a clean, empty `ok` analysis."""
    from blastbox.limits import Limits

    from boxjs_engine.engine import BoxJsEngine

    run_js = tmp_path / "box-js" / "run.js"
    run_js.parent.mkdir()
    run_js.write_text("process.exit(4)")
    monkeypatch.setenv("BOXJS_RUN_JS", str(run_js))
    sample = tmp_path / "s.jse"
    sample.write_bytes(b"\xef\xbb\xbf  #@~^IgAAAA==@#@&/mDkwOR?4.+^V^#~@")
    res = BoxJsEngine().detonate(sample, tmp_path, Limits())
    assert res.status == "rejected"
    assert [w.code for w in res.warnings] == ["jscript_encoded"]
    assert res.payload.fields["error"] == "jscript_encoded"


def test_a_resource_matching_a_run_command_stays_dropped(tmp_path):
    """resources.json names the sample's own writes; one whose bytes equal a Run command is
    still a dropped file, not box-js's saved command."""
    cmd_text = "cmd /c echo contract"
    r = _results(tmp_path, [{"type": "Run", "value": {"command": cmd_text}}])
    cmd = "ab2dee1c-06b2-4f7e-901b-8273d423d049"      # runShellCommand: the command
    res = "8c1dd676-f228-4159-bb73-87cc827a2571"      # logResource: the sample's file
    (r / cmd).write_text(cmd_text)
    (r / res).write_text(cmd_text)
    (r / "snippets.json").write_text(json.dumps({cmd: {"as": "WScript code"}}))
    (r / "resources.json").write_text(json.dumps({res: {"path": "C:\\x.txt"}}))
    kinds = {a.id: a.kind for a in _declare_artifacts(r, tmp_path, _Limits(), [])}
    assert kinds[cmd] == "snippet"
    assert kinds[res] == "dropped"


def _fake_box_js(tmp_path: Path, body: str) -> Path:
    """A stand-in run.js: makes <outdir>/<sample>.results/ then runs `body` (node)."""
    run_js = tmp_path / "fake-box-js" / "run.js"
    run_js.parent.mkdir()
    run_js.write_text(
        "const fs = require('fs'), path = require('path');\n"
        "const out = process.argv.find((a) => a.startsWith('--output-dir=')).slice(13);\n"
        "const res = path.join(out, path.basename(process.argv[2]) + '.results');\n"
        "fs.mkdirSync(res, {recursive: true});\n"
        "fs.writeFileSync(path.join(res, 'analysis.log'), 'log');\n" + body)
    return run_js


def _detonate(tmp_path, monkeypatch, body, data=b"var a = 1;", name="s.js", **limits):
    from blastbox.limits import Limits

    from boxjs_engine.engine import RUN_JS_ENV, BoxJsEngine

    monkeypatch.setenv(RUN_JS_ENV, str(_fake_box_js(tmp_path, body)))
    sample = tmp_path / name
    sample.write_bytes(data)
    out = tmp_path / "out"
    out.mkdir()
    return BoxJsEngine().detonate(sample, out, Limits(**limits)), out


def test_an_input_box_js_cannot_parse_is_rejected_not_an_empty_ok(tmp_path, monkeypatch):
    """box-js exits 4 when Acorn cannot parse the input (a WSF/HTA container, a .wsh)."""
    res, _ = _detonate(tmp_path, monkeypatch, "process.exit(4);", b"<job><script>x</script></job>",
                       name="s.wsf")
    assert res.status == "rejected"
    assert res.payload.fields["error"] == "unparseable"
    assert [w.code for w in res.warnings] == ["unparseable"]


def test_a_jscript_encoded_block_after_a_header_is_rejected(tmp_path, monkeypatch):
    """screnc keeps the text before //**Start Encode** plain, so the marker is mid-file."""
    data = b"// Copyright Contoso\r\n//**Start Encode**#@~^IgAAAA==@#@&/mDkwOR?4.+^V^#~@\r\n"
    res, _ = _detonate(tmp_path, monkeypatch, "process.exit(0);", data, name="s.jse")
    assert res.status == "rejected" and res.payload.fields["error"] == "jscript_encoded"


def test_box_js_exiting_is_not_held_by_a_child_keeping_its_pipes(tmp_path, monkeypatch):
    """box-js's own timeout leaves a sync-rpc child holding stdout/stderr; the engine must
    return when box-js exits (not at the wall clock) and not leave the child behind."""
    import time

    body = ("require('child_process').spawn(process.execPath, ['-e', 'setTimeout(()=>{}, 60000)'],"
            " {stdio: 'inherit'});\nsetTimeout(() => process.exit(0), 200);\n")
    t0 = time.monotonic()
    res, _ = _detonate(tmp_path, monkeypatch, body, timeout_s=10)
    assert time.monotonic() - t0 < 8
    assert res.status == "ok" and res.payload.fields["killed"] is False
    assert res.payload.fields["exit_code"] == 0


def test_only_regular_safely_named_files_are_declared(tmp_path):
    import os

    r = _results(tmp_path, [{"type": "Sample Name", "value": "s"}])
    (r / "real.bin").write_bytes(b"x")
    (r / "link").symlink_to(r / "real.bin")
    os.mkfifo(r / "fifo")
    (r / "Invoice (1).pdf").write_bytes(b"%PDF")
    arts = _declare_artifacts(r, tmp_path, _Limits(), [])
    paths = {a.path.rsplit("/", 1)[-1]: a.id for a in arts}
    assert "link" not in paths and "fifo" not in paths
    assert paths["Invoice (1).pdf"] == "Invoice__1_.pdf"
    assert len({a.id for a in arts}) == len(arts)


def test_hostile_json_in_the_results_dir_is_ignored(tmp_path):
    import os

    r = _results(tmp_path, [{"type": "Sample Name", "value": "s"}])
    (r / "urls.json").write_text("[" * 100000 + "]" * 100000)
    os.remove(r / "IOC.json")
    os.mkfifo(r / "IOC.json")
    s = _summarise(r)
    assert s["ioc_count"] == 0 and s["url_count"] == 0


def test_every_non_ok_payload_carries_a_schema_version(tmp_path, monkeypatch):
    from boxjs_engine.engine import SCHEMA_VERSION

    for body, data in (("process.exit(4);", b"x"), ("", b"#@~^IgAAAA==^#~@")):
        sub = tmp_path / str(len(body))
        sub.mkdir()
        res, _ = _detonate(sub, monkeypatch, body, data)
        assert res.status != "ok" and res.payload.fields["schema_version"] == SCHEMA_VERSION
    sub = tmp_path / "noresults"
    sub.mkdir()
    from blastbox.limits import Limits

    from boxjs_engine.engine import RUN_JS_ENV, BoxJsEngine
    run_js = sub / "run.js"
    run_js.write_text("process.exit(3)")
    monkeypatch.setenv(RUN_JS_ENV, str(run_js))
    (sub / "s.js").write_text("1")
    res = BoxJsEngine().detonate(sub / "s.js", sub, Limits())
    assert res.status == "engine_error" and res.payload.fields["schema_version"] == SCHEMA_VERSION
    monkeypatch.setenv("PATH", "")
    res = BoxJsEngine().detonate(sub / "s.js", sub, Limits())
    assert res.status == "engine_error" and res.payload.fields["schema_version"] == SCHEMA_VERSION
