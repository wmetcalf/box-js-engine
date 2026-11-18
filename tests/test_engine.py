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


def test_results_dir_picks_newest(tmp_path):
    (tmp_path / "a.js.results").mkdir()
    (tmp_path / "b.js.results").mkdir()
    (tmp_path / "not-results").mkdir()
    assert _results_dir(tmp_path).name.endswith(".results")


def test_results_dir_none_when_absent(tmp_path):
    assert _results_dir(tmp_path) is None


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
