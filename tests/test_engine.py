"""Unit tests for BoxJsEngine that do not need node or blastbox's runtime."""
import json
from pathlib import Path

import pytest

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
