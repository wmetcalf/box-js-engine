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
    (tmp_path / "sample.js.2.results").mkdir()     # box-js _run.js: <name>.<i>.results
    (tmp_path / "sample.js.10.results").mkdir()
    (tmp_path / "zzz.results").mkdir()
    (tmp_path / "not-results").mkdir()
    # In a fresh outdir box-js takes the first free name; a run with nothing before it
    # picks <name>.results even if higher indexes appear later (planted by the sample).
    assert _results_dir(tmp_path, Path("sample.js")).name == "sample.js.results"
    assert _results_dir(tmp_path, Path("sample.js"),
                        before={"sample.js.results"}).name == "sample.js.2.results"


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


def test_summarise_counts_the_node_module_stub_iocs(tmp_path):
    """box-js's node stubs log their own IOC names (boilerplate.js): child_process as
    `process ...`, http/https/dns/net by module and method. Each is execution or network
    evidence, not just another entry in ioc_count."""
    r = _results(tmp_path, [
        {"type": "Sample Name", "value": {}},
        {"type": "process execSync()/exec()", "value": {"command": "whoami"}},
        {"type": "process spawn()", "value": {"file": "cmd.exe"}},
        {"type": "process fork()", "value": {"file": "x.js"}},
        {"type": "http.get()", "value": {"url": "http://a.invalid/"}},
        {"type": "http.request()", "value": {"url": "http://a.invalid/"}},
        {"type": "https.get()", "value": {"url": "https://b.invalid/"}},
        {"type": "https.request()", "value": {"url": "https://b.invalid/"}},
        {"type": "dns.lookup()", "value": {"hostname": "c.invalid"}},
        {"type": "dns.resolveTxt()", "value": {"hostname": "c.invalid"}},
        {"type": "net.createConnection()", "value": {"host": "d.invalid"}},
        {"type": "axios.get()", "value": {"url": "http://e.invalid/"}},
        {"type": "axios.post()", "value": {"url": "http://e.invalid/"}},
        {"type": "socket.io-client()", "value": {"url": "http://e.invalid/"}},
        # Not a module call: a lookalike name must not be counted by prefix alone.
        {"type": "https.", "value": {}},
        {"type": "dnsx.lookup()", "value": {}},
    ])
    s = _summarise(r)
    assert s["ioc_count"] == 16
    assert s["exec_iocs"] == 3
    assert s["url_iocs"] == 10
    assert s["write_iocs"] == 0


def test_summarise_counts_the_other_launch_and_fetch_iocs(tmp_path):
    """Launches and fetches box-js logs outside the node stubs: a remote MSI install, the JXA
    app launch (box-js's own tools/harrington-enrich.js counts it as a launch), the JXA and
    jQuery/beacon fetches. Not $.NSTask: box-js's logIOC for it is commented out, so the type
    is never emitted and counting it would claim a coverage box-js does not have."""
    r = _results(tmp_path, [
        {"type": "WindowsInstaller", "value": {"url": "http://a.invalid/p.msi"},
         "description": "The script installed a remote MSI."},
        {"type": "$.NSWorkSpace.sharedWorkspace.openApplicationAtURLConfigurationCompletionHandler()",
         "value": {"url": "file:///x.app"}},
        {"type": "$.NSData.dataWithContentsOfURL()", "value": {"url": "http://b.invalid/"}},
        {"type": "$.NSURLSession.sessionWithConfiguration().dataTaskWithURLCompletionHandler()",
         "value": {"url": "http://b.invalid/"}},
        {"type": "AJAX", "value": {"url": "http://c.invalid/"}},
        {"type": "JQuery.get()", "value": {"url": "http://c.invalid/"}},
        {"type": "JQuery.getJSON()", "value": {"url": "http://c.invalid/"}},
        {"type": "navigator.sendBeacon()", "value": {"url": "http://c.invalid/"}},
    ])
    s = _summarise(r)
    assert (s["exec_iocs"], s["url_iocs"], s["write_iocs"]) == (2, 6, 0)


def test_summarise_tells_entries_of_one_type_apart_by_what_box_js_logged(tmp_path):
    """Types box-js logs for more than one action: an XMLHttpRequest open() carries a url, a
    setRequestHeader does not. WindowsInstaller is a launch whether InstallProduct or
    OpenPackage logged it: box-js drops a later entry whose (type, value) matches an earlier
    one, so an open then an install of one URL leaves only the open's entry. Plus the fetches logged under their own names
    (WMI GetObject moniker, IE Navigate, Image.src, chrome.runtime.sendMessage) and
    PayloadExec, box-js's sign that a downloaded stage ran."""
    r = _results(tmp_path, [
        {"type": "XMLHttpRequest", "value": {"method": "POST", "url": "https://a.invalid/c"}},
        {"type": "XMLHttpRequest", "value": {"field": "X-Id", "value": "1"}},
        {"type": "WindowsInstaller", "value": {"url": "http://b.invalid/p.msi"},
         "description": "The script installed a remote MSI."},
        {"type": "WindowsInstaller", "value": {"url": "http://b.invalid/q.msi"},
         "description": "The script opened a remote MSI package."},
        {"type": "GetObject()", "value": "script:http://c.invalid/p.sct"},
        {"type": "InternetExplorer.Application", "value": {"url": "http://c.invalid/"}},
        {"type": "Image.src", "value": "https://c.invalid/p.gif"},
        {"type": "Remote Script", "value": {"url": "https://c.invalid/stage2.js"}},
        {"type": "chrome.runtime.sendMessage", "value": {"method": "??", "url": "http://c.invalid/"}},
        {"type": "PayloadExec", "value": "EXECUTED DOWNLOADED PAYLOAD"},
    ])
    s = _summarise(r)
    assert (s["exec_iocs"], s["url_iocs"]) == (3, 6)


def test_element_src_counts_only_a_network_url(tmp_path):
    """box-js logs Remote Script for the src of any created element and Image.src for any
    value: about:blank, data: URIs and decoded inline HTML fetch nothing."""
    r = _results(tmp_path, [
        {"type": "Remote Script", "value": {"url": "https://c.invalid/stage2.js"}},
        {"type": "Remote Script", "value": {"url": "//c.invalid/stage3.js"}},
        {"type": "Remote Script", "value": {"url": "about:blank"}},
        {"type": "Remote Script", "value": {"url": "data:image/gif;base64,R0lGODlhAQABAAAAACw="}},
        {"type": "Remote Script", "value": {"url": "<b>hi</b>"}},
        # box-js decodes a data:text/html;base64 src and logs the decoded text, any text.
        {"type": "Remote Script", "value": {"url": "alert(1)"}},
        {"type": "Remote Script", "value": {"url": "var a = 1;\nrun(a)"}},
        {"type": "Image.src", "value": "HTTP://c.invalid/p.gif"},
        {"type": "Image.src", "value": "data:image/png;base64,AAAA"},
        {"type": "Image.src", "value": {"not": "a string"}},
        # Path-relative: the browser fetches it from the page's origin.
        {"type": "Image.src", "value": "gate.php?c=1"},
        {"type": "Remote Script", "value": {"url": "/wp-content/s2.js"}},
        # An absolute URL counts whatever characters its path or query holds.
        {"type": "Image.src", "value": "https://c2.invalid/collect;sid=7"},
        {"type": "Remote Script", "value": {"url": "https://c2.invalid/a.php?q=('x'){1}"}},
        {"type": "Image.src", "value": "  //c2.invalid/p(1).gif"},
        # A script element of box-js's ActiveXObject("dom") document, appended or given a src
        # by setAttribute: logged as ScriptSrc (and kept out of urls.json by box-js).
        {"type": "ScriptSrc", "value": {"url": "https://c2.invalid/stage.js", "tag": "script"}},
        {"type": "ScriptSrc", "value": {"url": "about:blank", "tag": "script"}},
    ])
    assert _summarise(r)["url_iocs"] == 9


def test_no_url_family_entry_counts_a_target_that_fetches_nothing(tmp_path):
    """about:, data:, javascript: and blob: targets are not requests whichever API got
    them (IE Navigate('about:blank'), fetch(dataUri) for HTML smuggling); entries without a
    url (a dns query's hostname) still count."""
    r = _results(tmp_path, [
        {"type": "InternetExplorer.Application", "value": {"url": "about:blank"}},
        {"type": "fetch", "value": {"url": "data:application/octet-stream;base64,TVqQ"}},
        {"type": "UrlFetch", "value": {"url": " DATA:text/plain,x", "method": "GET"}},
        {"type": "XMLHttpRequest", "value": {"method": "GET", "url": "blob:https://a/1"}},
        {"type": "fetch", "value": {"url": "https://c2.invalid/a"}},
        {"type": "Window Location", "value": {"url": "https://login.invalid/oauth2"}},
        {"type": "window.open()", "value": {"url": "https://payload.invalid/invoice.zip"}},
        {"type": "window.open()", "value": {"url": "about:blank"}},
        {"type": "dns.lookup()", "value": {"hostname": "c2.invalid"}},
        {"type": "GetObject()", "value": "script:http://c2.invalid/p.sct"},
        # An anchor's href and setAttribute('src'|'href') share these types: not counted.
        {"type": "HREF Location", "value": {"url": "https://a.invalid/"}},
        {"type": "Element Source", "value": {"val": "https://a.invalid/"}},
    ])
    assert _summarise(r)["url_iocs"] == 5


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

    assert SCHEMA_VERSION == "boxjs.result/2"
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
    res, _ = _detonate(tmp_path, monkeypatch, "process.exit(4);",
                       b"\xef\xbb\xbf  #@~^IgAAAA==@#@&/mDkwOR?4.+^VIAAAAA==^#~@", name="s.jse")
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


def test_a_jscript_encoded_block_after_a_header_is_flagged(tmp_path, monkeypatch):
    """screnc keeps the text before //**Start Encode** plain, so the marker is mid-file and
    box-js parses the block as a comment (exit 0). That parses, so it is not a rejection, but
    the result says the encoded block went unanalysed. (A plain script quoting a whole block
    in a string looks the same, and is not thrown away.)"""
    data = b"// Copyright Contoso\r\n//**Start Encode**#@~^IgAAAA==@#@&/mDkwOR?4.+^VIAAAAA==^#~@\r\n"
    res, _ = _detonate(tmp_path, monkeypatch, "process.exit(0);", data, name="s.jse")
    assert res.status == "ok"
    assert "jscript_encoded_not_decoded" in [w.code for w in res.warnings]


def test_an_encoded_input_with_no_results_dir_is_an_engine_error(tmp_path, monkeypatch):
    from blastbox.limits import Limits

    from boxjs_engine.engine import RUN_JS_ENV, BoxJsEngine

    run_js = tmp_path / "run.js"
    run_js.write_text("process.exit(4)")       # box-js broken before making its results dir
    monkeypatch.setenv(RUN_JS_ENV, str(run_js))
    (tmp_path / "s.jse").write_bytes(b"#@~^IgAAAA==@#@&/mDkwOR?4.+^VIAAAAA==^#~@")
    res = BoxJsEngine().detonate(tmp_path / "s.jse", tmp_path, Limits())
    assert res.status == "engine_error" and res.payload.fields["error"] == "no_results_dir"


def test_detonate_takes_box_js_retry_dir_over_a_stale_one(tmp_path, monkeypatch):
    from blastbox.limits import Limits

    from boxjs_engine.engine import RUN_JS_ENV, BoxJsEngine

    run_js = tmp_path / "run.js"
    run_js.write_text(
        "const fs = require('fs'), path = require('path');\n"
        "const out = process.argv.find((a) => a.startsWith('--output-dir=')).slice(13);\n"
        "const res = path.join(out, 's.js.1.results'); fs.mkdirSync(res);\n"
        "fs.writeFileSync(path.join(res, 'IOC.json'), JSON.stringify([{type: 'Sample Name'},"
        " {type: 'Run', value: {command: 'x'}}]));\n")
    monkeypatch.setenv(RUN_JS_ENV, str(run_js))
    out = tmp_path / "out"
    (out / "s.js.results").mkdir(parents=True)         # stale, from before this run
    (tmp_path / "s.js").write_text("1")
    res = BoxJsEngine().detonate(tmp_path / "s.js", out, Limits())
    assert res.payload.fields["results_dir"] == "s.js.1.results"


def test_a_zero_index_decoy_is_not_box_js_dir(tmp_path):
    (tmp_path / "sample.js.results").mkdir()
    (tmp_path / "sample.js.0.results").mkdir()           # box-js never makes index 0
    assert _results_dir(tmp_path, Path("sample.js")).name == "sample.js.results"


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

    for body, data in (("process.exit(4);", b"x"), ("process.exit(4); ", b"#@~^IgAAAA==xIAAAAA==^#~@")):
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


def test_exit_4_after_real_behaviour_is_not_a_rejection(tmp_path, monkeypatch):
    """Evidence logged before an exit 4 is kept: the status is judged on what box-js produced,
    not on the exit code alone."""
    body = ("fs.writeFileSync(path.join(res, 'IOC.json'), JSON.stringify([{type: 'Sample Name'},"
            " {type: 'Run', value: {command: 'cmd /c whoami'}}]));\nprocess.exit(4);\n")
    res, _ = _detonate(tmp_path, monkeypatch, body)
    assert res.status == "ok" and res.payload.fields["exec_iocs"] == 1


def test_a_plain_script_quoting_a_jse_marker_is_analysed(tmp_path, monkeypatch):
    body = ("fs.writeFileSync(path.join(res, 'IOC.json'), JSON.stringify([{type: 'Sample Name'},"
            " {type: 'Run', value: {command: 'cmd /c whoami'}}]));\n")
    data = b"var m = '#@~^AAAAAA=='; new ActiveXObject('WScript.Shell').Run('cmd /c whoami');"
    res, _ = _detonate(tmp_path, monkeypatch, body, data)
    assert res.status == "ok"


def test_a_large_ioc_json_within_the_artifact_budget_is_counted(tmp_path):
    from boxjs_engine.engine import _summarise

    r = _results(tmp_path, [{"type": "Sample Name"}, {"type": "Run", "value": {"command": "x" * (70 << 20)}}])
    assert _summarise(r, max_json_bytes=128 << 20)["exec_iocs"] == 1


def test_the_jse_check_is_linear(tmp_path):
    import time

    from boxjs_engine.engine import _is_jscript_encoded

    p = tmp_path / "s.js"
    p.write_bytes(b"/*" + b"#@~^AAAAAA==" * (1 << 16) + b"*/ var a = 1;")
    t0 = time.monotonic()
    assert _is_jscript_encoded(p) is False
    assert time.monotonic() - t0 < 2


def test_an_encoded_block_behind_a_plain_prologue_is_flagged(tmp_path, monkeypatch):
    body = ("fs.writeFileSync(path.join(res, 'IOC.json'), JSON.stringify([{type: 'Sample Name'},"
            " {type: 'ActiveX Object Created', value: 'Scripting.FileSystemObject'}]));\n")
    data = (b'var fso = new ActiveXObject("Scripting.FileSystemObject");\r\n'
            b"//**Start Encode**#@~^IgAAAA==@#@&/mDkwOR?4.+^VIAAAAA==^#~@\r\n")
    res, _ = _detonate(tmp_path, monkeypatch, body, data, name="s.jse")
    assert res.status == "ok"
    assert "jscript_encoded_not_decoded" in [w.code for w in res.warnings]


def test_box_js_own_timeout_is_reported(tmp_path, monkeypatch):
    """box-js's own --timeout (60% of timeout_s, here 1 s) ends the run with exit 0."""
    body = "setTimeout(() => process.exit(0), 1300);\n"
    res, _ = _detonate(tmp_path, monkeypatch, body, timeout_s=2)
    assert res.payload.fields["killed"] is False
    assert "timeout" in [w.code for w in res.warnings]


def test_stdout_cannot_fake_or_hide_box_js_timeout(tmp_path, monkeypatch):
    body = "console.log('done\\nAnalysis for s.js timed out.'); process.exit(0);\n"
    res, _ = _detonate(tmp_path, monkeypatch, body, timeout_s=10)
    assert "timeout" not in [w.code for w in res.warnings]


def test_a_planted_higher_index_results_dir_is_not_taken(tmp_path, monkeypatch):
    body = ("fs.writeFileSync(path.join(res, 'IOC.json'), JSON.stringify([{type: 'Sample Name'},"
            " {type: 'Run', value: {command: 'cmd /c whoami'}}]));\n"
            "const decoy = path.join(out, 's.js.5.results');\nfs.mkdirSync(decoy);\n"
            "fs.writeFileSync(path.join(decoy, 'IOC.json'), JSON.stringify([{type: 'Sample Name'}]));\n")
    res, _ = _detonate(tmp_path, monkeypatch, body)
    assert res.payload.fields["results_dir"] == "s.js.results"
    assert res.payload.fields["exec_iocs"] == 1


def test_the_jse_check_finds_a_block_after_a_bad_terminator(tmp_path):
    from boxjs_engine.engine import _is_jscript_encoded

    p = tmp_path / "s.js"
    p.write_bytes(b"#@~^AAAAAA== x ==^#~@ then #@~^IgAAAA==body IAAAAA==^#~@")
    assert _is_jscript_encoded(p) is True
    p.write_bytes(b"#@~^AAAAAA== x ==^#~@ y IAAAAA==^#~@")      # one opener, bad then good tail
    assert _is_jscript_encoded(p) is True
    p.write_bytes(b"var s = '#@~^AAAAAA==';")
    assert _is_jscript_encoded(p) is False


def test_extra_argv_cannot_override_the_budget(monkeypatch):
    from boxjs_engine.engine import EXTRA_ARGV_ENV, _extra_argv

    monkeypatch.setenv(EXTRA_ARGV_ENV, json.dumps(
        ["--timeout=4", "--strip-timeout", "9", "--preprocess-timeout=1", "--no-rewrite"]))
    assert _extra_argv() == ["--no-rewrite"]


def test_files_written_before_a_self_exit_4_are_kept(tmp_path, monkeypatch):
    body = ("fs.writeFileSync(path.join(res, 'IOC.json'), JSON.stringify([{type: 'Sample Name'}]));\n"
            "fs.writeFileSync(path.join(res, 'payload.bin'), 'MZ');\nprocess.exit(4);\n")
    res, _ = _detonate(tmp_path, monkeypatch, body)
    assert res.status == "ok"
    assert "payload.bin" in {a.id for a in res.artifacts}


def test_a_stdout_flood_is_not_spooled_to_disk(tmp_path, monkeypatch):
    """stdout is unused and stderr keeps only a tail: nothing a sample prints is stored."""
    import pytest

    if not Path("/proc/self/fd").is_dir():
        pytest.skip("counts open files through /proc (Linux)")
    import os as _os
    import threading

    import tempfile as _tempfile

    # Measured on this test's own tree, with every temp dir (this process's and the
    # child's) inside it: the filesystem's free space is shared with every other process
    # and made the test flaky. A spool may be nameless (an O_TMPFILE TemporaryFile, or one
    # unlinked after opening), so open files are counted through /proc as well as named ones.
    spool = tmp_path / "tmpdir"
    spool.mkdir()
    monkeypatch.setenv("TMPDIR", str(spool))
    monkeypatch.setattr(_tempfile, "tempdir", str(spool))
    root = str(tmp_path)

    def used() -> int:
        seen: dict[tuple[int, int], int] = {}
        for d, _dirs, files in _os.walk(tmp_path):
            for f in files:
                try:
                    st = _os.lstat(_os.path.join(d, f))
                    seen[(st.st_dev, st.st_ino)] = st.st_size
                except OSError:
                    pass
        for pid in _os.listdir("/proc"):
            if not pid.isdigit():
                continue
            try:
                fds = _os.listdir(f"/proc/{pid}/fd")
            except OSError:
                continue
            for fd in fds:
                try:
                    if _os.readlink(f"/proc/{pid}/fd/{fd}").startswith(root):
                        st = _os.stat(f"/proc/{pid}/fd/{fd}")
                        seen[(st.st_dev, st.st_ino)] = st.st_size
                except OSError:
                    pass
        return sum(seen.values())

    highest = [used()]
    done = threading.Event()

    def watch():
        while not done.is_set():
            highest[0] = max(highest[0], used())
            done.wait(0.01)

    t = threading.Thread(target=watch)
    t.start()
    body = ("const chunk = 'A'.repeat(1 << 20);\n"
            "for (let i = 0; i < 300; i++) { process.stdout.write(chunk); process.stderr.write(chunk); }\n")
    try:
        res, _ = _detonate(tmp_path, monkeypatch, body)
    finally:
        done.set()
        t.join()
    assert res.status == "ok"
    # 600 MiB printed; at no point was more than a little of it on disk.
    assert highest[0] < (64 << 20)


def test_an_unreadable_ioc_report_is_not_called_silent(tmp_path, monkeypatch):
    """box-js rewrites IOC.json whole on every IOC, so a kill mid-write leaves it cut short;
    zero counts then mean 'unknown', not 'no behaviour'."""
    body = ("fs.writeFileSync(path.join(res, 'IOC.json'), '[{\"type\": \"Sample Name\"}, {\"type\": \"Ru');\n"
            "fs.writeFileSync(path.join(res, 'urls.json'), JSON.stringify(['http://a.invalid/']));\n")
    res, _ = _detonate(tmp_path, monkeypatch, body)
    codes = [w.code for w in res.warnings]
    assert res.status == "ok"
    assert codes == ["analysis_unreadable"]
    assert "IOC.json" in res.warnings[0].message
    assert res.payload.fields["url_count"] == 1


def test_a_cut_short_url_list_is_flagged_too(tmp_path, monkeypatch):
    """box-js rewrites urls.json on every logUrl, even of a URL it has, so a kill cuts it
    more often than IOC.json: url_count 0 is then unknown, not zero."""
    body = ("fs.writeFileSync(path.join(res, 'IOC.json'), JSON.stringify([{type: 'Sample Name'},"
            " {type: 'XMLHTTP', value: {url: 'http://c2.invalid/'}}]));\n"
            "fs.writeFileSync(path.join(res, 'urls.json'), '[\\n\\t\"http://c2.inv');\n")
    res, _ = _detonate(tmp_path, monkeypatch, body)
    assert [(w.code, "urls.json" in w.message) for w in res.warnings] == [("analysis_unreadable", True)]
    assert res.payload.fields["url_iocs"] == 1


def test_a_box_js_crash_is_not_a_clean_run(tmp_path, monkeypatch):
    """_run.js turns a signal death of analyze.js (a V8 heap-OOM abort, an OOM kill) into
    exit 0; V8's fatal line on stderr is what is left to tell it from a clean, inert run."""
    body = ("process.stderr.write('\\n<--- Last few GCs --->\\nFATAL ERROR: Reached heap limit "
            "Allocation failed - JavaScript heap out of memory\\n');\n"
            "fs.writeFileSync(path.join(res, 'IOC.json'), JSON.stringify([{type: 'Sample Name'}]));\n")
    res, _ = _detonate(tmp_path, monkeypatch, body)
    assert res.status == "ok"
    assert [w.code for w in res.warnings] == ["box_js_crashed"]
    # The line's text is never echoed: the sample can print such a line too.
    assert "Reached heap limit" not in res.warnings[0].message


def test_a_crash_is_seen_behind_a_long_native_stack_trace(tmp_path, monkeypatch):
    """Node 22 prints a native stack trace after V8's FATAL line, often more than the
    2000-byte stderr tail; the line is recognised as it streams past."""
    body = ("process.stderr.write('\\n\\n<--- JS stacktrace --->\\n\\nFATAL ERROR: Reached heap limit "
            "Allocation failed - JavaScript heap out of memory\\n----- Native stack trace -----\\n');\n"
            "for (let i = 0; i < 40; i++) process.stderr.write(' ' + i + ': 0xdeadbeef node::Something"
            "<v8::internal::Isolate, long template args>::Frame [/usr/local/bin/node]\\n'.repeat(1));\n"
            "fs.writeFileSync(path.join(res, 'IOC.json'), JSON.stringify([{type: 'Sample Name'}]));\n")
    res, _ = _detonate(tmp_path, monkeypatch, body)
    assert [w.code for w in res.warnings] == ["box_js_crashed"]


def test_fatal_text_inside_a_line_is_not_a_crash(tmp_path, monkeypatch):
    """box-js's uglify child prints its parse error as JSON quoting the sample's string, so
    a sample can put 'FATAL ERROR: ' mid-line on stderr; only the line-start form counts
    (which a sample can still produce in other ways: the warning is a hint, see _FATAL)."""
    body = ("process.stderr.write('{\"message\":\"Unexpected token: string (FATAL ERROR: Reached "
            "heap limit Allocation failed - JavaScript heap out of memory)\",\"line\":4}\\n');\n"
            "fs.writeFileSync(path.join(res, 'IOC.json'), JSON.stringify([{type: 'Sample Name'}]));\n")
    res, _ = _detonate(tmp_path, monkeypatch, body)
    assert [w.code for w in res.warnings] == ["no_observable_behaviour"]


def test_stderr_tail_is_kept_for_a_failed_run(tmp_path, monkeypatch):
    from blastbox.limits import Limits

    from boxjs_engine.engine import RUN_JS_ENV, BoxJsEngine

    run_js = tmp_path / "run.js"
    run_js.write_text("process.stderr.write('x'.repeat(5000) + 'TAILMARK'); process.exit(3)")
    monkeypatch.setenv(RUN_JS_ENV, str(run_js))
    (tmp_path / "s.js").write_text("1")
    res = BoxJsEngine().detonate(tmp_path / "s.js", tmp_path, Limits())
    tail = res.payload.fields["stderr_tail"]
    assert tail.endswith("TAILMARK") and len(tail) <= 2000


def test_the_jse_check_covers_the_whole_input(tmp_path):
    from boxjs_engine.engine import _is_jscript_encoded

    p = tmp_path / "s.js"
    p.write_bytes(b"var a = 1;\n" + b"/" * (2 << 20) + b"\n//**Start Encode**#@~^IgAAAA==body IAAAAA==^#~@")
    assert _is_jscript_encoded(p) is True


def test_a_descendant_outside_the_session_cannot_hold_the_run(tmp_path, monkeypatch):
    """A process that leaves box-js's session (setsid) and keeps stderr open must not keep
    detonate from returning."""
    import time

    body = ("fs.writeFileSync(path.join(res, 'IOC.json'), JSON.stringify([{type: 'Sample Name'},"
            " {type: 'Run', value: {command: 'x'}}]));\n"
            "require('child_process').spawn('sleep', ['30'], {detached: true,"
            " stdio: ['ignore', 'ignore', 'inherit']}).unref();\nprocess.exit(0);\n")
    t0 = time.monotonic()
    res, _ = _detonate(tmp_path, monkeypatch, body, timeout_s=2)
    assert time.monotonic() - t0 < 15
    assert res.status == "ok"


def test_a_silent_box_js_failure_is_an_engine_error(tmp_path, monkeypatch):
    """box-js exits 3 when its own rewrite fails before emulation starts."""
    res, _ = _detonate(tmp_path, monkeypatch, "process.exit(3);")
    assert res.status == "engine_error"
    assert res.payload.fields["error"] == "box_js_failed" and res.payload.fields["exit_code"] == 3


def test_declared_count_stays_under_the_envelope_ceiling(tmp_path):
    from boxjs_engine.engine import _ENVELOPE_MAX_ARTIFACTS

    class Big(_Limits):
        max_artifacts = 70000
        max_total_artifact_bytes = 1 << 30

    r = _results(tmp_path, [{"type": "Sample Name"}])
    for i in range(_ENVELOPE_MAX_ARTIFACTS + 5):
        (r / f"f{i}").write_bytes(b"")
    warns = []
    arts = _declare_artifacts(r, tmp_path, Big(), warns)
    assert len(arts) <= _ENVELOPE_MAX_ARTIFACTS
    assert any(w.code == "artifacts_truncated" for w in warns)


def test_colliding_names_get_ids_in_linear_time(tmp_path):
    import time

    from boxjs_engine.engine import _artifact_id

    taken: dict[str, int] = {}
    t0 = time.monotonic()
    ids = [_artifact_id("x" * 130 + str(i), taken) for i in range(16000)]
    assert time.monotonic() - t0 < 2
    assert len(set(ids)) == len(ids)


def test_snippet_discovery_reads_each_inode_once(tmp_path, monkeypatch):
    import os
    from pathlib import Path as _P

    from boxjs_engine import engine

    cmd = "c" * 1000
    r = _results(tmp_path, [{"type": "Run", "value": {"command": cmd}}])
    first = r / "ab2dee1c-06b2-4f7e-901b-8273d423d049"
    first.write_text(cmd)
    for i in range(50):
        os.link(first, r / f"ab2dee1c-06b2-4f7e-901b-{i:012d}")
    reads = []
    orig = _P.read_bytes
    monkeypatch.setattr(_P, "read_bytes", lambda self: (reads.append(self.name), orig(self))[1])
    engine._snippet_names(r)
    assert len(reads) == 1


def test_a_signal_killed_silent_run_is_an_engine_error(tmp_path, monkeypatch):
    res, _ = _detonate(tmp_path, monkeypatch, "process.kill(process.pid, 'SIGSEGV');")
    assert res.status == "engine_error" and res.payload.fields["error"] == "box_js_failed"


def test_snippet_matching_skips_resources_and_is_bounded(tmp_path, monkeypatch):
    from pathlib import Path as _P

    from boxjs_engine import engine

    cmd = "c" * 100
    r = _results(tmp_path, [{"type": "Run", "value": {"command": cmd}}])
    names = [f"ab2dee1c-06b2-4f7e-901b-{i:012d}" for i in range(20)]
    for n in names:
        (r / n).write_text("d" * 100)          # distinct inodes, same size as the command
    (r / "resources.json").write_text(json.dumps({names[0]: {"path": "C:\\x"}}))
    reads = []
    orig = _P.read_bytes
    monkeypatch.setattr(_P, "read_bytes", lambda self: (reads.append(self.name), orig(self))[1])
    engine._snippet_names(r, max_read_bytes=500)
    assert names[0] not in reads
    assert len(reads) <= 5
