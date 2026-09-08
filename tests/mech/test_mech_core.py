"""Tests for the v7.0 Mech-Unit core (P1): intents, probes, resolver,
compiler, state, events.

Covers the Gate P1 contract:
- Manifest schema validation is fail-fast, naming the offending field.
- llm_required: true is structurally rejected.
- Probes return structured results with reason + fix; unknown probes fail
  with a clear message instead of raising.
- Resolver fills placeholders deterministically and logs param ← source;
  unresolvable placeholders raise UnresolvedPlaceholder (never guess).
- Compiler blocks on hard precondition failure and collects unresolved
  entries instead of guessing.
- Plan state machine enforces legal transitions and persists atomically;
  a mid-run crash resumes from the last step boundary.
- Events carry monotonic sequence numbers; subscriber errors never escape.
"""
import os
import sys
import json
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

from core.mech.intents import (  # noqa: E402
    validate_manifest_dict, load_manifest, load_manifest_dir, IntentManifest)
from core.mech.probes import (  # noqa: E402
    ProbeResult, run_probe, probe_names, list_interfaces,
    probe_tools_present, probe_wordlist_available)
from core.mech.resolver import (  # noqa: E402
    Resolver, ResolveContext, UnresolvedPlaceholder, PLACEHOLDER_RE)
from core.mech.compiler import compile_intent, CompiledPlan  # noqa: E402
from core.mech.state import (  # noqa: E402
    PlanRunState, PlanState, StepState)
from core.mech.events import EventBus, socketio_channel, ALL_EVENTS  # noqa: E402


# ═══════════════════════════════════════════════════════════════
# Fixtures
# ═══════════════════════════════════════════════════════════════

def valid_manifest_dict(**overrides):
    base = {
        "id": "wifi_wpa_handshake",
        "name": "WPA/WPA2 Handshake Capture + Crack",
        "category": "wireless",
        "operator_label": "Crack a WiFi password (handshake)",
        "operator_description": "Capture the 4-way handshake and crack it offline.",
        "outcome": "PSK in plaintext, or exhaustion",
        "grants": ["wifi.psk"],
        "time_to_impact": "minutes-to-hours",
        "noise": "high",
        "risk_notes": "Deauth disrupts users. Authorized targets only.",
        "preconditions": [
            {"probe": "tools_present", "with": ["airodump-ng"]},
        ],
        "plan": [
            {"step": "monitor_up", "tool": "monitor_mode_enable",
             "args": {"interface": "{{ resolver.interface.monitor }}"}},
            {"step": "discover", "tool": "airodump_capture",
             "args": {"interface": "{{ resolver.interface.monitor }}",
                      "channel": "{{ resolver.channel.or_hop }}",
                      "capture_file": "{{ resolver.artifacts.capture_prefix }}"},
             "extracts": {"bssid": "([0-9A-Fa-f:]{17})"}},
            {"step": "deauth", "tool": "aireplay_attack",
             "args": {"interface": "auto", "bssid": "{{ target.bssid }}"},
             "when": "{{ facts.clients_seen }}"},
            {"step": "crack", "tool": "aircrack_crack",
             "args": {"cap_file": "{{ artifacts.capture }}",
                      "wordlist": "{{ resolver.wordlist.adaptive }}"},
             "gate": {"output": "KEY FOUND"}},
        ],
        "artifacts": {"capture": "{{ plan_dir }}/capture-01.cap"},
        "llm_required": False,
    }
    base.update(overrides)
    return base


def _write_manifest(directory, data, filename="wifi_wpa_handshake.yaml"):
    import yaml
    path = os.path.join(directory, filename)
    with open(path, "w") as f:
        yaml.safe_dump(data, f)
    return path


def compile_ctx(**overrides):
    """A ResolveContext that satisfies the default fixture manifest."""
    ctx = ResolveContext(
        target={"bssid": "AA:BB:CC:DD:EE:FF", "essid": "TestNet"},
        facts={"clients_seen": True},
        artifacts={"capture": "/tmp/fake-sandbox/capture-01.cap"},
        capture_interface="wlan0mon",
        scan={"channel": "6"},
        interfaces=[{"name": "wlan0mon", "wireless": True, "monitor": True,
                     "up": True}],
        tool_exists=lambda t: True,
        path_exists=lambda p: "rockyou" in p or "lab" in p,
    )
    for k, v in overrides.items():
        setattr(ctx, k, v)
    return ctx


# ═══════════════════════════════════════════════════════════════
# 1. Manifest schema validation (P1.1)
# ═══════════════════════════════════════════════════════════════

class TestManifestValidation(unittest.TestCase):
    def test_valid_manifest_passes(self):
        out = validate_manifest_dict(valid_manifest_dict())
        self.assertEqual(out["id"], "wifi_wpa_handshake")

    def test_missing_required_field_names_field(self):
        data = valid_manifest_dict()
        del data["noise"]
        with self.assertRaises(ValueError) as cm:
            validate_manifest_dict(data)
        self.assertIn("'noise'", str(cm.exception))

    def test_llm_required_true_rejected(self):
        with self.assertRaises(ValueError) as cm:
            validate_manifest_dict(valid_manifest_dict(llm_required=True))
        self.assertIn("llm_required", str(cm.exception))
        self.assertIn("advisor", str(cm.exception).lower())

    def test_llm_required_absent_ok(self):
        data = valid_manifest_dict()
        del data["llm_required"]
        validate_manifest_dict(data)  # must not raise

    def test_bad_category_names_field(self):
        with self.assertRaises(ValueError) as cm:
            validate_manifest_dict(valid_manifest_dict(category="space"))
        self.assertIn("'category'", str(cm.exception))

    def test_bad_noise_names_field(self):
        with self.assertRaises(ValueError) as cm:
            validate_manifest_dict(valid_manifest_dict(noise="loud"))
        self.assertIn("'noise'", str(cm.exception))

    def test_duplicate_step_names_rejected(self):
        data = valid_manifest_dict()
        data["plan"][1]["step"] = data["plan"][0]["step"]
        with self.assertRaises(ValueError) as cm:
            validate_manifest_dict(data)
        self.assertIn("duplicate step name", str(cm.exception))

    def test_fallback_colliding_with_main_step_rejected(self):
        data = valid_manifest_dict()
        data["plan"][2]["fallbacks"] = [{"step": "discover", "tool": "x"}]
        with self.assertRaises(ValueError) as cm:
            validate_manifest_dict(data)
        self.assertIn("collides", str(cm.exception))

    def test_fallback_needs_tool_or_use_intent(self):
        data = valid_manifest_dict()
        data["plan"][2]["fallbacks"] = [{"step": "fb_only"}]
        with self.assertRaises(ValueError) as cm:
            validate_manifest_dict(data)
        self.assertIn("use_intent", str(cm.exception))

    def test_bad_retries_rejected(self):
        with self.assertRaises(ValueError):
            validate_manifest_dict(valid_manifest_dict(**{
                "plan": [{"step": "s", "tool": "t", "retries": -1}]}))
        with self.assertRaises(ValueError):
            validate_manifest_dict(valid_manifest_dict(**{
                "plan": [{"step": "s", "tool": "t", "retries": "many"}]}))

    def test_empty_plan_rejected(self):
        with self.assertRaises(ValueError) as cm:
            validate_manifest_dict(valid_manifest_dict(plan=[]))
        self.assertIn("'plan'", str(cm.exception))

    def test_bad_id_rejected(self):
        with self.assertRaises(ValueError) as cm:
            validate_manifest_dict(valid_manifest_dict(id="Bad-Id!"))
        self.assertIn("'id'", str(cm.exception))

    def test_non_dict_root_rejected(self):
        with self.assertRaises(ValueError) as cm:
            validate_manifest_dict([1, 2, 3])
        self.assertIn("<root>", str(cm.exception))

    def test_precondition_without_probe_name_rejected(self):
        data = valid_manifest_dict(preconditions=[{"with": ["x"]}])
        with self.assertRaises(ValueError) as cm:
            validate_manifest_dict(data)
        self.assertIn("probe", str(cm.exception))


# ═══════════════════════════════════════════════════════════════
# 2. Probes (P1.2)
# ═══════════════════════════════════════════════════════════════

class TestProbes(unittest.TestCase):
    def test_tools_present_ok(self):
        # sh/python3 exist everywhere python runs
        res = probe_tools_present(["sh", "python3"])
        self.assertTrue(res.ok, res.reason)

    def test_tools_present_missing_have_fix(self):
        res = probe_tools_present(["definitely-not-a-binary-xyz"])
        self.assertFalse(res.ok)
        self.assertEqual(res.missing, ["definitely-not-a-binary-xyz"])
        self.assertIn("apt install", res.fix)

    def test_tools_present_without_with_list(self):
        res = probe_tools_present([])
        self.assertFalse(res.ok)
        self.assertIn("with", res.fix)

    def test_wordlist_available(self):
        with tempfile.NamedTemporaryFile(suffix=".txt", delete=False) as f:
            f.write(b"password\n")
            path = f.name
        try:
            self.assertTrue(probe_wordlist_available([path]).ok)
            res = probe_wordlist_available(["/no/such/file.txt"])
            self.assertFalse(res.ok)
            self.assertEqual(res.missing, ["/no/such/file.txt"])
        finally:
            os.unlink(path)

    def test_unknown_probe_fails_with_fix_not_raise(self):
        res = run_probe("totally_bogus_probe")
        self.assertFalse(res.ok)
        self.assertIn("no probe named", res.reason)
        self.assertIn("valid probes", res.fix)

    def test_registered_probe_names(self):
        names = probe_names()
        self.assertIn("tools_present", names)
        self.assertIn("wireless_adapter_monitor_capable", names)
        self.assertIn("running_as_root", names)

    def test_list_interfaces_with_fake_sysfs(self):
        with tempfile.TemporaryDirectory() as tmp:
            # wlan0: wireless with phy80211 link, operstate up
            os.makedirs(os.path.join(tmp, "wlan0", "wireless"))
            os.symlink("../phy0", os.path.join(tmp, "wlan0", "phy80211"))
            with open(os.path.join(tmp, "wlan0", "operstate"), "w") as f:
                f.write("up")
            # eth0: wired, down
            os.makedirs(os.path.join(tmp, "eth0"))
            with open(os.path.join(tmp, "eth0", "operstate"), "w") as f:
                f.write("down")
            inv = list_interfaces(sys_net=tmp)
            by_name = {it["name"]: it for it in inv}
            self.assertTrue(by_name["wlan0"]["wireless"])
            self.assertTrue(by_name["wlan0"]["up"])
            self.assertFalse(by_name["eth0"]["wireless"])
            self.assertFalse(by_name["eth0"]["up"])

    def test_list_interfaces_missing_sysfs_empty(self):
        self.assertEqual(list_interfaces(sys_net="/no/such/dir"), [])

    def test_probe_crash_degrades(self):
        # A registered probe that raises must yield a ProbeResult, not an exception.
        import core.mech.probes as probes
        def boom(params):
            raise RuntimeError("kaboom")
        probes.PROBE_REGISTRY["crashy_probe"] = boom
        try:
            res = run_probe("crashy_probe")
            self.assertFalse(res.ok)
            self.assertIn("crashed", res.reason)
        finally:
            del probes.PROBE_REGISTRY["crashy_probe"]


# ═══════════════════════════════════════════════════════════════
# 3. Resolver (P1.3)
# ═══════════════════════════════════════════════════════════════

class TestResolver(unittest.TestCase):
    def test_target_lookup(self):
        r = Resolver(compile_ctx())
        val, _src = r._lookup("target.bssid", "bssid")
        self.assertEqual(val, "AA:BB:CC:DD:EE:FF")

    def test_target_missing_raises(self):
        r = Resolver(compile_ctx())
        with self.assertRaises(UnresolvedPlaceholder) as cm:
            r._lookup("target.missing", "x")
        self.assertEqual(cm.exception.path, "target.missing")

    def test_facts_lookup(self):
        r = Resolver(compile_ctx())
        val, src = r._lookup("facts.clients_seen", "when")
        self.assertIs(val, True)
        self.assertIn("facts.clients_seen", src)

    def test_unknown_root_raises(self):
        r = Resolver(compile_ctx())
        with self.assertRaises(UnresolvedPlaceholder):
            r._lookup("nonsense.field", "x")

    def test_interface_monitor_prefers_capture_state(self):
        r = Resolver(compile_ctx())
        val, src = r._lookup("resolver.interface.monitor", "interface")
        self.assertEqual(val, "wlan0mon")
        self.assertIn("operator", src.lower())

    def test_interface_monitor_falls_back_to_inventory(self):
        ctx = compile_ctx(capture_interface=None)
        r = Resolver(ctx)
        val, _ = r._lookup("resolver.interface.monitor", "interface")
        self.assertEqual(val, "wlan0mon")

    def test_interface_monitor_no_interface_raises(self):
        ctx = compile_ctx(capture_interface=None, interfaces=[])
        r = Resolver(ctx)
        with self.assertRaises(UnresolvedPlaceholder):
            r._lookup("resolver.interface.monitor", "interface")

    def test_channel_or_hop_uses_scan_hint(self):
        r = Resolver(compile_ctx())
        val, src = r._lookup("resolver.channel.or_hop", "channel")
        self.assertEqual(val, "6")
        self.assertIn("scan hint", src)

    def test_channel_or_hop_no_hint_hops(self):
        ctx = compile_ctx(scan={})
        r = Resolver(ctx)
        val, src = r._lookup("resolver.channel.or_hop", "channel")
        self.assertEqual(val, "0")
        self.assertIn("hop", src.lower())

    def test_capture_prefix_uses_plan_dir(self):
        ctx = compile_ctx(plan_dir="/tmp/sandbox/plan1")
        r = Resolver(ctx)
        val, _ = r._lookup("resolver.artifacts.capture_prefix", "capture_file")
        self.assertEqual(val, os.path.join("/tmp/sandbox/plan1", "capture"))

    def test_wordlist_adaptive_first_existing(self):
        r = Resolver(compile_ctx())
        val, src = r._lookup("resolver.wordlist.adaptive", "wordlist")
        self.assertTrue(os.path.isabs(val))
        self.assertIn("first existing", src)

    def test_wordlist_adaptive_candidates(self):
        # Custom candidate list: path_exists stub only accepts rockyou/lab,
        # so the custom candidates never match → unresolved.
        r = Resolver(compile_ctx())
        with self.assertRaises(UnresolvedPlaceholder):
            r._lookup("resolver.wordlist.adaptive:/custom/a.txt,/custom/b.txt",
                      "wordlist")

    def test_tool_first_installed(self):
        r = Resolver(compile_ctx())
        val, src = r._lookup("resolver.tool.first_installed:hashcat,john", "tool")
        self.assertEqual(val, "hashcat")
        self.assertIn("first_installed", src)

    def test_tool_first_installed_none_raises(self):
        r = Resolver(compile_ctx(tool_exists=lambda t: False))
        with self.assertRaises(UnresolvedPlaceholder):
            r._lookup("resolver.tool.first_installed:nope1,nope2", "tool")

    def test_resolve_mapping_whole_value_typed(self):
        r = Resolver(compile_ctx())
        out, log = r.resolve_mapping({"when_flag": "{{ facts.clients_seen }}"})
        self.assertIs(out["when_flag"], True)   # typed bool, not "True"
        self.assertEqual(len(log), 1)
        self.assertEqual(log[0].arg_key, "when_flag")

    def test_resolve_mapping_embedded_substitution(self):
        r = Resolver(compile_ctx())
        out, log = r.resolve_mapping(
            {"url": "http://{{ target.bssid }}:8080/x"})
        self.assertEqual(out["url"], "http://AA:BB:CC:DD:EE:FF:8080/x")
        self.assertEqual(len(log), 1)

    def test_resolve_mapping_no_placeholder_passthrough(self):
        r = Resolver(compile_ctx())
        out, log = r.resolve_mapping({"port": 80, "name": "plain"})
        self.assertEqual(out, {"port": 80, "name": "plain"})
        self.assertEqual(log, [])

    def test_source_log_records_template_and_value(self):
        r = Resolver(compile_ctx())
        _, log = r.resolve_mapping({"bssid": "{{ target.bssid }}"})
        entry = log[0].to_dict()
        self.assertEqual(entry["template"], "{{ target.bssid }}")
        self.assertEqual(entry["value"], "AA:BB:CC:DD:EE:FF")
        self.assertIn("target.bssid", entry["source"])

    def test_placeholder_regex_shape(self):
        self.assertEqual(PLACEHOLDER_RE.findall("{{ target.bssid }}"),
                         ["target.bssid"])
        self.assertEqual(PLACEHOLDER_RE.findall("{{target.bssid}}"),
                         ["target.bssid"])
        self.assertEqual(PLACEHOLDER_RE.findall("no placeholders"), [])

    def test_wordlist_adaptive_unresolved_raises(self):
        ctx = compile_ctx(path_exists=lambda p: False)
        r = Resolver(ctx)
        with self.assertRaises(UnresolvedPlaceholder):
            r._lookup("resolver.wordlist.adaptive", "wordlist")


# ═══════════════════════════════════════════════════════════════
# 4. Compiler (P1.4)
# ═══════════════════════════════════════════════════════════════

class TestCompiler(unittest.TestCase):
    def test_compile_happy_path(self):
        manifest = IntentManifest(
            id="wifi_wpa_handshake", name="n", category="wireless",
            operator_label="l", operator_description="d",
            outcome="o", grants=["wifi.psk"], time_to_impact="t",
            noise="high", risk_notes="r",
            preconditions=[
                __import__("core.mech.intents", fromlist=["ProbeSpec"])
                .ProbeSpec(probe="tools_present", raw={"with": ["sh"]})],
            plan=[
                __import__("core.mech.intents", fromlist=["StepSpec"])
                .StepSpec(step="discover", tool="airodump_capture",
                          args={"interface": "{{ resolver.interface.monitor }}",
                                "bssid": "{{ target.bssid }}"},
                          extracts={"bssid": "x"}),
            ],
            artifacts={}, source_path="<test>")
        plan = compile_intent(manifest, compile_ctx(),
                              sandbox_root=tempfile.mkdtemp())
        self.assertIsInstance(plan, CompiledPlan)
        self.assertTrue(plan.runnable)
        self.assertEqual(plan.steps[0].args["interface"], "wlan0mon")
        self.assertEqual(plan.steps[0].args["bssid"], "AA:BB:CC:DD:EE:FF")
        # plan.json written and complete
        report = json.load(open(os.path.join(plan.plan_dir, "plan.json")))
        self.assertEqual(report["intent_id"], "wifi_wpa_handshake")
        self.assertTrue(report["runnable"])
        self.assertEqual(report["resolution_log"][0]["arg"], "interface")

    def test_compile_blocks_on_hard_probe_failure(self):
        manifest = IntentManifest(
            id="needs_tools", name="n", category="wireless",
            operator_label="l", operator_description="d",
            outcome="o", grants=[], time_to_impact="t", noise="low",
            risk_notes="r",
            preconditions=[
                __import__("core.mech.intents", fromlist=["ProbeSpec"])
                .ProbeSpec(probe="tools_present",
                           raw={"with": ["definitely-not-a-binary-xyz"]})],
            plan=[__import__("core.mech.intents", fromlist=["StepSpec"])
                  .StepSpec(step="s", tool="t")],
            source_path="<test>")
        with self.assertRaises(PermissionError) as cm:
            compile_intent(manifest, compile_ctx(), sandbox_root=tempfile.mkdtemp())
        self.assertIn("definitely-not-a-binary-xyz", str(cm.exception))
        self.assertIn("apt install", str(cm.exception))  # fix surfaced

    def test_compile_optional_probe_failure_warns_not_blocks(self):
        from core.mech.intents import ProbeSpec, StepSpec
        manifest = IntentManifest(
            id="opt_probe", name="n", category="host",
            operator_label="l", operator_description="d",
            outcome="o", grants=[], time_to_impact="t", noise="low",
            risk_notes="r",
            preconditions=[ProbeSpec(probe="running_as_root",
                                     raw={"optional": True})],
            plan=[StepSpec(step="s", tool="t", args={"x": "1"})],
            source_path="<test>")
        plan = compile_intent(manifest, compile_ctx(),
                              sandbox_root=tempfile.mkdtemp())
        self.assertTrue(plan.runnable)
        self.assertFalse(
            next(p for p in plan.probe_results if p.probe == "running_as_root").ok)

    def test_compile_collects_unresolved(self):
        from core.mech.intents import ProbeSpec, StepSpec
        manifest = IntentManifest(
            id="needs_target", name="n", category="web",
            operator_label="l", operator_description="d",
            outcome="o", grants=[], time_to_impact="t", noise="low",
            risk_notes="r",
            preconditions=[ProbeSpec(probe="tools_present", raw={"with": ["sh"]})],
            plan=[StepSpec(step="s", tool="t",
                           args={"url": "http://{{ target.host }}/x",
                                 "static": "y"})],
            source_path="<test>")
        plan = compile_intent(manifest, compile_ctx(),
                              sandbox_root=tempfile.mkdtemp())
        self.assertFalse(plan.runnable)
        self.assertEqual(len(plan.unresolved), 1)
        entry = plan.unresolved[0].to_dict()
        self.assertEqual(entry["step"], "s")
        self.assertEqual(entry["arg"], "url")
        self.assertEqual(entry["placeholder"], "target.host")
        # static arg still resolved
        self.assertEqual(plan.steps[0].args["static"], "y")

    def test_compile_artifacts_resolved_and_logged(self):
        from core.mech.intents import ProbeSpec, StepSpec
        manifest = IntentManifest(
            id="with_art", name="n", category="wireless",
            operator_label="l", operator_description="d",
            outcome="o", grants=[], time_to_impact="t", noise="low",
            risk_notes="r",
            preconditions=[ProbeSpec(probe="tools_present", raw={"with": ["sh"]})],
            plan=[StepSpec(step="s", tool="t")],
            artifacts={"cap": "{{ plan_dir }}/capture-01.cap"},
            source_path="<test>")
        plan_dir_root = tempfile.mkdtemp()
        plan = compile_intent(manifest, compile_ctx(), sandbox_root=plan_dir_root)
        self.assertTrue(plan.artifacts["cap"].startswith(plan.plan_dir))
        # plan_dir itself is recorded as the artifact's source.
        self.assertIn("plan sandbox", json.dumps(plan.resolution_log))
        self.assertEqual(plan.artifacts["cap"],
                         os.path.join(plan.plan_dir, "capture-01.cap"))


# ═══════════════════════════════════════════════════════════════
# 5. Plan state machine (P1.5)
# ═══════════════════════════════════════════════════════════════

class TestPlanState(unittest.TestCase):
    def _state(self, tmp):
        st = PlanRunState(plan_id="p1", intent_id="wifi_wpa_handshake",
                          plan_dir=tmp)
        st.set_step_order(["a", "b", "c"])
        return st

    def test_happy_transitions(self):
        with tempfile.TemporaryDirectory() as tmp:
            st = self._state(tmp)
            st.start()
            self.assertEqual(st.state, PlanState.RUNNING.value)
            st.mark_step_started("a")
            st.mark_step_complete("a", 0, 1.0)
            st.complete()
            self.assertEqual(st.state, PlanState.DONE.value)

    def test_illegal_transition_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            st = self._state(tmp)  # COMPILED
            with self.assertRaises(ValueError):
                st.pause()  # COMPILED → PAUSED is illegal
            with self.assertRaises(ValueError):
                st.complete()  # COMPILED → DONE is illegal

    def test_terminal_states_frozen(self):
        with tempfile.TemporaryDirectory() as tmp:
            st = self._state(tmp)
            st.start()
            st.abort()
            with self.assertRaises(ValueError):
                st.resume()

    def test_atomic_persistence_and_reload(self):
        with tempfile.TemporaryDirectory() as tmp:
            st = self._state(tmp)
            st.start()
            st.mark_step_started("a")
            st.mark_step_complete("a", 0, 2.5, output_file="/x.out",
                                  finding="WPA handshake captured")
            st.add_finding({"severity": "high", "title": "handshake"})
            st.save()
            reloaded = PlanRunState.load(tmp)
            self.assertEqual(reloaded.state, PlanState.RUNNING.value)
            self.assertEqual(reloaded.records["a"].state, StepState.SUCCESS.value)
            self.assertEqual(reloaded.records["a"].duration_seconds, 2.5)
            self.assertEqual(reloaded.findings[0]["title"], "handshake")

    def test_resume_point_after_crash(self):
        # kill -9 simulation: state saved after step 'a' completed, step 'b'
        # was mid-run (RUNNING persisted) → resume should restart at 'b'.
        with tempfile.TemporaryDirectory() as tmp:
            st = self._state(tmp)
            st.start()
            st.mark_step_started("a")
            st.mark_step_complete("a", 0, 1.0)
            st.mark_step_started("b")   # persisted RUNNING, then crash
            st.save()
            reloaded = PlanRunState.load(tmp)
            self.assertEqual(reloaded.next_pending_step(), "b")

    def test_resume_all_done_returns_none(self):
        with tempfile.TemporaryDirectory() as tmp:
            st = self._state(tmp)
            st.start()
            for name in ("a", "b", "c"):
                st.mark_step_started(name)
                st.mark_step_complete(name, 0, 0.1)
            st.save()
            self.assertIsNone(PlanRunState.load(tmp).next_pending_step())

    def test_corrupt_state_file_returns_none(self):
        with tempfile.TemporaryDirectory() as tmp:
            with open(os.path.join(tmp, "state.json"), "w") as f:
                f.write("{ not json !!!")
            self.assertIsNone(PlanRunState.load(tmp))

    def test_summary_shape(self):
        with tempfile.TemporaryDirectory() as tmp:
            st = self._state(tmp)
            st.start()
            st.mark_step_started("a")
            st.mark_step_complete("a", 0, 0.1)
            s = st.summary()
            self.assertEqual(s["steps_total"], 3)
            self.assertEqual(s["steps_done"], 1)
            self.assertEqual(s["findings_count"], 0)
            self.assertEqual(s["state"], "running")

    def test_fallback_record_appended(self):
        with tempfile.TemporaryDirectory() as tmp:
            st = self._state(tmp)
            st.start()
            st.add_fallback_record("pmkid_attempt")
            self.assertIn("pmkid_attempt", st.step_order)
            st.mark_step_started("pmkid_attempt")
            st.mark_step_complete("pmkid_attempt", 0, 0.1)
            # 'a' was never started in this state → still the resume point.
            self.assertEqual(st.next_pending_step(), "a")


# ═══════════════════════════════════════════════════════════════
# 6. Event bus (P1.6)
# ═══════════════════════════════════════════════════════════════

class TestEventBus(unittest.TestCase):
    def test_sequence_monotonic(self):
        bus = EventBus()
        seen = []
        bus.subscribe("finding", lambda p: seen.append(p["seq"]))
        bus.emit("finding", {"title": "1"})
        bus.emit("finding", {"title": "2"})
        bus.emit("finding", {"title": "3"})
        self.assertEqual(seen, [1, 2, 3])

    def test_unknown_event_rejected(self):
        bus = EventBus()
        with self.assertRaises(ValueError):
            bus.subscribe("not_a_real_event", lambda p: None)
        with self.assertRaises(ValueError):
            bus.emit("not_a_real_event")

    def test_subscriber_error_does_not_propagate(self):
        bus = EventBus()
        bus.subscribe("finding", lambda p: 1 / 0)
        payload = bus.emit("finding", {"title": "ok"})  # must not raise
        self.assertEqual(payload["title"], "ok")

    def test_payload_enriched_with_event_and_seq(self):
        bus = EventBus()
        payload = bus.emit("step_started", {"step": "a", "attempt": 1})
        self.assertEqual(payload["event"], "step_started")
        self.assertEqual(payload["seq"], 1)
        self.assertEqual(payload["step"], "a")

    def test_socketio_channel_mapping(self):
        self.assertEqual(socketio_channel("finding"), "mech_finding")
        self.assertEqual(socketio_channel("step_started"), "mech_step_started")

    def test_all_events_have_channels(self):
        for event in ALL_EVENTS:
            self.assertTrue(socketio_channel(event).startswith("mech_"))


# ═══════════════════════════════════════════════════════════════
# 7. Manifest directory loading (P1.1)
# ═══════════════════════════════════════════════════════════════

class TestManifestDir(unittest.TestCase):
    def test_load_dir_roundtrip(self):
        with tempfile.TemporaryDirectory() as tmp:
            _write_manifest(tmp, valid_manifest_dict())
            _write_manifest(tmp, valid_manifest_dict(
                id="wifi_pmkid", name="PMKID"), filename="wifi_pmkid.yaml")
            manifests = load_manifest_dir(tmp)
            self.assertEqual(set(manifests), {"wifi_wpa_handshake", "wifi_pmkid"})
            self.assertIsInstance(manifests["wifi_pmkid"], IntentManifest)

    def test_load_dir_duplicate_ids_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            _write_manifest(tmp, valid_manifest_dict())
            _write_manifest(tmp, valid_manifest_dict(),
                            filename="copy_of_same.yaml")
            with self.assertRaises(ValueError) as cm:
                load_manifest_dir(tmp)
            self.assertIn("duplicate manifest id", str(cm.exception))

    def test_load_dir_broken_manifest_raises(self):
        with tempfile.TemporaryDirectory() as tmp:
            _write_manifest(tmp, valid_manifest_dict())
            _write_manifest(tmp, {"id": "broken"}, filename="broken.yaml")
            with self.assertRaises(ValueError) as cm:
                load_manifest_dir(tmp)
            self.assertIn("broken.yaml", str(cm.exception))

    def test_load_dir_missing_dir_raises(self):
        with self.assertRaises(ValueError):
            load_manifest_dir("/no/such/dir")

    def test_load_manifest_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = _write_manifest(tmp, valid_manifest_dict())
            m = load_manifest(path)
            self.assertEqual(m.id, "wifi_wpa_handshake")
            self.assertEqual(m.plan[3].step, "crack")
            self.assertFalse(m.llm_required)
# ═════════════════════════════════════════════════════════════
# v7.1 Task 2 — resume across process restarts (plan.json rebuild)
# ═══════════════════════════════════════════════════════════════

class TestResumeAcrossRestart(unittest.TestCase):
    """A fresh MechUnit (new process) must be able to resume a plan that was
    compiled by another process — the CLI spawns a new unit per invocation,
    so this is the only path that makes crash recovery real."""

    def _unit(self, sandbox):
        from core.mech import MechUnit, DEFAULT_MANIFEST_DIR
        return MechUnit(config={}, manifest_dir=DEFAULT_MANIFEST_DIR,
                        sandbox_root=sandbox)

    def test_resume_rebuilds_plan_from_report(self):
        sandbox = tempfile.mkdtemp()
        unit = self._unit(sandbox)
        plan = unit.compile("wifi_pmkid", target={"bssid": "AA:BB:CC:DD:EE:FF"})
        unit.run(plan)  # terminal state (tools absent in test env → failed/done)
        # Simulate a NEW process: fresh MechUnit, same sandbox.
        unit2 = self._unit(sandbox)
        st = unit2.resume(plan.plan_id)  # must not raise KeyError
        self.assertIn(st.state, ("done", "failed", "aborted"))

    def test_resume_never_ran_compiled_plan(self):
        sandbox = tempfile.mkdtemp()
        unit = self._unit(sandbox)
        plan = unit.compile("wifi_pmkid", target={"bssid": "AA:BB:CC:DD:EE:FF"})
        st = unit.resume(plan.plan_id)  # COMPILED → runs to terminal
        self.assertIn(st.state, ("done", "failed", "aborted"))

    def test_resume_unknown_plan_raises_keyerror(self):
        unit = self._unit(tempfile.mkdtemp())
        with self.assertRaises(KeyError):
            unit.resume("wifi_pmkid_19700101_000000")

    def test_list_plans_finds_persisted_runs(self):
        sandbox = tempfile.mkdtemp()
        unit = self._unit(sandbox)
        plan = unit.compile("wifi_pmkid", target={"bssid": "AA:BB:CC:DD:EE:FF"})
        names = [p["plan_id"] for p in unit.list_plans()]
        self.assertIn(plan.plan_id, names)
        entry = next(p for p in unit.list_plans()
                     if p["plan_id"] == plan.plan_id)
        self.assertEqual(entry["intent_id"], "wifi_pmkid")

    def test_get_plan_report_roundtrip(self):
        unit = self._unit(tempfile.mkdtemp())
        plan = unit.compile("wifi_pmkid", target={"bssid": "AA:BB:CC:DD:EE:FF"})
        report = unit.get_plan_report(plan.plan_id)
        self.assertEqual(report["plan_id"], plan.plan_id)
        self.assertEqual(report["intent_id"], "wifi_pmkid")


if __name__ == "__main__":
    unittest.main()
