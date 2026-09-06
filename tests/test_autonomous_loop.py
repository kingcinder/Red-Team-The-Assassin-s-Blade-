"""v6.3.5 — Autonomous mode must keep driving many sequential turns.

Regression: process_prompt had an UNCONDITIONAL `break` on action
"waiting_for_user"/"waiting_for_approval". Because the LLM frequently emits
prose/analysis without a JSON tool_call between actions, autonomous mode halted
after a single turn ("autonomous does nothing"). In autonomous mode these
responses must nudge-and-continue instead of break, letting the AI run 100+
turns in sequence.
"""

import sys
import unittest
from unittest.mock import MagicMock

sys.path.insert(0, ".")

import core.orchestrator as orch_mod
from core.orchestrator import (
    Orchestrator,
    DEFAULT_MAX_ITERATIONS,
    AUTONOMOUS_MAX_ITERATIONS,
    AUTONOMOUS_PROSE_NUDGE_LIMIT,
)


def _real_orch():
    """Build a real Orchestrator via __new__ with only the deps
    process_prompt touches stubbed."""
    o = Orchestrator.__new__(Orchestrator)
    o.sessions = MagicMock()
    o.prompts = MagicMock()
    o.prompts.memory_context.return_value = ""
    o.context = MagicMock()
    o.config = {}
    o.tactics = MagicMock()
    o._autonomous = False
    o._callbacks = {}
    o.scorer = MagicMock()
    o.memory = MagicMock()
    o.llm = MagicMock()
    o.llm.get_usage.return_value = {}
    o._current_session = "s"
    o._running = False
    o._emit = lambda *a, **k: None
    o._check_phase_transition = lambda *a, **k: None
    o._run_reflection = MagicMock()
    o._generate_report = MagicMock(return_value="")
    # Force out of the every-10-step memory.save() branch being too aggressive
    o.memory.save.return_value = None
    return o


def _prose_step(text="Analysis here."):
    return {
        "action": "waiting_for_user",
        "tool_calls": [],
        "results": [],
        "llm_response": text,
        "error": None,
    }


class TestAutonomousLoopContinuation(unittest.TestCase):
    def test_autonomous_does_not_break_on_prose_only(self):
        o = _real_orch()
        o._autonomous = True
        # First response is prose (no tool call) but NOT a completion signal —
        # the exact case that used to break the loop in autonomous mode.
        o._run_iteration = MagicMock(side_effect=[
            _prose_step("Let me analyze the targets first."),
            {
                "action": "complete",
                "tool_calls": [{"tool": "nmap_scan", "args": {"target": "10.0.0.1"}}],
                "results": [],
                "llm_response": "engagement complete",
                "error": None,
            },
        ])
        result = o.process_prompt("Test objective", skip_plan=True)
        # The loop must have run BOTH iterations — it was not stopped at turn 1.
        self.assertEqual(result["total_steps"], 2)
        # And it nudged the LLM to keep going rather than stopping.
        nudge_msgs = [c[0][2] for c in o.sessions.add_message.call_args_list
                      if "Continue autonomously" in c[0][2]]
        self.assertTrue(nudge_msgs, "expected a nudge-to-continue system message")

    def test_non_autonomous_still_breaks_on_prose_only(self):
        o = _real_orch()
        o._autonomous = False
        o._run_iteration = MagicMock(side_effect=[
            _prose_step("Let me analyze the targets first."),
            {
                "action": "complete",
                "tool_calls": [],
                "results": [],
                "llm_response": "engagement complete",
                "error": None,
            },
        ])
        result = o.process_prompt("Test objective", skip_plan=True)
        # Non-autonomous keeps its original single-turn behavior.
        self.assertEqual(result["total_steps"], 1)

    def test_autonomous_runs_many_sequential_turns(self):
        o = _real_orch()
        o._autonomous = True
        # Simulate a genuine long engagement: alternating prose and tool calls,
        # ending in completion after N turns.
        n = 40  # many sequential turns
        steps = []
        for i in range(n):
            if i % 2 == 0:  # prose (no tool call)
                steps.append(_prose_step(f"Analyzing round {i}."))
            else:            # tool call (reset the prose guard)
                steps.append({
                    "action": "continue",
                    "tool_calls": [{"tool": "nmap_scan", "args": {"target": "10.0.0.1"}}],
                    "results": [{"status": "success", "tool": "nmap_scan",
                                 "summary": "open ports", "stdout": "22/tcp open"}],
                    "llm_response": f"Running round {i}",
                    "error": None,
                })
        steps.append({
            "action": "complete",
            "tool_calls": [],
            "results": [],
            "llm_response": "engagement complete",
            "error": None,
        })
        o._run_iteration = MagicMock(side_effect=steps)
        result = o.process_prompt("Test objective", skip_plan=True)
        self.assertEqual(result["total_steps"], n + 1)

    def test_prose_only_runaway_guard(self):
        o = _real_orch()
        o._autonomous = True
        # Model keeps producing prose with zero tool calls — the guard must
        # terminate (wrap up as complete) once the streak exceeds the limit,
        # instead of either breaking on turn 1 OR burning the full 500 budget.
        supply = [_prose_step("just thinking...")] * (AUTONOMOUS_PROSE_NUDGE_LIMIT + 8)
        o._run_iteration = MagicMock(side_effect=supply)
        result = o.process_prompt("x", skip_plan=True)
        # It must break at streak > limit, i.e. iteration LIMIT+1, NOT at 500.
        self.assertEqual(result["total_steps"], AUTONOMOUS_PROSE_NUDGE_LIMIT + 1)
        final_msgs = [c[0][2] for c in o.sessions.add_message.call_args_list
                      if "Several consecutive responses with no tool call" in c[0][2]]
        self.assertTrue(final_msgs, "expected the wrap-up guidance after prose runaway")
        # The last step must be marked complete so the report path runs.
        self.assertEqual(result["steps"][-1]["action"], "complete")


class TestAutonomousConfig(unittest.TestCase):
    def test_constants_sane(self):
        self.assertGreater(AUTONOMOUS_MAX_ITERATIONS, 100)
        self.assertLess(DEFAULT_MAX_ITERATIONS, AUTONOMOUS_MAX_ITERATIONS)
        self.assertGreater(AUTONOMOUS_PROSE_NUDGE_LIMIT, 0)


if __name__ == "__main__":
    unittest.main()