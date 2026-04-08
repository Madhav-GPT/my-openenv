"""Behavior and API tests for the final preset-based environment."""

from __future__ import annotations
from typing import get_args

from fastapi.testclient import TestClient
from unified_incident_env.models import ActionType, PostmortemPayload, UnifiedIncidentAction
from unified_incident_env.server import app as app_module
from unified_incident_env.server.app import (
    baseline as baseline_endpoint,
    grader as grader_endpoint,
    health as health_endpoint,
    status as status_endpoint,
    tasks as tasks_endpoint,
)
from unified_incident_env.server.environment import UnifiedIncidentEnvironment
from unified_incident_env.server.grader import UnifiedIncidentGrader


def _postmortem_for(scenario_id: str) -> PostmortemPayload:
    if scenario_id == "database_sqli_outage":
        return PostmortemPayload(
            root_cause="SQL injection in login exhausted and crashed the database.",
            attack_vector="Unsanitized SQL input triggered abusive database load.",
            timeline=[
                "Queried database logs",
                "Inspected code",
                "Patched SQL injection",
                "Verified exploit blocked",
                "Restarted database",
            ],
            remediation_steps=["Use parameterized query", "Restart database"],
            prevention_steps=["Parameterized queries", "DB abuse alerting"],
        )
    if scenario_id == "cache_abuse_broken_access_control":
        return PostmortemPayload(
            root_cause="Broken access control on the internal admin endpoint caused a cache and database cascade.",
            attack_vector="Missing authorization let attackers abuse the internal admin path.",
            timeline=[
                "Queried cache metrics",
                "Queried api-gateway dependencies",
                "Inspected code",
                "Enforced admin role",
                "Verified exploit blocked",
                "Restarted cache",
                "Restarted database",
            ],
            remediation_steps=["Enforce admin role", "Restart cache", "Restart database"],
            prevention_steps=["Authorization checks", "Admin role enforcement", "Rate limits"],
        )
    return PostmortemPayload(
        root_cause="A bad worker deploy plus command injection repeatedly poisoned downstream services.",
        attack_vector="Shell-based worker commands accepted unsafe filenames and kept replaying corruption.",
        timeline=[
            "Queried worker logs",
            "Queried database metrics",
            "Inspected code",
            "Patched command injection",
            "Verified exploit blocked",
            "Rolled back worker",
            "Restarted database",
            "Restarted api-gateway",
        ],
        remediation_steps=["Avoid shell", "Rollback worker", "Restart database", "Restart api-gateway"],
        prevention_steps=["Avoid shell", "Input validation", "Safer deploy checks"],
    )


def _solve_easy(env: UnifiedIncidentEnvironment) -> None:
    env.reset(scenario_id="database_sqli_outage")
    env.step(UnifiedIncidentAction(action_type="query_logs", service="database"))
    env.step(UnifiedIncidentAction(action_type="inspect_code"))
    env.step(
        UnifiedIncidentAction(
            action_type="classify_vulnerability",
            vulnerability_type="sql_injection",
        )
    )
    env.step(
        UnifiedIncidentAction(
            action_type="apply_patch",
            patch_id="parameterized_query",
        )
    )
    env.step(UnifiedIncidentAction(action_type="verify_security_fix"))
    env.step(UnifiedIncidentAction(action_type="submit_security_fix"))
    env.step(UnifiedIncidentAction(action_type="restart_service", service="database"))


def _solve_medium(env: UnifiedIncidentEnvironment) -> None:
    env.reset(scenario_id="cache_abuse_broken_access_control")
    env.step(
        UnifiedIncidentAction(
            action_type="query_metrics",
            service="cache",
            metric="cpu",
        )
    )
    env.step(
        UnifiedIncidentAction(
            action_type="query_dependencies",
            service="api-gateway",
        )
    )
    env.step(UnifiedIncidentAction(action_type="inspect_code"))
    env.step(
        UnifiedIncidentAction(
            action_type="classify_vulnerability",
            vulnerability_type="broken_access_control",
        )
    )
    env.step(
        UnifiedIncidentAction(
            action_type="apply_patch",
            patch_id="enforce_admin_role",
        )
    )
    env.step(UnifiedIncidentAction(action_type="verify_security_fix"))
    env.step(UnifiedIncidentAction(action_type="submit_security_fix"))
    env.step(UnifiedIncidentAction(action_type="restart_service", service="cache"))
    env.step(UnifiedIncidentAction(action_type="restart_service", service="database"))


def _solve_hard(env: UnifiedIncidentEnvironment) -> None:
    env.reset(scenario_id="worker_bad_deploy_command_injection")
    env.step(UnifiedIncidentAction(action_type="query_logs", service="worker"))
    env.step(UnifiedIncidentAction(action_type="inspect_code"))
    env.step(
        UnifiedIncidentAction(
            action_type="classify_vulnerability",
            vulnerability_type="command_injection",
        )
    )
    env.step(
        UnifiedIncidentAction(
            action_type="apply_patch",
            patch_id="avoid_shell",
        )
    )
    env.step(UnifiedIncidentAction(action_type="verify_security_fix"))
    env.step(UnifiedIncidentAction(action_type="submit_security_fix"))
    env.step(UnifiedIncidentAction(action_type="rollback_deploy", service="worker"))
    env.step(UnifiedIncidentAction(action_type="restart_service", service="database"))


def test_happy_path_easy() -> None:
    env = UnifiedIncidentEnvironment()
    _solve_easy(env)
    obs = env.step(
        UnifiedIncidentAction(
            action_type="submit_postmortem",
            postmortem=_postmortem_for("database_sqli_outage"),
        )
    )
    assert obs.done is True
    assert obs.incident_resolved is True
    assert obs.security_subquest_status == "completed"
    assert obs.final_score >= 0.8
    assert obs.final_score < 1.0


def test_reset_score_is_strictly_between_zero_and_one() -> None:
    env = UnifiedIncidentEnvironment()
    for scenario_id in (
        "database_sqli_outage",
        "cache_abuse_broken_access_control",
        "worker_bad_deploy_command_injection",
    ):
        obs = env.reset(scenario_id=scenario_id)
        assert 0.0 < obs.final_score < 1.0


def test_happy_path_medium() -> None:
    env = UnifiedIncidentEnvironment()
    _solve_medium(env)
    obs = env.step(
        UnifiedIncidentAction(
            action_type="submit_postmortem",
            postmortem=_postmortem_for("cache_abuse_broken_access_control"),
        )
    )
    assert obs.done is True
    assert obs.incident_resolved is True
    assert obs.security_subquest_status == "completed"
    assert obs.final_score >= 0.8
    assert obs.final_score < 1.0


def test_happy_path_hard() -> None:
    env = UnifiedIncidentEnvironment()
    _solve_hard(env)
    obs = env.step(
        UnifiedIncidentAction(
            action_type="submit_postmortem",
            postmortem=_postmortem_for("worker_bad_deploy_command_injection"),
        )
    )
    assert obs.done is True
    assert obs.incident_resolved is True
    assert obs.security_subquest_status == "completed"
    assert obs.final_score >= 0.8
    assert obs.final_score < 1.0


def test_trap_path_easy() -> None:
    env = UnifiedIncidentEnvironment()
    env.reset(scenario_id="database_sqli_outage")
    obs = env.step(
        UnifiedIncidentAction(action_type="restart_service", service="api-gateway")
    )
    assert "does not help" in obs.last_action_result.lower()
    assert obs.reward == -0.10


def test_trap_path_medium() -> None:
    env = UnifiedIncidentEnvironment()
    env.reset(scenario_id="cache_abuse_broken_access_control")
    obs = env.step(
        UnifiedIncidentAction(action_type="restart_service", service="database")
    )
    assert "trap" in obs.last_action_result.lower()
    assert obs.reward == -0.10


def test_trap_path_hard() -> None:
    env = UnifiedIncidentEnvironment()
    env.reset(scenario_id="worker_bad_deploy_command_injection")
    obs = env.step(
        UnifiedIncidentAction(action_type="rollback_deploy", service="worker")
    )
    assert "trap" in obs.last_action_result.lower()
    assert obs.reward == -0.10


def test_security_subquest_unlock_requires_evidence_chain_on_medium() -> None:
    env = UnifiedIncidentEnvironment()
    obs = env.reset(scenario_id="cache_abuse_broken_access_control")
    assert obs.security_subquest_status == "locked"
    first = env.step(
        UnifiedIncidentAction(
            action_type="query_metrics",
            service="cache",
            metric="cpu",
        )
    )
    assert first.security_subquest_status == "locked"
    assert first.workflow_stage == "root_cause_analysis"
    second = env.step(
        UnifiedIncidentAction(
            action_type="query_dependencies",
            service="api-gateway",
        )
    )
    assert second.security_subquest_status == "active"
    assert second.workflow_stage == "security_subquest"
    assert second.security_unlock_reason is not None


def test_stage_aware_allowed_actions_and_required_fields() -> None:
    env = UnifiedIncidentEnvironment()
    obs = env.reset(scenario_id="database_sqli_outage")
    assert obs.workflow_stage == "diagnosis"
    assert obs.allowed_actions == [
        "query_logs",
        "query_metrics",
        "query_dependencies",
    ]
    assert obs.required_fields_by_action["query_metrics"] == ["service", "metric"]
    assert obs.valid_action_example is not None
    assert obs.valid_action_example["action_type"] in obs.allowed_actions

    security_obs = env.step(
        UnifiedIncidentAction(action_type="query_logs", service="database")
    )
    assert security_obs.workflow_stage == "security_subquest"
    assert security_obs.allowed_actions == [
        "inspect_code",
        "classify_vulnerability",
        "apply_patch",
        "verify_security_fix",
        "submit_security_fix",
    ]
    assert security_obs.required_fields_by_action["apply_patch"] == ["patch_id"]

    inspect_obs = env.step(UnifiedIncidentAction(action_type="inspect_code"))
    classify_obs = env.step(
        UnifiedIncidentAction(
            action_type="classify_vulnerability",
            vulnerability_type="sql_injection",
        )
    )
    patch_obs = env.step(
        UnifiedIncidentAction(
            action_type="apply_patch",
            patch_id="parameterized_query",
        )
    )
    verify_obs = env.step(UnifiedIncidentAction(action_type="verify_security_fix"))
    assert inspect_obs.workflow_stage == "security_subquest"
    assert classify_obs.workflow_stage == "security_subquest"
    assert patch_obs.workflow_stage == "security_subquest"
    assert verify_obs.workflow_stage == "verification"
    assert "submit_security_fix" in verify_obs.allowed_actions
    assert verify_obs.valid_action_example == {"action_type": "submit_security_fix"}


def test_loop_warning_emits_after_repeated_no_progress_actions() -> None:
    env = UnifiedIncidentEnvironment()
    env.reset(scenario_id="database_sqli_outage")
    first = env.step(
        UnifiedIncidentAction(action_type="restart_service", service="api-gateway")
    )
    assert first.loop_warning is None
    second = env.step(
        UnifiedIncidentAction(action_type="restart_service", service="api-gateway")
    )
    assert second.loop_warning is not None
    assert second.failure_type in {"trap_action", "repeated_no_progress_action"}
    assert second.why_failed is not None


def test_observation_exposes_blocked_until_security_complete() -> None:
    env = UnifiedIncidentEnvironment()
    env.reset(scenario_id="database_sqli_outage")
    obs = env.step(
        UnifiedIncidentAction(action_type="restart_service", service="database")
    )
    assert obs.blocked_until_security_complete is True
    assert obs.failure_type == "infra_before_security"
    assert obs.best_recovery_action_family == "submit_security_fix"


def test_public_action_schema_is_unchanged() -> None:
    assert set(get_args(ActionType)) == {
        "query_logs",
        "query_metrics",
        "query_dependencies",
        "restart_service",
        "rollback_deploy",
        "inspect_code",
        "classify_vulnerability",
        "apply_patch",
        "verify_security_fix",
        "submit_security_fix",
        "submit_postmortem",
    }


def test_security_incomplete_caps_score_at_point_five() -> None:
    grader = UnifiedIncidentGrader()
    breakdown = grader.compute_breakdown(
        {
            "relevant_investigations": 3,
            "correct_infra_steps": 3,
            "infra_restored_in_correct_order": True,
            "incident_resolved": True,
            "selected_vulnerability": "command_injection",
            "selected_patch": "avoid_shell",
            "exploit_blocked": True,
            "security_fix_submitted": False,
            "security_subquest_status": "active",
            "wasteful_ticks": 0,
            "score_breakdown": {"postmortem_score": 0.10},
        },
        {
            "security": {
                "correct_vulnerability": "command_injection",
                "correct_patch": "avoid_shell",
            }
        },
    )
    assert breakdown["final_score"] == 0.5


def test_postmortem_scoring_is_deterministic() -> None:
    grader = UnifiedIncidentGrader()
    score = grader.postmortem_score(
        _postmortem_for("database_sqli_outage"),
        {
            "postmortem_keywords": {
                "root_cause": ["sql injection", "database"],
                "attack_vector": ["unsanitized sql", "login", "input"],
                "remediation": ["parameterized query", "restart database"],
                "prevention": ["parameterized queries", "db abuse alerting"],
            }
        },
    )
    assert score == 0.10


def test_http_routes() -> None:
    payload = tasks_endpoint().model_dump()
    assert payload["environment"] == "unified_incident_env"
    assert {item["id"] for item in payload["scenarios"]} == {
        "database_sqli_outage",
        "cache_abuse_broken_access_control",
        "worker_bad_deploy_command_injection",
    }

    baseline_payload = baseline_endpoint().model_dump()
    assert len(baseline_payload["baselines"]) == 3

    grader_payload = grader_endpoint().model_dump()
    assert "score" in grader_payload

    status_payload = status_endpoint().model_dump()
    assert "progress" in status_payload
    assert "grader" in status_payload

    health_payload = health_endpoint()
    assert health_payload["status"] == "ok"
    assert health_payload["environment"] == "unified_incident_env"


def test_web_step_accepts_raw_action_payload(monkeypatch) -> None:
    monkeypatch.setenv("ENABLE_WEB_INTERFACE", "true")
    client = TestClient(app_module.create_compatible_app())
    reset_response = client.post("/web/reset", json={})
    assert reset_response.status_code == 200

    step_response = client.post(
        "/web/step",
        json={"action_type": "query_logs", "service": "database"},
    )
    assert step_response.status_code == 200
    payload = step_response.json()
    assert payload["reward"] == 0.05
    assert payload["observation"]["workflow_stage"] == "security_subquest"
