"""Fully deterministic grading for the final preset pack."""

from __future__ import annotations

from typing import Any

from ..models import GraderCheck, GraderReport, PostmortemPayload

MIN_PUBLIC_SCORE = 0.01
MAX_PUBLIC_SCORE = 0.99


def _contains_all(text: str, phrases: list[str]) -> bool:
    lowered = text.lower()
    return all(phrase.lower() in lowered for phrase in phrases)


def _contains_any(text: str, phrases: list[str]) -> bool:
    lowered = text.lower()
    return any(phrase.lower() in lowered for phrase in phrases)


def _strict_public_score(score: float) -> float:
    return round(min(MAX_PUBLIC_SCORE, max(MIN_PUBLIC_SCORE, score)), 4)


class DeterministicPostmortemScorer:
    """Deterministic postmortem scorer with the final rubric."""

    def score(
        self,
        postmortem: PostmortemPayload,
        scenario: dict[str, Any],
    ) -> float:
        keywords = scenario["postmortem_keywords"]
        total = 0.0
        root_text = postmortem.root_cause.strip().lower()
        attack_text = postmortem.attack_vector.strip().lower()
        remediation_text = " ".join(
            list(postmortem.timeline) + list(postmortem.remediation_steps)
        ).lower()
        prevention_text = " ".join(postmortem.prevention_steps).lower()

        if root_text and _contains_all(root_text, keywords["root_cause"]):
            total += 0.03
        if attack_text and _contains_any(attack_text, keywords["attack_vector"]):
            total += 0.02
        if remediation_text and _contains_all(remediation_text, keywords["remediation"]):
            total += 0.03
        if prevention_text and _contains_any(prevention_text, keywords["prevention"]):
            total += 0.02
        return round(min(0.10, total), 4)


class UnifiedIncidentGrader:
    """Deterministic final scorer for the unified preset benchmark."""

    def __init__(self) -> None:
        self._postmortem = DeterministicPostmortemScorer()

    def postmortem_score(
        self,
        postmortem: PostmortemPayload,
        scenario: dict[str, Any],
    ) -> float:
        return self._postmortem.score(postmortem, scenario)

    def compute_breakdown(
        self,
        state: dict[str, Any],
        scenario: dict[str, Any],
    ) -> dict[str, float]:
        infrastructure_score = min(
            0.45,
            round(
                (0.05 * int(state.get("relevant_investigations", 0)))
                + (0.10 * int(state.get("correct_infra_steps", 0)))
                + (0.15 if state.get("infra_restored_in_correct_order", False) else 0.0)
                + (0.15 if state.get("incident_resolved", False) else 0.0),
                4,
            ),
        )

        security_score = 0.0
        if state.get("selected_vulnerability") == scenario["security"]["correct_vulnerability"]:
            security_score += 0.10
        if state.get("selected_patch") == scenario["security"]["correct_patch"]:
            security_score += 0.10
        if state.get("exploit_blocked") is True:
            security_score += 0.10
        if state.get("security_fix_submitted") is True:
            security_score += 0.05
        security_score = round(min(0.35, security_score), 4)

        efficiency_score = round(
            max(0.0, 0.10 - (0.01 * int(state.get("wasteful_ticks", 0)))),
            4,
        )

        postmortem_score = round(
            float(state.get("score_breakdown", {}).get("postmortem_score", 0.0)),
            4,
        )

        final_score = round(
            max(
                0.0,
                min(
                    1.0,
                    infrastructure_score
                    + security_score
                    + efficiency_score
                    + postmortem_score,
                ),
            ),
            4,
        )
        if state.get("security_subquest_status") != "completed":
            final_score = min(final_score, 0.5)
        final_score = _strict_public_score(final_score)

        return {
            "infrastructure_score": round(infrastructure_score, 4),
            "security_score": round(security_score, 4),
            "efficiency_score": round(efficiency_score, 4),
            "postmortem_score": round(postmortem_score, 4),
            "final_score": round(final_score, 4),
        }

    def build_report(self, state: dict[str, Any], scenario: dict[str, Any]) -> GraderReport:
        breakdown = self.compute_breakdown(state, scenario)
        checks = [
            GraderCheck(
                name="security_subquest_completed",
                passed=state.get("security_subquest_status") == "completed",
                detail=(
                    "Security subquest completed."
                    if state.get("security_subquest_status") == "completed"
                    else "Security subquest is incomplete."
                ),
                weight=0.35,
            ),
            GraderCheck(
                name="incident_resolved",
                passed=bool(state.get("incident_resolved")),
                detail=(
                    "All required services are healthy."
                    if state.get("incident_resolved")
                    else "Required services are not fully healthy."
                ),
                weight=0.30,
            ),
            GraderCheck(
                name="investigation_performed",
                passed=int(state.get("relevant_investigations", 0)) > 0,
                detail=(
                    "Relevant investigation was performed."
                    if int(state.get("relevant_investigations", 0)) > 0
                    else "No relevant investigation evidence was collected."
                ),
                weight=0.15,
            ),
            GraderCheck(
                name="postmortem_submitted",
                passed=bool(state.get("postmortem_submitted")),
                detail=(
                    "Postmortem submitted."
                    if state.get("postmortem_submitted")
                    else "Postmortem not submitted."
                ),
                weight=0.10,
            ),
            GraderCheck(
                name="efficiency_positive",
                passed=breakdown["efficiency_score"] > 0.0,
                detail=(
                    "Efficiency score remains positive."
                    if breakdown["efficiency_score"] > 0.0
                    else "Efficiency score fell to zero."
                ),
                weight=0.10,
            ),
        ]
        passed = bool(
            state.get("incident_resolved")
            and state.get("security_subquest_status") == "completed"
            and state.get("postmortem_submitted")
        )
        message = (
            "Unified incident resolved successfully."
            if passed
            else "Unified incident is not fully complete."
        )
        return GraderReport(
            scenario_id=scenario["id"],
            passed=passed,
            score=breakdown["final_score"],
            message=message,
            breakdown=breakdown,
            checks=checks,
        )
