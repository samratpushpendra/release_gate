"""Deterministic release-gate policy logic.

Pure functions only -- no I/O -- so the decision logic is easy to unit test
independently of the HTTP layer.
"""

import re

SHA40 = re.compile(r"^[0-9a-f]{40}$")

REQUIRED_PERMISSIONS = {
    "contents": "read",
    "packages": "write",
    "id-token": "none",
}


def _check_permissions_violated(permissions):
    """Return True if permissions are NOT exactly least-privilege."""
    if not isinstance(permissions, dict):
        return True

    # No additional scopes may be present, and no scope may be missing.
    if set(permissions.keys()) != set(REQUIRED_PERMISSIONS.keys()):
        return True

    for key, expected in REQUIRED_PERMISSIONS.items():
        if permissions.get(key) != expected:
            return True

    return False


def _check_action_mutable(action):
    """Return True if this single action is NOT properly pinned."""
    if not isinstance(action, dict):
        return True

    owner = action.get("owner")
    ref = action.get("ref")

    if owner == "actions":
        # actions/* may use a version tag -- any non-empty string ref is fine.
        return not (isinstance(ref, str) and len(ref) > 0)

    # Third-party action: must be pinned to a full 40-char lowercase hex SHA.
    return not (isinstance(ref, str) and bool(SHA40.match(ref)))


def evaluate(body):
    """Evaluate a release-gate request body, returning a list of violation codes."""
    body = body or {}
    target = body.get("target")
    event = body.get("event")
    ref = body.get("ref")
    workflow = body.get("workflow") or {}
    image = body.get("image") or {}

    violations = []

    # --- Permissions: exact least privilege ---
    if _check_permissions_violated(workflow.get("permissions")):
        violations.append("EXCESS_PERMISSION")

    # --- PR trigger safety ---
    if workflow.get("trigger") == "pull_request_target":
        violations.append("UNSAFE_PR_TRIGGER")

    # --- Testing completeness ---
    tests_ok = (
        workflow.get("testsPassed") is True
        and workflow.get("matrixComplete") is True
        and workflow.get("failFast") is False
    )
    if not tests_ok:
        violations.append("TESTS_INCOMPLETE")

    # --- Action pinning ---
    actions = workflow.get("actions")
    actions = actions if isinstance(actions, list) else []
    if any(_check_action_mutable(a) for a in actions):
        violations.append("MUTABLE_ACTION")

    # --- Image hardening ---
    if image.get("multiStage") is not True:
        violations.append("SINGLE_STAGE_IMAGE")

    if image.get("runsAsRoot") is not False:
        violations.append("ROOT_RUNTIME")

    if image.get("secretMode") not in ("none", "buildkit"):
        violations.append("SECRET_IN_LAYER")

    if image.get("criticalVulnerabilities") != 0:
        violations.append("CRITICAL_CVE")

    if image.get("digestPinned") is not True:
        violations.append("UNPINNED_IMAGE")

    # --- Production-only requirements ---
    if target == "production":
        if not (event == "push" and ref == "refs/heads/main"):
            violations.append("INVALID_PRODUCTION_REF")
        if workflow.get("environmentApproval") is not True:
            violations.append("APPROVAL_REQUIRED")

    return violations


def decide(body):
    violations = evaluate(body)
    return {
        "decision": "promote" if not violations else "block",
        "violations": violations,
    }
