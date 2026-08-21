import copy
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from policy import decide  # noqa: E402

SHA = "a" * 40


def sorted_result(result):
    return {"decision": result["decision"], "violations": sorted(result["violations"])}


def base_safe_preview():
    return {
        "target": "preview",
        "event": "pull_request",
        "ref": "refs/heads/feature-x",
        "workflow": {
            "trigger": "pull_request",
            "permissions": {"contents": "read", "packages": "write", "id-token": "none"},
            "testsPassed": True,
            "matrixComplete": True,
            "failFast": False,
            "actions": [
                {"owner": "actions", "name": "checkout", "ref": "v4"},
                {"owner": "someorg", "name": "cool-action", "ref": SHA},
            ],
        },
        "image": {
            "multiStage": True,
            "runsAsRoot": False,
            "secretMode": "buildkit",
            "criticalVulnerabilities": 0,
            "digestPinned": True,
        },
    }


def base_safe_production():
    body = copy.deepcopy(base_safe_preview())
    body["target"] = "production"
    body["event"] = "push"
    body["ref"] = "refs/heads/main"
    body["workflow"]["trigger"] = "push"
    body["workflow"]["environmentApproval"] = True
    return body


class ReleaseGatePolicyTests(unittest.TestCase):
    def test_safe_preview_promotes(self):
        self.assertEqual(
            sorted_result(decide(base_safe_preview())),
            {"decision": "promote", "violations": []},
        )

    def test_safe_production_promotes(self):
        self.assertEqual(
            sorted_result(decide(base_safe_production())),
            {"decision": "promote", "violations": []},
        )

    def test_excess_permission_extra_scope(self):
        body = base_safe_preview()
        body["workflow"]["permissions"] = {
            "contents": "read",
            "packages": "write",
            "id-token": "none",
            "actions": "write",
        }
        self.assertEqual(
            sorted_result(decide(body)),
            {"decision": "block", "violations": ["EXCESS_PERMISSION"]},
        )

    def test_excess_permission_wrong_value(self):
        body = base_safe_preview()
        body["workflow"]["permissions"]["id-token"] = "write"
        self.assertEqual(
            sorted_result(decide(body)),
            {"decision": "block", "violations": ["EXCESS_PERMISSION"]},
        )

    def test_excess_permission_missing_scope(self):
        body = base_safe_preview()
        del body["workflow"]["permissions"]["id-token"]
        self.assertEqual(
            sorted_result(decide(body)),
            {"decision": "block", "violations": ["EXCESS_PERMISSION"]},
        )

    def test_unsafe_pr_trigger(self):
        body = base_safe_preview()
        body["workflow"]["trigger"] = "pull_request_target"
        self.assertEqual(
            sorted_result(decide(body)),
            {"decision": "block", "violations": ["UNSAFE_PR_TRIGGER"]},
        )

    def test_tests_incomplete_matrix(self):
        body = base_safe_preview()
        body["workflow"]["matrixComplete"] = False
        self.assertEqual(
            sorted_result(decide(body)),
            {"decision": "block", "violations": ["TESTS_INCOMPLETE"]},
        )

    def test_tests_incomplete_failfast(self):
        body = base_safe_preview()
        body["workflow"]["failFast"] = True
        self.assertEqual(
            sorted_result(decide(body)),
            {"decision": "block", "violations": ["TESTS_INCOMPLETE"]},
        )

    def test_tests_incomplete_not_passed(self):
        body = base_safe_preview()
        body["workflow"]["testsPassed"] = False
        self.assertEqual(
            sorted_result(decide(body)),
            {"decision": "block", "violations": ["TESTS_INCOMPLETE"]},
        )

    def test_mutable_third_party_action_tag(self):
        body = base_safe_preview()
        body["workflow"]["actions"] = [
            {"owner": "actions", "name": "checkout", "ref": "v4"},
            {"owner": "someorg", "name": "cool-action", "ref": "v1.2.3"},
        ]
        self.assertEqual(
            sorted_result(decide(body)),
            {"decision": "block", "violations": ["MUTABLE_ACTION"]},
        )

    def test_mutable_action_uppercase_sha_rejected(self):
        body = base_safe_preview()
        body["workflow"]["actions"] = [{"owner": "someorg", "name": "x", "ref": SHA.upper()}]
        self.assertEqual(
            sorted_result(decide(body)),
            {"decision": "block", "violations": ["MUTABLE_ACTION"]},
        )

    def test_actions_owner_tag_allowed(self):
        body = base_safe_preview()
        body["workflow"]["actions"] = [{"owner": "actions", "name": "setup-node", "ref": "v4"}]
        self.assertEqual(
            sorted_result(decide(body)),
            {"decision": "promote", "violations": []},
        )

    def test_single_stage_image(self):
        body = base_safe_preview()
        body["image"]["multiStage"] = False
        self.assertEqual(
            sorted_result(decide(body)),
            {"decision": "block", "violations": ["SINGLE_STAGE_IMAGE"]},
        )

    def test_root_runtime(self):
        body = base_safe_preview()
        body["image"]["runsAsRoot"] = True
        self.assertEqual(
            sorted_result(decide(body)),
            {"decision": "block", "violations": ["ROOT_RUNTIME"]},
        )

    def test_secret_in_layer_arg(self):
        body = base_safe_preview()
        body["image"]["secretMode"] = "arg"
        self.assertEqual(
            sorted_result(decide(body)),
            {"decision": "block", "violations": ["SECRET_IN_LAYER"]},
        )

    def test_secret_in_layer_copy(self):
        body = base_safe_preview()
        body["image"]["secretMode"] = "copy"
        self.assertEqual(
            sorted_result(decide(body)),
            {"decision": "block", "violations": ["SECRET_IN_LAYER"]},
        )

    def test_critical_cve(self):
        body = base_safe_preview()
        body["image"]["criticalVulnerabilities"] = 2
        self.assertEqual(
            sorted_result(decide(body)),
            {"decision": "block", "violations": ["CRITICAL_CVE"]},
        )

    def test_unpinned_image(self):
        body = base_safe_preview()
        body["image"]["digestPinned"] = False
        self.assertEqual(
            sorted_result(decide(body)),
            {"decision": "block", "violations": ["UNPINNED_IMAGE"]},
        )

    def test_invalid_production_ref_branch(self):
        body = base_safe_production()
        body["ref"] = "refs/heads/release"
        self.assertEqual(
            sorted_result(decide(body)),
            {"decision": "block", "violations": ["INVALID_PRODUCTION_REF"]},
        )

    def test_invalid_production_ref_event(self):
        body = base_safe_production()
        body["event"] = "pull_request"
        body["ref"] = "refs/heads/main"
        self.assertEqual(
            sorted_result(decide(body)),
            {"decision": "block", "violations": ["INVALID_PRODUCTION_REF"]},
        )

    def test_approval_required_false(self):
        body = base_safe_production()
        body["workflow"]["environmentApproval"] = False
        self.assertEqual(
            sorted_result(decide(body)),
            {"decision": "block", "violations": ["APPROVAL_REQUIRED"]},
        )

    def test_approval_required_missing(self):
        body = base_safe_production()
        del body["workflow"]["environmentApproval"]
        self.assertEqual(
            sorted_result(decide(body)),
            {"decision": "block", "violations": ["APPROVAL_REQUIRED"]},
        )

    def test_kitchen_sink_multi_failure(self):
        body = base_safe_production()
        body["workflow"]["permissions"] = {
            "contents": "write",
            "packages": "write",
            "id-token": "none",
        }
        body["workflow"]["trigger"] = "pull_request_target"
        body["workflow"]["testsPassed"] = False
        body["workflow"]["actions"] = [{"owner": "thirdparty", "name": "action", "ref": "main"}]
        body["image"]["multiStage"] = False
        body["image"]["runsAsRoot"] = True
        body["image"]["secretMode"] = "copy"
        body["image"]["criticalVulnerabilities"] = 1
        body["image"]["digestPinned"] = False
        body["ref"] = "refs/heads/develop"
        body["workflow"]["environmentApproval"] = False

        expected = sorted(
            [
                "APPROVAL_REQUIRED",
                "CRITICAL_CVE",
                "EXCESS_PERMISSION",
                "INVALID_PRODUCTION_REF",
                "MUTABLE_ACTION",
                "ROOT_RUNTIME",
                "SECRET_IN_LAYER",
                "SINGLE_STAGE_IMAGE",
                "TESTS_INCOMPLETE",
                "UNPINNED_IMAGE",
                "UNSAFE_PR_TRIGGER",
            ]
        )
        self.assertEqual(
            sorted_result(decide(body)),
            {"decision": "block", "violations": expected},
        )


if __name__ == "__main__":
    unittest.main()
