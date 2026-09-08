import importlib.util
from pathlib import Path

_SPEC = importlib.util.spec_from_file_location(
    "build_iac_inventory",
    Path(__file__).resolve().parents[1] / "src" / "traust" / "ops" / "build_iac_inventory.py",
)
bii = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(bii)


def test_classify_terraform_and_sca_covered():
    cls = bii.classify_paths(
        [
            "infra/main.tf",
            "infra/vars.tfvars",
            "deploy/Chart.yaml",
            "Dockerfile",
            "src/main.go",
        ]
    )
    assert cls["terraform"] == 2
    assert cls["iac_hit"] is True
    assert cls["helm_chart"] == 1 and cls["dockerfile"] == 1
    assert cls["samples"]["terraform"] == "infra/main.tf"


def test_sca_covered_alone_does_not_trigger_lane():
    cls = bii.classify_paths(["Chart.yaml", "Dockerfile.ubi", "a.go"])
    assert cls["iac_hit"] is False


def test_cloudformation_dir_based_only():
    cls = bii.classify_paths(
        [
            "cloudformation/stack.yaml",
            "cfn/net.json",
            "app.template.json",  # suffix rule dropped
            "openshift/backend.template.yaml",  # OpenShift Template != CFN
            "deploy/azuredeploy.parameters.json",
            "modules/net.bicep",
        ]
    )
    assert cls["cloudformation"] == 2
    assert cls["arm_bicep"] == 2


def test_priority_order_exposure_then_services_then_tier():
    rows = [
        {
            "exposure": "private-internal",
            "services_segment": False,
            "tier": "P0",
            "live_crit_high": 9,
        },
        {
            "exposure": "public-external",
            "services_segment": False,
            "tier": "P2",
            "live_crit_high": 0,
        },
        {
            "exposure": "public-external",
            "services_segment": True,
            "tier": "P2",
            "live_crit_high": 0,
        },
    ]
    rows.sort(key=bii.priority_key)
    assert rows[0]["services_segment"] is True
    assert rows[-1]["exposure"] == "private-internal"


def test_tier_simplification():
    assert bii.risk_tier(5) == "P0"
    assert bii.risk_tier(1) == "P1"
    assert bii.risk_tier(0) == "P2"
