"""Tests for harnessing/3-audit/pqc-readiness/scripts/l2_prepass.py routing."""

import unittest

from l2_prepass import route_repo


def _facts(rules=(), fips=0, fp=1):
    fl = [{"rule_id": r, "path_class": "first_party"} for r in rules]
    fl += [
        {"rule_id": "API_GO_CRYPTO_RSA", "path_class": "first_party", "fips_mode": True}
        for _ in range(fips)
    ]
    fl += [
        {"rule_id": "API_GO_CRYPTO_RSA", "path_class": "first_party"}
        for _ in range(max(0, fp - len(fl)))
    ]
    return {"facts": fl}


def _readiness(bucket="partial", clock=False, hndl=False):
    return {
        "readiness_bucket": bucket,
        "flags": {"has_2030_clock_items": clock, "hndl_priority": hndl},
    }


class TestRouting(unittest.TestCase):
    def test_gov_facts_route_full(self):
        tier, hints = route_repo(_facts(rules=["HP_GOV_PLATFORM_OCP_LIBGO"]), _readiness())
        self.assertEqual(tier, "full")
        self.assertEqual(hints["gov_rules"], ["HP_GOV_PLATFORM_OCP_LIBGO"])

    def test_db_and_fips_route_full(self):
        self.assertEqual(route_repo(_facts(rules=["HP_DB_CLIENT_TLS"]), _readiness())[0], "full")
        self.assertEqual(route_repo(_facts(fips=1), _readiness())[0], "full")

    def test_high_stakes_flags_route_full(self):
        for kw in (
            {"clock": True},
            {"hndl": True},
            {"bucket": "not-ready"},
            {"bucket": "blocked-external"},
        ):
            self.assertEqual(route_repo(_facts(), _readiness(**kw))[0], "full", kw)

    def test_plain_scored_repo_routes_light(self):
        self.assertEqual(route_repo(_facts(), _readiness())[0], "light")

    def test_zero_hit_na_and_vendor_only_skip(self):
        self.assertEqual(route_repo({"facts": []}, _readiness(bucket="not-applicable"))[0], "skip")
        vendor_only = {"facts": [{"rule_id": "API_GO_CRYPTO_RSA", "path_class": "vendor"}]}
        self.assertEqual(route_repo(vendor_only, _readiness())[0], "skip")

    def test_unscored_when_no_readiness(self):
        self.assertEqual(route_repo(_facts(), None)[0], "unscored")


if __name__ == "__main__":
    unittest.main()
