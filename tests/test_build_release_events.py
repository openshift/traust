"""Tests for harnessing/2-threat-model/threat-model/scripts/build_release_events.py — the release/dist-git
event feeders. No network: git ls-remote is monkeypatched throughout;
the container leg is pure CSV diffing by design (v1 has no registry
polling)."""

import json
from pathlib import Path

import build_release_events as bre
import pytest

from traust.cli import build_rescan_worklist as rw

# ---------------------------------------------------------------------------
# fixtures
# ---------------------------------------------------------------------------

PAYLOAD_HEADER = (
    "GitHub Repository,GitHub URL,Organization,Repo Name,"
    "Source Branch,Category,ClusterOperator(s),"
    "Payload Image(s),Image Count\n"
)
CATALOG_HEADER = (
    "GitHub Repository,GitHub URL,Organization,Repo Name,"
    "Branch,Category,Payload Image Key(s),Image Count\n"
)

PULLSPEC = (
    "registry.redhat.io/openshift4/ose-coredns-rhel9@sha256:"
    "1c67ef212402d8c10bafd9549b3faac5e6b87ce684bc5a9089243fdf"
    "55d050d9"
)


def _mk_inputs(tmp_path):
    """A miniature inputs-inventory tree with both CSV shapes."""
    root = tmp_path / "inputs"
    (root / "openshift").mkdir(parents=True)
    (root / "openshift" / "openshift-4.19-payload-repos.csv").write_text(
        PAYLOAD_HEADER + "openshift/api,https://github.com/openshift/api,openshift,"
        "api,release-4.19,ClusterOperator,config-operator,"
        "cluster-config-api,1\n"
    )
    cat = root / "operator-catalog" / "some-operator" / "1.2.3"
    cat.mkdir(parents=True)
    (cat / "some-operator-1.2.3-payload-repos.csv").write_text(
        CATALOG_HEADER + f"openshift/coredns,https://github.com/openshift/coredns,"
        f"openshift,coredns,commit:b6048bb02c11,RHEL Base Images,"
        f"{PULLSPEC},1\n" + "N/A (RHEL Base Image),N/A (RHEL Base Image),,,N/A,"
        "RHEL Base Images,system_memcached; zync_postgresql,2\n"
    )
    return root


def _mk_config(tmp_path, urls):
    cfg = tmp_path / "rpm-distgit-watch.yaml"
    cfg.write_text("active:\n" + "".join(f"  - {u}\n" for u in urls) if urls else "active: []\n")
    return cfg


def _run(tmp_path, inputs, config=None, extra=None):
    events = tmp_path / "rescan-events.jsonl"
    state = tmp_path / "release-events-state.json"
    config = config or _mk_config(tmp_path, [])
    rc = bre.main(
        [
            "--inputs",
            str(inputs),
            "--events",
            str(events),
            "--state",
            str(state),
            "--config",
            str(config),
        ]
        + (extra or [])
    )
    assert rc == 0
    return events, state


# ---------------------------------------------------------------------------
# container leg — CSV parsing and diffing (pure)
# ---------------------------------------------------------------------------


class TestParseInventory:
    def test_both_csv_shapes_and_na_rows(self, tmp_path):
        root = _mk_inputs(tmp_path)
        items = []
        for p in bre.inventory_csvs(root):
            items.extend(bre.parse_inventory_csv(p, root))
        by_image = {it["image"]: it for it in items}
        # payload shape (`Payload Image(s)`) — bare key, repo mapped
        assert by_image["cluster-config-api"]["repo"] == "https://github.com/openshift/api"
        # catalog shape (`Payload Image Key(s)`) — full pullspec
        assert by_image[PULLSPEC]["repo"] == "https://github.com/openshift/coredns"
        # `;`-split, N/A repo rows keep images with repo ""
        assert by_image["system_memcached"]["repo"] == ""
        assert by_image["zync_postgresql"]["repo"] == ""

    def test_key_identity_pullspec_vs_bare(self, tmp_path):
        root = _mk_inputs(tmp_path)
        items = []
        for p in bre.inventory_csvs(root):
            items.extend(bre.parse_inventory_csv(p, root))
        by_image = {it["image"]: it for it in items}
        # digest-qualified pullspec: globally unique on its own
        assert by_image[PULLSPEC]["key"] == PULLSPEC
        # bare key: scoped to its inventory file
        assert by_image["cluster-config-api"]["key"] == (
            "openshift/openshift-4.19-payload-repos.csv::cluster-config-api"
        )

    def test_pullspec_detector(self):
        assert bre.looks_like_pullspec(PULLSPEC)
        assert bre.looks_like_pullspec("quay.io/org/img:v1.2.3")
        assert not bre.looks_like_pullspec("manager")
        assert not bre.looks_like_pullspec("some/path-no-tag")

    def test_diff_dedupes_and_orders(self):
        items = [
            {"key": "b", "image": "b", "repo": "", "inventory": "i"},
            {"key": "a", "image": "a", "repo": "", "inventory": "i"},
            {"key": "b", "image": "b", "repo": "", "inventory": "i"},
            {"key": "c", "image": "c", "repo": "", "inventory": "i"},
        ]
        new = bre.diff_container(items, {"c"})
        assert [it["key"] for it in new] == ["a", "b"]


# ---------------------------------------------------------------------------
# state round-trip
# ---------------------------------------------------------------------------


class TestState:
    def test_round_trip(self, tmp_path):
        p = tmp_path / "state.json"
        bre.save_state(p, {"k2", "k1"}, {"u": "a" * 40})
        st = bre.load_state(p)
        assert st == {
            "container_seen": {"k1", "k2"},
            "distgit_heads": {"u": "a" * 40},
            # release identity (2026-08-05): saved with no
            # marks, so the seen-set round-trips unchanged
            # and the migration flag reads false
            "inventory_versions": {},
            "had_versions": False,
        }

    def test_absent_is_none(self, tmp_path):
        assert bre.load_state(tmp_path / "nope.json") is None

    def test_corrupt_state_refuses(self, tmp_path):
        p = tmp_path / "state.json"
        p.write_text("{not json")
        with pytest.raises(SystemExit):
            bre.load_state(p)


# ---------------------------------------------------------------------------
# dist-git leg — URL gating and S3 discipline
# ---------------------------------------------------------------------------


class TestDistgitHead:
    def test_non_https_rejected_without_network(self, monkeypatch):
        def boom(*a, **k):  # pragma: no cover - must not be reached
            raise AssertionError("subprocess ran for a non-https URL")

        monkeypatch.setattr(bre.subprocess, "run", boom)
        for url in (
            "http://example.com/r.git",
            "git://host/r.git",
            "ssh://git@host/r.git",
            "file:///etc/passwd",
            "dir:/tmp/x",
        ):
            res = bre.distgit_head(url)
            assert not res["ok"]
            assert "non-https" in res["error"]

    def test_s3_argv_env_and_separator(self, monkeypatch):
        captured = {}

        def fake_run(argv, **kw):
            captured["argv"] = argv
            captured["env"] = kw.get("env") or {}

            class P:
                returncode = 0
                stdout = "b" * 40 + "\tHEAD\n"
                stderr = ""

            return P()

        monkeypatch.setattr(bre.subprocess, "run", fake_run)
        res = bre.distgit_head("https://gitlab.com/redhat/centos-stream/rpms/openssl.git")
        assert res == {"ok": True, "head": "b" * 40}
        argv = captured["argv"]
        assert isinstance(argv, list)  # S4: argv list
        assert argv[:3] == ["git", "ls-remote", "--"]  # S3: separator
        assert captured["env"]["GIT_ALLOW_PROTOCOL"] == "https"

    def test_failure_degrades(self, monkeypatch):
        def fake_run(argv, **kw):
            class P:
                returncode = 128
                stdout = ""
                stderr = "fatal: could not resolve host"

            return P()

        monkeypatch.setattr(bre.subprocess, "run", fake_run)
        res = bre.distgit_head("https://gitlab.com/x/y.git")
        assert not res["ok"] and "resolve" in res["error"]


# ---------------------------------------------------------------------------
# end to end — seeding, idempotency, event shape, dry-run
# ---------------------------------------------------------------------------


class TestEndToEnd:
    def test_first_run_seeds_and_emits_nothing(self, tmp_path):
        root = _mk_inputs(tmp_path)
        events, state = _run(tmp_path, root)
        assert not events.is_file() or events.read_text() == ""
        st = bre.load_state(state)
        assert PULLSPEC in st["container_seen"]

    def test_second_run_idempotent(self, tmp_path):
        root = _mk_inputs(tmp_path)
        _run(tmp_path, root)
        events, _ = _run(tmp_path, root)
        assert not events.is_file() or events.read_text() == ""

    def test_new_digest_emits_router_shaped_event(self, tmp_path):
        root = _mk_inputs(tmp_path)
        _run(tmp_path, root)  # seed
        # inventory refresh lands a new digest for coredns
        new_spec = PULLSPEC.replace("1c67ef", "aaaaaa")
        cat = root / "operator-catalog" / "some-operator" / "1.2.4"
        cat.mkdir(parents=True)
        (cat / "some-operator-1.2.4-payload-repos.csv").write_text(
            CATALOG_HEADER + f"openshift/coredns,https://github.com/openshift/coredns,"
            f"openshift,coredns,commit:b6048bb02c11,RHEL Base Images,"
            f"{new_spec},1\n"
        )
        events, _state = _run(tmp_path, root)
        # exactly one event: the pullspec is new, the version-scoped
        # bare keys did not reappear
        loaded = rw.load_events(events)  # ROUND-TRIP the router
        assert len(loaded) == 1
        ev = loaded[0]
        assert ev["source"] == "release"
        assert ev["repo"] == "https://github.com/openshift/coredns"
        assert new_spec in ev["note"]
        assert rw.event_lane(ev["source"], None) == "release-passthrough"
        # third run: nothing new
        events, _ = _run(tmp_path, root)
        assert len(rw.load_events(events)) == 1

    def test_distgit_head_move_emits_event(self, tmp_path, monkeypatch):
        root = _mk_inputs(tmp_path)
        url = "https://gitlab.com/redhat/centos-stream/rpms/openssl.git"
        cfg = _mk_config(tmp_path, [url])
        heads = {"h": "a" * 40}
        monkeypatch.setattr(
            bre, "distgit_head", lambda u, timeout=60: {"ok": True, "head": heads["h"]}
        )
        _run(tmp_path, root, config=cfg)  # seed: records HEAD
        st = bre.load_state(tmp_path / "release-events-state.json")
        assert st["distgit_heads"][url] == "a" * 40

        heads["h"] = "b" * 40  # HEAD moves
        events, state = _run(tmp_path, root, config=cfg)
        loaded = rw.load_events(events)
        assert len(loaded) == 1
        ev = loaded[0]
        assert ev["source"] == "release" and ev["repo"] == url
        assert "dist-git commit" in ev["note"]
        assert "secure-rpm-audit" in ev["note"]
        st = bre.load_state(state)
        assert st["distgit_heads"][url] == "b" * 40
        # unchanged HEAD: no further event
        events, _ = _run(tmp_path, root, config=cfg)
        assert len(rw.load_events(events)) == 1

    def test_distgit_failure_is_skip_not_crash(self, tmp_path, monkeypatch, capsys):
        root = _mk_inputs(tmp_path)
        url = "https://gitlab.com/redhat/centos-stream/rpms/openssl.git"
        cfg = _mk_config(tmp_path, [url])
        monkeypatch.setattr(
            bre, "distgit_head", lambda u, timeout=60: {"ok": False, "error": "i/o timeout"}
        )
        events, state = _run(tmp_path, root, config=cfg)
        assert not events.is_file() or events.read_text() == ""
        assert url not in bre.load_state(state)["distgit_heads"]
        assert "skipped" in capsys.readouterr().err

    def test_dry_run_writes_nothing(self, tmp_path):
        root = _mk_inputs(tmp_path)
        _run(tmp_path, root)  # seed
        new_spec = PULLSPEC.replace("1c67ef", "bbbbbb")
        cat = root / "operator-catalog" / "some-operator" / "1.2.5"
        cat.mkdir(parents=True)
        (cat / "some-operator-1.2.5-payload-repos.csv").write_text(
            CATALOG_HEADER + f"openshift/coredns,https://github.com/openshift/coredns,"
            f"openshift,coredns,commit:b6048bb02c11,RHEL Base Images,"
            f"{new_spec},1\n"
        )
        state_before = (tmp_path / "release-events-state.json").read_text()
        events, state = _run(tmp_path, root, extra=["--dry-run"])
        assert not events.is_file() or events.read_text() == ""
        assert state.read_text() == state_before  # state untouched

    def test_shipped_example_config_is_inert(self, tmp_path):
        """The committed example config has an empty active list."""
        cfg = Path(__file__).resolve().parents[1] / "config" / "rpm-distgit-watch.example.yaml"
        assert bre.load_watch_config(cfg) == []


# ---------------------------------------------------------------------------
# release identity (threat-model cadence Phase 2, 2026-08-05)
# ---------------------------------------------------------------------------


class TestParseInventoryVersion:
    def test_openshift_payload_path(self):
        fam, ver = bre.parse_inventory_version("openshift/openshift-4.19-payload-repos.csv")
        assert fam == "openshift/openshift-{V}-payload-repos.csv"
        assert ver == (4, 19, 0)

    def test_operator_catalog_path_normalizes_both_occurrences(self):
        fam, ver = bre.parse_inventory_version(
            "operator-catalog/rhacs-operator/4.9.2/rhacs-operator-4.9.2-payload-repos.csv"
        )
        assert "{V}" in fam and "4.9.2" not in fam
        assert ver == (4, 9, 2)

    def test_two_part_and_three_part_versions_are_comparable(self):
        _, a = bre.parse_inventory_version("x-4.19-payload-repos.csv")
        _, b = bre.parse_inventory_version("x-4.19.3-payload-repos.csv")
        assert a < b

    def test_minor_is_not_truncated(self):
        """`4.19` must not parse as 4.1 — otherwise 4.19 -> 4.2 reads
        as an upgrade and 4.9 -> 4.10 reads as a downgrade."""
        _, v = bre.parse_inventory_version("x-4.19-payload-repos.csv")
        assert v == (4, 19, 0)
        _, low = bre.parse_inventory_version("x-4.9-payload-repos.csv")
        assert low < v

    def test_unversioned_path(self):
        assert bre.parse_inventory_version("foo/bar-payload-repos.csv") is None


class TestClassifyBump:
    @pytest.mark.parametrize(
        "new,prev,want",
        [
            ((4, 20, 0), (4, 19, 0), "minor"),
            ((5, 0, 0), (4, 23, 0), "major"),
            ((4, 19, 3), (4, 19, 2), "patch"),
            ((4, 18, 0), (4, 19, 0), "backfill"),
            ((4, 19, 0), (4, 19, 0), "none"),
            ((4, 19, 0), None, "initial"),
        ],
    )
    def test_kinds(self, new, prev, want):
        assert bre.classify_bump(new, prev) == want

    def test_only_major_minor_remodel(self):
        assert bre.REMODEL_CHANGES == ("major", "minor")
        for kind in ("patch", "backfill", "initial", "none", "unknown"):
            assert kind not in bre.REMODEL_CHANGES


class TestReleaseIdentityOnEvents:
    def test_container_event_carries_structured_version(self):
        ev = bre.container_event(
            {
                "image": "img",
                "repo": "https://github.com/o/r",
                "inventory": "openshift/openshift-4.20-payload-repos.csv",
            },
            "2026-08-05",
            {"family": "f", "version": "4.20.0", "previous": "4.19.0", "change": "minor"},
        )
        assert ev["release_change"] == "minor"
        assert ev["release_version"] == "4.20.0"
        assert ev["release_previous"] == "4.19.0"
        assert "minor release 4.20.0" in ev["note"]

    def test_container_event_without_release_info_is_unknown(self):
        ev = bre.container_event({"image": "i", "repo": "", "inventory": "x.csv"}, "2026-08-05")
        assert ev["release_change"] == "unknown"
        assert ev["release_version"] is None

    def test_distgit_event_has_no_version_and_never_remodels(self):
        """A dist-git HEAD is a commit sha, not a release — stating the
        coverage limit rather than inventing a version."""
        ev = bre.distgit_event("https://x/y", "a" * 40, "b" * 40, "2026-08-05")
        assert ev["release_version"] is None
        assert ev["release_change"] == "unknown"
        assert ev["release_change"] not in bre.REMODEL_CHANGES

    def test_router_and_feeder_agree_on_the_remodel_set(self):
        assert tuple(bre.REMODEL_CHANGES) == tuple(rw.RELEASE_REMODEL_CHANGES)


class TestVersionMarks:
    def test_high_water_mark_advances_and_never_regresses(self):
        rel = {
            "a.csv": {"family": "f", "version": "4.20.0", "previous": None, "change": "initial"},
            "b.csv": {"family": "f", "version": "4.18.0", "previous": None, "change": "initial"},
        }
        marks = bre.advance_version_marks(rel, {"f": "4.19.0"})
        assert marks["f"] == "4.20.0"

    def test_unversioned_entries_are_ignored(self):
        rel = {"a.csv": {"family": None, "version": None, "previous": None, "change": "unknown"}}
        assert bre.advance_version_marks(rel, {"f": "1.0.0"}) == {"f": "1.0.0"}

    def test_release_map_classifies_against_committed_marks(self, tmp_path):
        root = tmp_path
        p = root / "openshift" / "openshift-4.20-payload-repos.csv"
        p.parent.mkdir(parents=True)
        p.write_text("x")
        rel = bre.inventory_release_map(
            [p], root, {"openshift/openshift-{V}-payload-repos.csv": "4.19.0"}
        )
        info = rel["openshift/openshift-4.20-payload-repos.csv"]
        assert info["change"] == "minor" and info["previous"] == "4.19.0"


class TestStateVersionMigration:
    def test_pre_existing_state_without_versions_reads_as_empty(self, tmp_path):
        """State files predating the release-identity change must load,
        seed their marks, and not crash or re-emit the inventory."""
        p = tmp_path / "state.json"
        p.write_text(json.dumps({"container_seen": ["k1"], "distgit_heads": {"u": "a" * 40}}))
        st = bre.load_state(p)
        assert st["inventory_versions"] == {}
        assert st["had_versions"] is False
        assert st["container_seen"] == {"k1"}

    def test_state_roundtrips_versions(self, tmp_path):
        p = tmp_path / "state.json"
        bre.save_state(p, {"k"}, {}, {"fam": "4.19.0"})
        assert bre.load_state(p)["inventory_versions"] == {"fam": "4.19.0"}
        assert bre.load_state(p)["had_versions"] is True
