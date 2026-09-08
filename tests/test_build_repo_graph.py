"""Findings-coverage discovery in harnessing/repo-graph/scripts/build_repo_graph.py.

The builder must discover findings dirs through the corpus resolver
(traust.cli.groups.corpus): depth-tolerant (shallow findings/<repo>/ dirs with no
product parent count), symlink aliases excluded, JSON-backed reports only.
The script is CLI-at-import, so it is exercised via subprocess against a
throwaway workspace.
"""

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from traust.paths import skill_dir

HARNESS = Path(__file__).resolve().parents[1]
SCRIPT = skill_dir("repo-graph") / "scripts" / "build_repo_graph.py"


def _audit(dirpath: Path, base: str, url: str) -> None:
    dirpath.mkdir(parents=True, exist_ok=True)
    (dirpath / f"{base}-security-audit.json").write_text(
        json.dumps({"metadata": {"repository": url}, "findings": []})
    )


def _workspace(ws: Path) -> Path:
    """Minimal workspace: inventory CSV + findings tree. Returns findings."""
    findings = ws / "analysis-results" / "findings"
    inp = ws / "inputs" / "services" / "svc"
    inp.mkdir(parents=True)
    # inventory descriptor: segment kinds are declared, never inferred
    # from the directory name (traust.inventory)
    (ws / "inputs" / "inventory.yaml").write_text(
        "segments:\n"
        "  platform: {kind: release-payload, label: Platform}\n"
        "  services: {kind: services, label: Services}\n"
    )
    (inp / "svc-repos.csv").write_text(
        "Repo Name,GitHub URL\n"
        "deep-repo,https://github.com/acme/deep-repo\n"
        "shallow-repo,https://github.com/acme/shallow-repo\n"
        "branchy,https://github.com/acme/branchy\n"
    )
    return findings


def _run(ws: Path, findings: Path) -> subprocess.CompletedProcess:
    return subprocess.run(
        [
            sys.executable,
            str(SCRIPT),
            "--inputs",
            str(ws / "inputs"),
            "--findings",
            str(findings),
            "--out",
            str(ws / "analysis-results" / "graph"),
        ],
        capture_output=True,
        text=True,
    )


class TestFindingsDiscovery(unittest.TestCase):
    def test_shallow_nested_and_branch_dirs_are_discovered(self):
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td)
            findings = _workspace(ws)
            _audit(
                findings / "prod" / "deep-repo", "deep-repo", "https://github.com/acme/deep-repo"
            )
            # shallow: no product parent — invisible to the old */*/ glob
            _audit(
                findings / "shallow-repo", "shallow-repo", "https://github.com/acme/shallow-repo"
            )
            # branch re-audit at product/repo depth — included before, still
            _audit(
                findings / "prod" / "branchy__release-4.19",
                "branchy__release-4.19",
                "https://github.com/acme/branchy",
            )

            proc = _run(ws, findings)
            self.assertEqual(proc.returncode, 0, proc.stderr)
            g = json.loads((ws / "analysis-results" / "graph" / "repo-graph.json").read_text())
            self.assertEqual(g["stats"]["repos_with_findings"], 3)
            labels = {n["label"] for n in g["nodes"] if n["type"] == "findings"}
            self.assertEqual(
                labels, {"prod/deep-repo", "shallow-repo", "prod/branchy__release-4.19"}
            )

    def test_symlink_aliases_are_excluded(self):
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td)
            findings = _workspace(ws)
            real = findings / "prod" / "deep-repo"
            _audit(real, "deep-repo", "https://github.com/acme/deep-repo")
            alias = findings / "alias-repo"
            alias.mkdir(parents=True)
            (alias / "alias-repo-security-audit.json").symlink_to(
                real / "deep-repo-security-audit.json"
            )

            proc = _run(ws, findings)
            self.assertEqual(proc.returncode, 0, proc.stderr)
            g = json.loads((ws / "analysis-results" / "graph" / "repo-graph.json").read_text())
            labels = {n["label"] for n in g["nodes"] if n["type"] == "findings"}
            self.assertEqual(labels, {"prod/deep-repo"})

    def test_owners_csv_trailing_escalation_column_is_tolerated(self):
        # owners.csv gained a trailing 'Escalation Contact' column
        # (2026-07-30). ingest_owners is header-name-driven and must build
        # the same owned-by edges with the column present and ignore it.
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td)
            findings = _workspace(ws)
            _audit(
                findings / "prod" / "deep-repo", "deep-repo", "https://github.com/acme/deep-repo"
            )
            (ws / "inputs" / "services" / "svc" / "owners.csv").write_text(
                "Repository,URL,Host,Owner Team,Manager,"
                "Individual Owners,Ownership Source,Jira Project,"
                "Jira Component,App/Sub-Service,Escalation Contact\n"
                "deep-repo,https://github.com/acme/deep-repo,github,"
                "Acme Team,mgr1,dev1,org,PROJ,comp,svc,alice\n"
            )

            proc = _run(ws, findings)
            self.assertEqual(proc.returncode, 0, proc.stderr)
            g = json.loads((ws / "analysis-results" / "graph" / "repo-graph.json").read_text())
            teams = [n for n in g["nodes"] if n["type"] == "owner-team"]
            self.assertEqual([t["label"] for t in teams], ["Acme Team"])
            owned = [e for e in g["edges"] if e["rel"] == "owned-by"]
            self.assertEqual(len(owned), 1)
            # the new column never leaks into the graph
            self.assertNotIn("alice", json.dumps(g))

    def test_unregistered_findings_tree_hard_fails(self):
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td)
            _workspace(ws)
            other = ws / "analysis-results" / "not-a-corpus-tree"
            _audit(other / "prod" / "deep-repo", "deep-repo", "https://github.com/acme/deep-repo")

            proc = _run(ws, other)
            self.assertNotEqual(proc.returncode, 0)
            self.assertIn("not a registered corpus tree", proc.stderr)


class TestRefLayer(unittest.TestCase):
    """Branch-awareness Phase 2: inventory Source Branch rows
    produce first-class, deduplicated repo-ref nodes plus has_ref/ships_ref
    edges — and inventories without branches produce none."""

    def _graph(self, ws: Path) -> dict:
        return json.loads((ws / "analysis-results" / "graph" / "repo-graph.json").read_text())

    def test_branch_rows_create_deduped_first_class_refs(self):
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td)
            findings = _workspace(ws)
            findings.mkdir(parents=True)
            ocp = ws / "inputs" / "platform"
            ocp.mkdir(parents=True)
            # same (repo, branch) mentioned by two rows → ONE ref node;
            # a row without a branch → no ref for that repo
            (ocp / "platform-4.19-payload-repos.csv").write_text(
                "Repo Name,GitHub URL,Source Branch,Category\n"
                "api,https://github.com/acme/api,release-4.19,Core\n"
                "api,https://github.com/acme/api,release-4.19,Installer\n"
                "tools,https://github.com/acme/tools,,\n"
            )

            proc = _run(ws, findings)
            self.assertEqual(proc.returncode, 0, proc.stderr)
            g = self._graph(ws)

            refs = [n for n in g["nodes"] if n["type"] == "repo-ref"]
            self.assertEqual(len(refs), 1)
            self.assertEqual(refs[0]["id"], "ref:github.com/acme/api@release-4.19")
            self.assertEqual(refs[0]["label"], "acme/api@release-4.19")
            self.assertEqual(refs[0]["attrs"], {"branch": "release-4.19"})

            has_ref = [e for e in g["edges"] if e["rel"] == "has_ref"]
            self.assertEqual(
                has_ref,
                [
                    {
                        "from": "repo:github.com/acme/api",
                        "to": "ref:github.com/acme/api@release-4.19",
                        "rel": "has_ref",
                    }
                ],
            )

            ships_ref = [e for e in g["edges"] if e["rel"] == "ships_ref"]
            self.assertEqual(len(ships_ref), 2)  # one per shipping category
            self.assertEqual(
                {e["from"] for e in ships_ref},
                {"category:platform/Core", "category:platform/Installer"},
            )
            for e in ships_ref:
                self.assertEqual(e["to"], "ref:github.com/acme/api@release-4.19")
                self.assertEqual(e["branch"], "release-4.19")

            # ships edges keep carrying the branch attr exactly as before
            ships = [
                e
                for e in g["edges"]
                if e["rel"] == "ships" and e["to"] == "repo:github.com/acme/api"
            ]
            self.assertEqual(len(ships), 2)
            self.assertTrue(all(e.get("branch") == "release-4.19" for e in ships))

    def test_no_branch_inventory_produces_zero_refs(self):
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td)
            findings = _workspace(ws)  # services CSV only — no branch column
            findings.mkdir(parents=True)
            proc = _run(ws, findings)
            self.assertEqual(proc.returncode, 0, proc.stderr)
            g = self._graph(ws)
            self.assertEqual([n for n in g["nodes"] if n["type"] == "repo-ref"], [])
            self.assertEqual([e for e in g["edges"] if e["rel"] in ("has_ref", "ships_ref")], [])


class TestGitLabSubgroupPaths(unittest.TestCase):
    """canon_repo must keep full GitLab subgroup paths (regression for the
    2026-07-29 week-2 batch: group/subgroup/repo URLs were truncated to
    two segments, producing a phantom group-a/subgroup node and collapsing
    every group-b/subgroup-builds/* repo into one node). GitHub stays
    exactly org/name."""

    def test_subgroup_repos_stay_distinct_and_github_stays_two_seg(self):
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td)
            findings = ws / "analysis-results" / "findings"
            findings.mkdir(parents=True)
            inp = ws / "inputs" / "services" / "svc"
            inp.mkdir(parents=True)
            (inp / "svc-repos.csv").write_text(
                "Repo Name,URL,Organization/Group\n"
                "billing-operator,"
                "https://gitlab.example.com/group-a/subgroup/"
                "billing-operator,group-a/subgroup\n"
                "build-a,https://gitlab.example.com/group-b/"
                "subgroup-builds/build-a,group-b/subgroup-builds\n"
                "build-b,https://gitlab.example.com/group-b/"
                "subgroup-builds/build-b,group-b/subgroup-builds\n"
                "plain,https://github.com/acme/plain,acme\n"
            )

            proc = _run(ws, findings)
            self.assertEqual(proc.returncode, 0, proc.stderr)
            g = json.loads((ws / "analysis-results" / "graph" / "repo-graph.json").read_text())
            ids = {n["id"] for n in g["nodes"] if n["type"] == "repo"}
            self.assertIn("repo:gitlab.example.com/group-a/subgroup/billing-operator", ids)
            self.assertIn("repo:gitlab.example.com/group-b/subgroup-builds/build-a", ids)
            self.assertIn("repo:gitlab.example.com/group-b/subgroup-builds/build-b", ids)
            self.assertIn("repo:github.com/acme/plain", ids)
            # the truncated phantom must NOT exist
            self.assertNotIn("repo:gitlab.example.com/group-a/subgroup", ids)
            self.assertNotIn("repo:gitlab.example.com/group-b/subgroup-builds", ids)
            # node url attr carries the full clone path
            aap = next(n for n in g["nodes"] if n["id"].endswith("billing-operator"))
            self.assertEqual(
                aap["attrs"]["url"], "https://gitlab.example.com/group-a/subgroup/billing-operator"
            )


if __name__ == "__main__":
    unittest.main()
