#!/usr/bin/env python3
"""scan_k8s_hardening.py tests — fixture manifests per check class."""

import tempfile
import unittest
from pathlib import Path

from traust_engine.adapters import checkov as S

BAD_DEPLOYMENT = """\
apiVersion: apps/v1
kind: Deployment
metadata:
  name: bad-app
spec:
  template:
    spec:
      hostNetwork: true
      volumes:
      - name: host
        hostPath:
          path: /var/run
      containers:
      - name: app
        image: quay.io/example/app:latest
        env:
        - name: TOKEN
          valueFrom:
            secretKeyRef:
              name: creds
              key: token
        args: ["--anonymous-auth=true"]
        securityContext:
          privileged: true
          capabilities:
            add: ["SYS_ADMIN"]
"""

GOOD_DEPLOYMENT = """\
apiVersion: apps/v1
kind: Deployment
metadata:
  name: good-app
spec:
  template:
    spec:
      serviceAccountName: good-app
      automountServiceAccountToken: false
      securityContext:
        runAsNonRoot: true
        seccompProfile:
          type: RuntimeDefault
      containers:
      - name: app
        image: quay.io/example/app@sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
        resources:
          limits: {cpu: 100m, memory: 128Mi}
        securityContext:
          allowPrivilegeEscalation: false
          readOnlyRootFilesystem: true
          capabilities:
            drop: ["ALL"]
"""

WILDCARD_ROLE = """\
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: too-broad
rules:
- apiGroups: ["*"]
  resources: ["*"]
  verbs: ["*"]
- apiGroups: [""]
  resources: ["secrets"]
  verbs: ["get", "list"]
- apiGroups: ["rbac.authorization.k8s.io"]
  resources: ["clusterroles"]
  verbs: ["escalate", "bind"]
"""

ADMIN_BINDING = """\
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: give-admin
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: cluster-admin
subjects:
- kind: ServiceAccount
  name: app
"""

CRD = """\
apiVersion: apiextensions.k8s.io/v1
kind: CustomResourceDefinition
metadata:
  name: widgets.example.io
spec:
  group: example.io
  scope: Namespaced
  names:
    kind: Widget
    plural: widgets
"""

WEBHOOK_WITH_RULES = """\
apiVersion: admissionregistration.k8s.io/v1
kind: MutatingWebhookConfiguration
metadata:
  name: mw
webhooks:
- name: mutate.example.io
  failurePolicy: Fail
  rules:
  - apiGroups: ["apps"]
    resources: ["deployments"]
    operations: ["CREATE", "UPDATE"]
"""

GO_GROUP_LITERAL = """\
package api

var gv = schema.GroupVersion{Group: "route.openshift.io", Version: "v1"}
"""

CSV = """\
apiVersion: operators.coreos.com/v1alpha1
kind: ClusterServiceVersion
metadata:
  name: my-operator.v1.0.0
spec:
  customresourcedefinitions:
    owned:
    - name: widgets.example.io
      kind: Widget
      version: v1
    required:
    - name: certificates.cert-manager.io
      kind: Certificate
      version: v1
  installModes:
  - type: OwnNamespace
    supported: false
  - type: AllNamespaces
    supported: true
  install:
    spec:
      deployments:
      - name: my-operator
        spec:
          template:
            spec:
              containers:
              - name: manager
                image: quay.io/example/operator:v1
"""

NETPOL = """\
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: default-deny
spec:
  podSelector: {}
"""

NETPOL_ALLOW_ALL = """\
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: allow-everything
spec:
  podSelector: {}
  policyTypes: ["Ingress", "Egress"]
  ingress:
  - {}
  egress:
  - {}
"""

NETPOL_BROAD_PEERS = """\
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: broad-peers
spec:
  podSelector:
    matchLabels:
      app: web
  ingress:
  - from:
    - namespaceSelector: {}
  - ports:
    - port: 8080
  egress:
  - to:
    - ipBlock:
        cidr: 0.0.0.0/0
"""

ANP_PERMISSIVE = """\
apiVersion: policy.networking.k8s.io/v1alpha1
kind: AdminNetworkPolicy
metadata:
  name: cluster-allow
spec:
  priority: 10
  subject:
    namespaces: {}
  ingress:
  - name: allow-everyone
    action: Allow
    from:
    - namespaces: {}
  egress:
  - name: allow-internet
    action: Allow
    to:
    - networks:
      - 0.0.0.0/0
"""

ANP_SCOPED = """\
apiVersion: policy.networking.k8s.io/v1alpha1
kind: AdminNetworkPolicy
metadata:
  name: scoped-admin
spec:
  priority: 20
  subject:
    namespaces:
      matchLabels:
        tenant: a
  ingress:
  - name: deny-cross-tenant
    action: Deny
    from:
    - namespaces: {}
  - name: allow-monitoring
    action: Allow
    from:
    - namespaces:
        matchLabels:
          kubernetes.io/metadata.name: monitoring
  - name: pass-to-netpol
    action: Pass
    from:
    - namespaces: {}
"""

BANP_PERMISSIVE_PODS = """\
apiVersion: policy.networking.k8s.io/v1alpha1
kind: BaselineAdminNetworkPolicy
metadata:
  name: default
spec:
  subject:
    namespaces: {}
  ingress:
  - name: allow-all-pods
    action: Allow
    from:
    - pods:
        namespaceSelector: {}
        podSelector: {}
"""

EGRESS_FIREWALL_PERMISSIVE = """\
apiVersion: k8s.ovn.org/v1
kind: EgressFirewall
metadata:
  name: default
spec:
  egress:
  - type: Allow
    to:
      cidrSelector: 0.0.0.0/0
"""

EGRESS_FIREWALL_SCOPED = """\
apiVersion: k8s.ovn.org/v1
kind: EgressFirewall
metadata:
  name: default
spec:
  egress:
  - type: Allow
    to:
      dnsName: registry.redhat.io
  - type: Allow
    to:
      cidrSelector: 10.0.0.0/8
  - type: Deny
    to:
      cidrSelector: 0.0.0.0/0
"""

MULTI_NETPOL_ALLOW_ALL = """\
apiVersion: k8s.cni.cncf.io/v1beta1
kind: MultiNetworkPolicy
metadata:
  name: allow-all-secondary
  annotations:
    k8s.v1.cni.cncf.io/policy-for: macvlan-net
spec:
  podSelector: {}
  ingress:
  - {}
"""

NETPOL_SCOPED = """\
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: scoped
spec:
  podSelector:
    matchLabels:
      app: web
  ingress:
  - from:
    - namespaceSelector:
        matchLabels:
          kubernetes.io/metadata.name: monitoring
    - namespaceSelector: {}
      podSelector:
        matchLabels:
          app: gateway
    ports:
    - port: 8080
"""

WEBHOOK = """\
apiVersion: admissionregistration.k8s.io/v1
kind: ValidatingWebhookConfiguration
metadata:
  name: vw
webhooks:
- name: check.example.com
  failurePolicy: Ignore
"""

NAMESPACE_NO_PSA = """\
apiVersion: v1
kind: Namespace
metadata:
  name: app-ns
  labels:
    team: x
"""

HELM_TEMPLATED = """\
apiVersion: apps/v1
kind: Deployment
metadata:
  name: {{ .Release.Name }}
"""

GO_FILE = """\
package main

import "crypto/tls"

func dial() {
\tcfg := &tls.Config{InsecureSkipVerify: true}
\t_ = cfg
}

// WATCH_NAMESPACE drives scoping
// uses SubjectAccessReview for authz
"""


def scan(tree: dict) -> dict:
    """Write {relpath: content} into a tmp dir and return the report."""
    with tempfile.TemporaryDirectory() as d:
        root = Path(d)
        for rel, content in tree.items():
            p = root / rel
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(content)
        scanner = S.Scanner(root)
        scanner.run()
        return scanner.report()


def checks(report: dict) -> set:
    return {r["check"] for r in report["results"]}


class TestWorkloadChecks(unittest.TestCase):
    def test_bad_deployment_fires_expected_checks(self):
        r = scan({"config/bad.yaml": BAD_DEPLOYMENT})
        expected = {
            "KHS-W01",
            "KHS-W03",
            "KHS-W04",
            "KHS-W06",
            "KHS-W07",
            "KHS-W10",
            "KHS-W11",
            "KHS-W13",
            "KHS-A01",
            "KHS-N02",
        }
        self.assertLessEqual(expected, checks(r))

    def test_good_deployment_minimal_noise(self):
        r = scan({"config/good.yaml": GOOD_DEPLOYMENT, "config/netpol.yaml": NETPOL})
        noisy = {
            "KHS-W01",
            "KHS-W02",
            "KHS-W03",
            "KHS-W04",
            "KHS-W06",
            "KHS-W07",
            "KHS-W08",
            "KHS-W09",
            "KHS-W10",
            "KHS-W11",
            "KHS-W12",
            "KHS-W13",
            "KHS-A01",
            "KHS-N02",
        }
        self.assertEqual(checks(r) & noisy, set())

    def test_results_carry_file_line_and_kind(self):
        r = scan({"config/bad.yaml": BAD_DEPLOYMENT})
        hit = next(x for x in r["results"] if x["check"] == "KHS-W01")
        self.assertEqual(hit["file"], "config/bad.yaml")
        self.assertGreater(hit["line"], 1)
        self.assertEqual(hit["kind"], "Deployment")
        self.assertEqual(hit["name"], "bad-app")

    def test_test_path_and_patch_overlay_tagging(self):
        r = scan(
            {
                "test/e2e/bad.yaml": BAD_DEPLOYMENT,
                "config/manager_auth_proxy_patch.yaml": BAD_DEPLOYMENT,
            }
        )
        by_file = {}
        for x in r["results"]:
            by_file.setdefault(x["file"], x)
        self.assertTrue(by_file["test/e2e/bad.yaml"]["test_path"])
        self.assertTrue(by_file["config/manager_auth_proxy_patch.yaml"]["patch_overlay"])
        self.assertFalse(by_file["test/e2e/bad.yaml"]["patch_overlay"])


class TestRbacChecks(unittest.TestCase):
    def test_wildcards_secrets_escalation(self):
        r = scan({"config/rbac/role.yaml": WILDCARD_ROLE})
        self.assertLessEqual({"KHS-R01", "KHS-R03", "KHS-R04"}, checks(r))
        self.assertEqual(next(x["name"] for x in r["results"]), "too-broad")

    def test_cluster_admin_binding(self):
        r = scan({"config/rbac/binding.yaml": ADMIN_BINDING})
        self.assertIn("KHS-R02", checks(r))

    def test_cluster_scoped_rbac_signal(self):
        r = scan({"config/rbac/role.yaml": WILDCARD_ROLE})
        self.assertEqual(r["tenancy_signals"]["cluster_scoped_rbac"][0]["name"], "too-broad")


class TestOtherKindsAndSignals(unittest.TestCase):
    def test_csv_install_modes_and_embedded_deployment(self):
        r = scan({"bundle/manifests/op.csv.yaml": CSV})
        self.assertEqual(r["tenancy_signals"]["csv_install_modes"]["AllNamespaces"], True)
        self.assertIn("KHS-W11", checks(r))  # embedded deployment scanned

    def test_webhook_failure_policy_and_psa(self):
        r = scan({"config/wh.yaml": WEBHOOK, "config/ns.yaml": NAMESPACE_NO_PSA})
        self.assertLessEqual({"KHS-H01", "KHS-P01"}, checks(r))

    def test_netpol_presence_suppresses_n02(self):
        r = scan({"config/bad.yaml": BAD_DEPLOYMENT, "config/netpol.yaml": NETPOL})
        self.assertNotIn("KHS-N02", checks(r))

    def test_templated_files_skipped_and_counted(self):
        r = scan({"chart/templates/deploy.yaml": HELM_TEMPLATED})
        self.assertEqual(r["stats"]["templated_skipped"], 1)
        self.assertEqual(r["templated_files"], ["chart/templates/deploy.yaml"])
        self.assertEqual(r["results"], [])

    def test_code_signals(self):
        r = scan({"pkg/client.go": GO_FILE})
        ts = r["tenancy_signals"]
        self.assertEqual(ts["insecure_skip_verify"][0]["file"], "pkg/client.go")
        self.assertTrue(ts["watch_scope_hints"])
        self.assertTrue(ts["subject_access_review_usage"])

    def test_vendor_excluded(self):
        r = scan({"vendor/x/bad.yaml": BAD_DEPLOYMENT, "vendor/x/client.go": GO_FILE})
        self.assertEqual(r["results"], [])
        self.assertEqual(r["tenancy_signals"]["insecure_skip_verify"], [])


class TestNetworkPolicyPermissiveness(unittest.TestCase):
    def test_default_deny_not_flagged(self):
        r = scan({"config/netpol.yaml": NETPOL})
        self.assertNotIn("KHS-N03", checks(r))
        sig = r["tenancy_signals"]["network_policies"][0]
        self.assertFalse(sig["permissive"])

    def test_allow_all_rules_flagged_both_directions(self):
        r = scan({"config/netpol.yaml": NETPOL_ALLOW_ALL})
        hits = [x for x in r["results"] if x["check"] == "KHS-N03"]
        self.assertEqual(len(hits), 2)
        details = " ".join(h["detail"] for h in hits)
        self.assertIn("ingress", details)
        self.assertIn("egress", details)
        sig = r["tenancy_signals"]["network_policies"][0]
        self.assertTrue(sig["permissive"])

    def test_broad_peers_flagged(self):
        r = scan({"config/netpol.yaml": NETPOL_BROAD_PEERS})
        hits = [x for x in r["results"] if x["check"] == "KHS-N03"]
        self.assertEqual(len(hits), 3)  # match-all ns, ports-only, 0.0.0.0/0
        details = " ".join(h["detail"] for h in hits)
        self.assertIn("every namespace", details)
        self.assertIn("no 'from' peers", details)
        self.assertIn("0.0.0.0/0", details)

    def test_scoped_policy_not_flagged(self):
        # labelled namespaceSelector, and match-all namespaceSelector
        # narrowed by a podSelector, are both legitimate scoping
        r = scan({"config/netpol.yaml": NETPOL_SCOPED})
        self.assertNotIn("KHS-N03", checks(r))

    def test_permissive_netpol_still_suppresses_n02(self):
        r = scan({"config/bad.yaml": BAD_DEPLOYMENT, "config/netpol.yaml": NETPOL_ALLOW_ALL})
        self.assertNotIn("KHS-N02", checks(r))
        self.assertIn("KHS-N03", checks(r))


class TestOpenShiftNetworkPolicies(unittest.TestCase):
    def test_anp_allow_all_flagged_both_shapes(self):
        r = scan({"config/anp.yaml": ANP_PERMISSIVE})
        hits = [x for x in r["results"] if x["check"] == "KHS-N04"]
        self.assertEqual(len(hits), 2)  # match-all namespaces + 0.0.0.0/0
        details = " ".join(h["detail"] for h in hits)
        self.assertIn("match-all namespaces", details)
        self.assertIn("0.0.0.0/0", details)
        sig = r["tenancy_signals"]["openshift_network_policies"][0]
        self.assertEqual(sig["kind"], "AdminNetworkPolicy")
        self.assertTrue(sig["permissive"])

    def test_anp_deny_and_pass_and_labelled_allow_not_flagged(self):
        r = scan({"config/anp.yaml": ANP_SCOPED})
        self.assertNotIn("KHS-N04", checks(r))
        sig = r["tenancy_signals"]["openshift_network_policies"][0]
        self.assertFalse(sig["permissive"])

    def test_banp_match_all_pods_peer_flagged(self):
        r = scan({"config/banp.yaml": BANP_PERMISSIVE_PODS})
        hits = [x for x in r["results"] if x["check"] == "KHS-N04"]
        self.assertEqual(len(hits), 1)
        self.assertIn("match-all pods peer", hits[0]["detail"])
        self.assertEqual(hits[0]["kind"], "BaselineAdminNetworkPolicy")

    def test_egress_firewall_allow_all_flagged(self):
        r = scan({"config/ef.yaml": EGRESS_FIREWALL_PERMISSIVE})
        hits = [x for x in r["results"] if x["check"] == "KHS-N04"]
        self.assertEqual(len(hits), 1)
        self.assertIn("0.0.0.0/0", hits[0]["detail"])

    def test_egress_firewall_trailing_deny_all_not_flagged(self):
        # Deny 0.0.0.0/0 is the correct default-deny tail; scoped Allows
        # (dnsName, private CIDR) are fine
        r = scan({"config/ef.yaml": EGRESS_FIREWALL_SCOPED})
        self.assertNotIn("KHS-N04", checks(r))

    def test_multi_networkpolicy_reuses_n03(self):
        r = scan({"config/mnp.yaml": MULTI_NETPOL_ALLOW_ALL})
        hits = [x for x in r["results"] if x["check"] == "KHS-N03"]
        self.assertEqual(len(hits), 1)
        self.assertEqual(hits[0]["kind"], "MultiNetworkPolicy")
        sig = r["tenancy_signals"]["openshift_network_policies"][0]
        self.assertEqual(sig["kind"], "MultiNetworkPolicy")
        self.assertTrue(sig["permissive"])

    def test_openshift_kinds_do_not_suppress_n02(self):
        # none of these is pod-level primary-network default-deny
        r = scan(
            {
                "config/bad.yaml": BAD_DEPLOYMENT,
                "config/anp.yaml": ANP_SCOPED,
                "config/ef.yaml": EGRESS_FIREWALL_SCOPED,
                "config/mnp.yaml": MULTI_NETPOL_ALLOW_ALL,
            }
        )
        self.assertIn("KHS-N02", checks(r))


class TestInterfaceExtraction(unittest.TestCase):
    def test_crd_definition_extracted(self):
        r = scan({"config/crd/widget.yaml": CRD})
        crds = r["tenancy_signals"]["crds_defined"]
        self.assertEqual(len(crds), 1)
        self.assertEqual(
            (crds[0]["group"], crds[0]["kind"], crds[0]["scope"]),
            ("example.io", "Widget", "Namespaced"),
        )

    def test_csv_owned_and_required(self):
        r = scan({"bundle/manifests/op.csv.yaml": CSV})
        ts = r["tenancy_signals"]
        self.assertEqual(ts["csv_owned_crds"][0]["name"], "widgets.example.io")
        self.assertEqual(ts["csv_required_crds"][0]["kind"], "Certificate")

    def test_webhook_rules_extracted(self):
        r = scan({"config/webhook/mw.yaml": WEBHOOK_WITH_RULES})
        wh = r["tenancy_signals"]["webhooks"][0]
        self.assertTrue(wh["mutating"])
        self.assertEqual(wh["rules"][0]["groups"], ["apps"])
        self.assertEqual(wh["failure_policy"], "Fail")
        # Fail policy is not a KHS-H01 hit
        self.assertNotIn("KHS-H01", checks(r))

    def test_rbac_grants_recorded(self):
        r = scan({"config/rbac/role.yaml": WILDCARD_ROLE})
        grants = r["tenancy_signals"]["rbac_grants"]
        self.assertEqual(len(grants), 3)
        self.assertEqual(grants[1]["resources"], ["secrets"])

    def test_api_group_literal_signal(self):
        r = scan({"pkg/api/gv.go": GO_GROUP_LITERAL})
        lits = r["tenancy_signals"]["api_group_literals"]
        self.assertEqual(lits[0]["value"], "route.openshift.io")


if __name__ == "__main__":
    unittest.main()
