import axios from "axios";

export async function proxy(req: any, res: any): Promise<void> {
  const target = req.query.endpoint;
  // ruleid: traust-ts-ssrf-request-taint
  await fetch(target);

  // ruleid: traust-ts-ssrf-request-taint
  await axios.get(`https://${req.params.cluster}/api/v1/status`);

  // ok: traust-ts-ssrf-request-taint
  await fetch("https://api.openshift.com/healthz");
}
