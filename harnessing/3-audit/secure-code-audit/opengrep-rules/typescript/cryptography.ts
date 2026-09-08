import https from "https";

export function clients(url: string): void {
  // ruleid: traust-ts-cryptography-reject-unauthorized-false
  const agent = new https.Agent({ rejectUnauthorized: false });

  // ruleid: traust-ts-cryptography-reject-unauthorized-false
  process.env.NODE_TLS_REJECT_UNAUTHORIZED = "0";

  // ok: traust-ts-cryptography-reject-unauthorized-false
  const safeAgent = new https.Agent({ keepAlive: true });
  void agent;
  void safeAgent;
}
