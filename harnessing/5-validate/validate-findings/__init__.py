"""
validate-findings — Live Validation & Attack-Chain Harness.

Public surface:
  ingest.ingest(source)            -> Normalized
  scope.build(...)                 -> Scope
  plan.build_plan(n, scope, ...)   -> (steps, chains)
  plan.write_plan(...)             -> Path
  execute.run(plan_path, scope, out_dir, ...) -> (results, audit)
  report.build_validation_json(...) / report.write(...)
"""

__all__ = ["chain", "execute", "ingest", "novel", "plan", "report", "scope"]
