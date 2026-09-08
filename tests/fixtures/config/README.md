# Test fixture: an estate-neutral `TRAUST_CONFIG_HOME`

`tests/conftest.py` points `TRAUST_CONFIG_HOME` here so the suite runs without
any operational configuration. Contents are the harness repo's shipped
`config/*.example.*` templates (renamed to their real filenames) plus its
`model-registry.yaml`. Nothing here is deployment data and nothing here ships
in the wheel (`[tool.hatch.build.targets.wheel] packages = ["src/traust_engine"]`).
When a template changes upstream, refresh the copy here.

`corpus-config.yaml` must be a filled-in fixture — `load_context()` loads
schema-valid files; completeness is checked separately (see
`config_completeness_audit`).
