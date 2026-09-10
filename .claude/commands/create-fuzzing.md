---
description: "Create or run Go fuzz harnesses for authorized targets and triage resulting crashes."
---

Author and/or run Go-native fuzz harnesses for $ARGUMENTS using the create-fuzzing skill. Load the skill at .claude/skills/create-fuzzing/SKILL.md and follow its full procedure — locate or add a targets.json entry, author a white-box *_fuzz_test.go under harnesses/<id>/, drive `make clone install build fuzz-<id>`, and triage any crashers into follow-up findings. `$ARGUMENTS` may be a repo URL / `<org>/<repo>`, a finding ID, an existing target ID, or empty (run the current batch). Work from `traust/harnessing/6-fuzz/create-fuzzing/`.
