# Test Plan

Run the automated suite:

```bash
python -m pytest -q
```

The suite covers:

- Recon helper behavior and invalid target handling
- XSS reflected marker detection
- SQLi helper behavior and mocked detection paths
- Security configuration checks and risk scoring
- Integrated orchestration with mocked modules

Live scans should only be run in an authorized lab or owned environment.
