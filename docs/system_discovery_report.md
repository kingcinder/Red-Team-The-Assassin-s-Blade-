# Whole-System Discovery Report

Generated: `2026-09-20T17:00:11.251463+00:00`  
Repository: `/home/cody/Documents/redteam-harness`  
Read-only: `True`

This pass is discovery-only. Findings below were not repaired during the scan.

**Findings:** 1

## PYENV-PIP-CHECK-home-cody-Documents-the oracle tts-.venv-bin

- **Category:** python-dependency  
- **Severity / confidence:** medium / medium  
- **Status:** new  
- **When:** 2026-09-20T17:00:00.703918+00:00  
- **Where:** `/home/cody/Documents/the oracle tts/.venv/bin`  
- **What:** Python environment reports dependency metadata problems.  
- **Why:** Installed package metadata does not form a clean dependency set.  
- **How detected/reproduced:** Run: /home/cody/Documents/the oracle tts/.venv/bin/pip check  
- **Evidence:** `chatterbox-tts 0.1.6 has requirement gradio==5.44.1, but you have gradio 6.8.0.
chatterbox-tts 0.1.6 has requirement numpy<1.26.0,>=1.24.0, but you have numpy 1.26.4.
`  
- **Recommended correction:** Resolve or isolate the conflicting environment dependencies.

