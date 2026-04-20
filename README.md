# codex-429auto-continue

Watch Codex session logs and inject `继续` into the matching Codex terminal after a `429 Too Many Requests` error.

Files:
- `codex_429_watcher.py`
- `codex_429_watcher.ps1`

Usage:
```powershell
powershell -ExecutionPolicy Bypass -File .\codex_429_watcher.ps1 --replay-recent-errors --verbose
```
