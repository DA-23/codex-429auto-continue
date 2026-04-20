#!/usr/bin/env python3
from __future__ import annotations

import argparse
import ctypes
import json
import re
import sys
import time
from collections import defaultdict, deque
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable

import psutil
import win32con
import win32console
import win32file

ERROR_TEXT = "exceeded retry limit, last status: 429 Too Many Requests"
REQUEST_ID_RE = re.compile(r"request id:\s*([0-9a-f-]+)", re.IGNORECASE)
SESSION_ID_RE = re.compile(r"([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})")
LEADING_STATUS_RE = re.compile(r"^[^\w\u4e00-\u9fff]+", re.UNICODE)

kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
user32 = ctypes.WinDLL("user32", use_last_error=True)
GetConsoleTitleW = kernel32.GetConsoleTitleW
GetConsoleTitleW.argtypes = [ctypes.c_wchar_p, ctypes.c_uint]
GetConsoleTitleW.restype = ctypes.c_uint
MapVirtualKeyW = user32.MapVirtualKeyW
MapVirtualKeyW.argtypes = [ctypes.c_uint, ctypes.c_uint]
MapVirtualKeyW.restype = ctypes.c_uint


@dataclass
class PendingResume:
    key: str
    message: str
    first_seen: float


@dataclass
class SessionState:
    path: Path
    session_id: str
    cwd: str
    title_key: str
    started_at: float
    offset: int
    last_mtime: float
    last_inject_at: float = 0.0
    pending: PendingResume | None = None
    sent_keys: set[str] = field(default_factory=set)


@dataclass
class TerminalTarget:
    codex_pid: int
    shell_pid: int
    shell_create_time: float
    title: str
    title_key: str
    match_reason: str = ""


class Codex429Watcher:
    def __init__(
        self,
        sessions_root: Path,
        poll_interval: float,
        cooldown_seconds: float,
        continue_text: str,
        dry_run: bool,
        replay_recent: bool,
        replay_lines: int,
        verbose: bool,
    ) -> None:
        self.sessions_root = sessions_root
        self.poll_interval = poll_interval
        self.cooldown_seconds = cooldown_seconds
        self.continue_text = continue_text
        self.dry_run = dry_run
        self.replay_recent = replay_recent
        self.replay_lines = replay_lines
        self.verbose = verbose
        self.sessions: dict[Path, SessionState] = {}
        self.targets_by_session: dict[str, TerminalTarget] = {}

    def run(self) -> int:
        self.log(f"watching {self.sessions_root}")
        while True:
            self.discover_sessions()
            self.refresh_targets()
            self.read_updates()
            self.flush_pending()
            time.sleep(self.poll_interval)

    def discover_sessions(self) -> None:
        if not self.sessions_root.exists():
            self.log(f"sessions root does not exist: {self.sessions_root}")
            return

        for path in self.iter_session_files():
            if path in self.sessions:
                continue
            meta = self.read_session_meta(path)
            if not meta:
                continue

            state = SessionState(
                path=path,
                session_id=meta["session_id"],
                cwd=meta["cwd"],
                title_key=self.normalize_title_key(Path(meta["cwd"]).name),
                started_at=meta["started_at"],
                offset=path.stat().st_size,
                last_mtime=path.stat().st_mtime,
            )
            self.sessions[path] = state
            self.log(
                f"discovered {state.session_id} cwd={state.cwd}",
                verbose_only=True,
            )
            if self.replay_recent:
                self.replay_recent_lines(state)

    def refresh_targets(self) -> None:
        terminals = self.collect_terminal_targets()
        mapping: dict[str, TerminalTarget] = {}
        used_session_ids: set[str] = set()
        used_shell_pids: set[int] = set()

        exact_pairs = self.build_exact_pairs(terminals)
        self.consume_pairs(exact_pairs, mapping, used_session_ids, used_shell_pids)

        fuzzy_pairs = self.build_fuzzy_pairs(terminals, used_session_ids, used_shell_pids)
        self.consume_pairs(fuzzy_pairs, mapping, used_session_ids, used_shell_pids)

        fallback_pairs = self.build_recency_pairs(terminals, used_session_ids, used_shell_pids)
        self.consume_pairs(fallback_pairs, mapping, used_session_ids, used_shell_pids)

        self.targets_by_session = mapping
        if self.verbose:
            for session_id, target in sorted(self.targets_by_session.items()):
                self.log(
                    f"mapped {session_id} -> shell={target.shell_pid} title={target.title!r} reason={target.match_reason}",
                    verbose_only=True,
                )

    def build_exact_pairs(self, terminals: list[TerminalTarget]) -> list[tuple[SessionState, TerminalTarget, str]]:
        grouped_sessions: dict[str, list[SessionState]] = defaultdict(list)
        grouped_targets: dict[str, list[TerminalTarget]] = defaultdict(list)

        for state in self.sessions.values():
            grouped_sessions[state.title_key].append(state)
        for target in terminals:
            grouped_targets[target.title_key].append(target)

        pairs: list[tuple[SessionState, TerminalTarget, str]] = []
        for title_key, targets in grouped_targets.items():
            sessions = sorted(
                grouped_sessions.get(title_key, []),
                key=lambda item: (item.last_mtime, item.started_at),
                reverse=True,
            )
            targets = sorted(
                targets,
                key=lambda item: item.shell_create_time,
                reverse=True,
            )
            for session, target in zip(sessions, targets):
                pairs.append((session, target, "exact-title"))
        return pairs

    def build_fuzzy_pairs(
        self,
        terminals: list[TerminalTarget],
        used_session_ids: set[str],
        used_shell_pids: set[int],
    ) -> list[tuple[SessionState, TerminalTarget, str]]:
        scored: list[tuple[int, float, SessionState, TerminalTarget, str]] = []
        for session in self.sessions.values():
            if session.session_id in used_session_ids:
                continue
            for target in terminals:
                if target.shell_pid in used_shell_pids:
                    continue
                reason, score = self.get_fuzzy_reason_and_score(session.title_key, target.title_key)
                if score <= 0:
                    continue
                time_delta = abs(session.started_at - target.shell_create_time)
                scored.append((score, -time_delta, session, target, reason))

        scored.sort(key=lambda item: (item[0], item[1]), reverse=True)
        return [(session, target, reason) for _, _, session, target, reason in scored]

    def build_recency_pairs(
        self,
        terminals: list[TerminalTarget],
        used_session_ids: set[str],
        used_shell_pids: set[int],
    ) -> list[tuple[SessionState, TerminalTarget, str]]:
        sessions = sorted(
            [s for s in self.sessions.values() if s.session_id not in used_session_ids],
            key=lambda item: (item.last_mtime, item.started_at),
            reverse=True,
        )
        targets = sorted(
            [t for t in terminals if t.shell_pid not in used_shell_pids],
            key=lambda item: item.shell_create_time,
            reverse=True,
        )
        return [(session, target, "recency-fallback") for session, target in zip(sessions, targets)]

    def consume_pairs(
        self,
        pairs: list[tuple[SessionState, TerminalTarget, str]],
        mapping: dict[str, TerminalTarget],
        used_session_ids: set[str],
        used_shell_pids: set[int],
    ) -> None:
        for session, target, reason in pairs:
            if session.session_id in used_session_ids or target.shell_pid in used_shell_pids:
                continue
            target.match_reason = reason
            mapping[session.session_id] = target
            used_session_ids.add(session.session_id)
            used_shell_pids.add(target.shell_pid)

    def get_fuzzy_reason_and_score(self, session_key: str, target_key: str) -> tuple[str, int]:
        if not session_key or not target_key:
            return ("", 0)
        if session_key == target_key:
            return ("exact-title", 1000)
        if target_key in session_key or session_key in target_key:
            return ("substring-title", 300)
        if len(target_key) <= 4 and self.is_subsequence(target_key, session_key):
            return ("short-subsequence-title", 200)
        if len(session_key) <= 4 and self.is_subsequence(session_key, target_key):
            return ("session-short-subsequence", 180)
        return ("", 0)

    def is_subsequence(self, needle: str, haystack: str) -> bool:
        if not needle:
            return False
        index = 0
        for ch in haystack:
            if ch == needle[index]:
                index += 1
                if index == len(needle):
                    return True
        return False

    def collect_terminal_targets(self) -> list[TerminalTarget]:
        targets: list[TerminalTarget] = []
        for proc in psutil.process_iter(["pid", "name", "create_time"]):
            try:
                name = (proc.info.get("name") or "").lower()
                if name != "codex.exe" and name != "codex":
                    continue
                node_proc = proc.parent()
                shell_proc = node_proc.parent() if node_proc else None
                if node_proc is None or shell_proc is None:
                    continue
                if "node" not in node_proc.name().lower():
                    continue
                if not shell_proc.name().lower().startswith("pwsh"):
                    continue

                title = self.get_console_title(shell_proc.pid)
                title_key = self.normalize_title_key(title)
                if not title_key:
                    continue

                targets.append(
                    TerminalTarget(
                        codex_pid=proc.pid,
                        shell_pid=shell_proc.pid,
                        shell_create_time=shell_proc.create_time(),
                        title=title,
                        title_key=title_key,
                    )
                )
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
        return targets

    def read_updates(self) -> None:
        for state in list(self.sessions.values()):
            try:
                stat = state.path.stat()
            except FileNotFoundError:
                self.log(f"session file disappeared: {state.path}", verbose_only=True)
                self.sessions.pop(state.path, None)
                continue

            size = stat.st_size
            state.last_mtime = stat.st_mtime
            if size < state.offset:
                state.offset = 0

            if size == state.offset:
                continue

            with state.path.open("r", encoding="utf-8", errors="replace") as handle:
                handle.seek(state.offset)
                while True:
                    line = handle.readline()
                    if not line:
                        break
                    state.offset = handle.tell()
                    self.handle_line(state, line)

    def replay_recent_lines(self, state: SessionState) -> None:
        try:
            with state.path.open("r", encoding="utf-8", errors="replace") as handle:
                recent = deque(handle, maxlen=self.replay_lines)
        except OSError as exc:
            self.log(f"failed to replay {state.path}: {exc}")
            return

        for line in recent:
            self.handle_line(state, line, replay=True)

        try:
            stat = state.path.stat()
            state.offset = stat.st_size
            state.last_mtime = stat.st_mtime
        except FileNotFoundError:
            state.offset = 0

    def handle_line(self, state: SessionState, raw_line: str, replay: bool = False) -> None:
        try:
            entry = json.loads(raw_line)
        except json.JSONDecodeError:
            return

        message = self.extract_user_message(entry)
        if message is not None and message.strip() == self.continue_text:
            state.pending = None
            state.last_inject_at = time.time()
            self.log(
                f"{state.session_id}: detected manual continue{' from history' if replay else ''}",
                verbose_only=True,
            )
            return

        error_message = self.extract_error_message(entry)
        if not error_message or ERROR_TEXT not in error_message:
            return

        key = self.build_error_key(error_message, raw_line)
        if key in state.sent_keys:
            return
        state.pending = PendingResume(key=key, message=error_message, first_seen=time.time())
        self.log(
            f"{state.session_id}: queued continue for 429{' from history' if replay else ''}",
        )

    def flush_pending(self) -> None:
        now = time.time()
        for state in self.sessions.values():
            if state.pending is None:
                continue
            if now - state.last_inject_at < self.cooldown_seconds:
                continue

            target = self.targets_by_session.get(state.session_id)
            if target is None:
                self.log(
                    f"{state.session_id}: no terminal mapping for cwd={state.cwd}",
                    verbose_only=True,
                )
                continue

            if self.inject_continue(target, state):
                state.sent_keys.add(state.pending.key)
                state.pending = None
                state.last_inject_at = now

    def inject_continue(self, target: TerminalTarget, state: SessionState) -> bool:
        self.log(
            f"{state.session_id}: injecting into shell={target.shell_pid} title={target.title!r}"
        )
        if self.dry_run:
            return True

        try:
            self.write_console_text(target.shell_pid, self.continue_text)
            return True
        except Exception as exc:
            self.log(f"{state.session_id}: inject failed: {exc}")
            return False

    def write_console_text(self, shell_pid: int, text: str) -> None:
        if not kernel32.FreeConsole():
            ctypes.set_last_error(0)
        if not kernel32.AttachConsole(shell_pid):
            raise OSError(ctypes.get_last_error(), f"AttachConsole({shell_pid}) failed")

        try:
            handle = win32file.CreateFile(
                "CONIN$",
                win32con.GENERIC_READ | win32con.GENERIC_WRITE,
                win32con.FILE_SHARE_READ | win32con.FILE_SHARE_WRITE,
                None,
                win32con.OPEN_EXISTING,
                0,
                None,
            )
            conin = win32console.PyConsoleScreenBufferType(handle.Detach())
            records = self.build_text_input_records(text)
            conin.WriteConsoleInput(records)
        finally:
            kernel32.FreeConsole()

    def build_text_input_records(self, text: str) -> list:
        records = []
        for ch in text:
            key_down = win32console.PyINPUT_RECORDType(win32console.KEY_EVENT)
            key_down.KeyDown = 1
            key_down.RepeatCount = 1
            key_down.Char = ch
            key_down.VirtualKeyCode = 0
            key_down.VirtualScanCode = 0
            key_down.ControlKeyState = 0

            key_up = win32console.PyINPUT_RECORDType(win32console.KEY_EVENT)
            key_up.KeyDown = 0
            key_up.RepeatCount = 1
            key_up.Char = ch
            key_up.VirtualKeyCode = 0
            key_up.VirtualScanCode = 0
            key_up.ControlKeyState = 0
            records.extend([key_down, key_up])

        enter_scan = MapVirtualKeyW(win32con.VK_RETURN, 0)
        enter_down = win32console.PyINPUT_RECORDType(win32console.KEY_EVENT)
        enter_down.KeyDown = 1
        enter_down.RepeatCount = 1
        enter_down.Char = "\r"
        enter_down.VirtualKeyCode = win32con.VK_RETURN
        enter_down.VirtualScanCode = enter_scan
        enter_down.ControlKeyState = 0

        enter_up = win32console.PyINPUT_RECORDType(win32console.KEY_EVENT)
        enter_up.KeyDown = 0
        enter_up.RepeatCount = 1
        enter_up.Char = "\r"
        enter_up.VirtualKeyCode = win32con.VK_RETURN
        enter_up.VirtualScanCode = enter_scan
        enter_up.ControlKeyState = 0
        records.extend([enter_down, enter_up])
        return records

    def get_console_title(self, shell_pid: int) -> str:
        if not kernel32.FreeConsole():
            ctypes.set_last_error(0)
        if not kernel32.AttachConsole(shell_pid):
            return ""
        try:
            buffer = ctypes.create_unicode_buffer(1024)
            length = GetConsoleTitleW(buffer, len(buffer))
            return buffer.value[:length]
        finally:
            kernel32.FreeConsole()

    def read_session_meta(self, path: Path) -> dict | None:
        try:
            with path.open("r", encoding="utf-8", errors="replace") as handle:
                for _ in range(5):
                    line = handle.readline()
                    if not line:
                        break
                    entry = json.loads(line)
                    if entry.get("type") != "session_meta":
                        continue
                    payload = entry.get("payload") or {}
                    session_id = payload.get("id")
                    cwd = payload.get("cwd")
                    started_text = payload.get("timestamp")
                    if not isinstance(session_id, str) or not isinstance(cwd, str):
                        return None
                    started_at = self.parse_timestamp(started_text)
                    return {
                        "session_id": session_id,
                        "cwd": cwd,
                        "started_at": started_at,
                    }
        except (OSError, json.JSONDecodeError):
            return None
        return None

    def parse_timestamp(self, value: str | None) -> float:
        if not value:
            return 0.0
        try:
            return time.mktime(time.strptime(value[:19], "%Y-%m-%dT%H:%M:%S"))
        except ValueError:
            return 0.0

    def extract_error_message(self, entry: dict) -> str | None:
        if entry.get("type") != "event_msg":
            return None
        payload = entry.get("payload") or {}
        if payload.get("type") != "error":
            return None
        message = payload.get("message")
        return message if isinstance(message, str) else None

    def extract_user_message(self, entry: dict) -> str | None:
        entry_type = entry.get("type")
        payload = entry.get("payload") or {}

        if entry_type == "event_msg" and payload.get("type") == "user_message":
            message = payload.get("message")
            return message if isinstance(message, str) else None

        if entry_type != "response_item":
            return None
        if payload.get("type") != "message" or payload.get("role") != "user":
            return None

        texts: list[str] = []
        for item in payload.get("content") or []:
            if item.get("type") == "input_text" and isinstance(item.get("text"), str):
                texts.append(item["text"])
        if not texts:
            return None
        return "\n".join(texts)

    def build_error_key(self, error_message: str, raw_line: str) -> str:
        match = REQUEST_ID_RE.search(error_message)
        if match:
            return match.group(1).lower()
        return str(hash(raw_line))

    def normalize_title_key(self, value: str) -> str:
        cleaned = LEADING_STATUS_RE.sub("", value.strip()).strip().lower()
        return cleaned

    def iter_session_files(self) -> Iterable[Path]:
        return sorted(self.sessions_root.rglob("rollout-*.jsonl"))

    def log(self, message: str, verbose_only: bool = False) -> None:
        if verbose_only and not self.verbose:
            return
        timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
        text = f"[{timestamp}] {message}"
        encoding = sys.stdout.encoding or "utf-8"
        safe_text = text.encode(encoding, errors="backslashreplace").decode(encoding)
        try:
            print(safe_text, flush=True)
        except OSError:
            return


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Watch Codex session logs and inject 'continue' into the matching Codex terminal after 429 errors."
    )
    default_root = Path.home() / ".codex" / "sessions"
    parser.add_argument(
        "--sessions-root",
        type=Path,
        default=default_root,
        help=f"Codex sessions root (default: {default_root})",
    )
    parser.add_argument(
        "--poll-interval",
        type=float,
        default=2.0,
        help="Polling interval in seconds.",
    )
    parser.add_argument(
        "--cooldown-seconds",
        type=float,
        default=15.0,
        help="Minimum gap between auto-continues for the same session.",
    )
    parser.add_argument(
        "--continue-text",
        default="继续",
        help="Prompt text injected into the target terminal.",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Print actions without actually injecting anything.",
    )
    parser.add_argument(
        "--replay-recent-errors",
        action="store_true",
        help="Scan the tail of existing session files on startup and recover already-stuck sessions.",
    )
    parser.add_argument(
        "--replay-lines",
        type=int,
        default=200,
        help="How many trailing lines to inspect when --replay-recent-errors is enabled.",
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Print discovery and mapping details.",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    watcher = Codex429Watcher(
        sessions_root=args.sessions_root,
        poll_interval=args.poll_interval,
        cooldown_seconds=args.cooldown_seconds,
        continue_text=args.continue_text,
        dry_run=args.dry_run,
        replay_recent=args.replay_recent_errors,
        replay_lines=args.replay_lines,
        verbose=args.verbose,
    )
    try:
        return watcher.run()
    except KeyboardInterrupt:
        watcher.log("stopped")
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
