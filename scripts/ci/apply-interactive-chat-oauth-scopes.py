#!/usr/bin/env python3
from pathlib import Path


def replace_exact(path: str, old: str, new: str, expected: int = 1) -> None:
    file = Path(path)
    text = file.read_text(encoding="utf-8")
    count = text.count(old)
    if count != expected:
        raise SystemExit(f"{path}: expected {expected} matches, found {count}")
    file.write_text(text.replace(old, new), encoding="utf-8")


replace_exact(
    "internal/config/config.go",
    '"channel:read:redemptions",\n\t"user:read:emotes",\n',
    '"channel:read:redemptions",\n\t"channel:manage:polls",\n\t"channel:manage:predictions",\n\t"user:read:emotes",\n',
)
replace_exact(
    "internal/config/config_auth_test.go",
    '"moderator:manage:chat_messages",\n\t} {\n',
    '"moderator:manage:chat_messages",\n\t\t"channel:manage:polls",\n\t\t"channel:manage:predictions",\n\t} {\n',
)

print("Interactive chat OAuth scopes patch applied successfully")
