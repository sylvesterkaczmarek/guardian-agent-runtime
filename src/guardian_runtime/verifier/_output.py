from __future__ import annotations


def print_result(message: str) -> None:
    """Keep untrusted file names and error details inert in terminal output."""

    print("".join(character if character.isprintable() else ascii(character)[1:-1] for character in message))
