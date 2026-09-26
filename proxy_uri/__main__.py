"""python -m proxy_uri 'ss://...'"""
from __future__ import annotations

import sys

from proxy_uri.parse import parse_share


def main(argv: list[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    if not args:
        print("用法: python -m proxy_uri <分享链接>", file=sys.stderr)
        return 2
    try:
        print(parse_share(args[0]).format())
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
