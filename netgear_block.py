from __future__ import annotations

import argparse
import os
import sys
from collections.abc import Mapping
from pathlib import Path

from netgear_client import (
    AuthenticationError,
    ConfigError,
    NetgearClient,
    ProtocolError,
    RequestError,
    RouterConfig,
    load_profile,
    normalize_mac,
)


EXIT_OK = 0
EXIT_RUNTIME = 1
EXIT_AUTH = 2
EXIT_PROTOCOL = 3


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Change a MAC address on a Netgear access-control list.")
    parser.add_argument("mac", help="MAC address to block or unblock")
    parser.add_argument(
        "--profile",
        default="router_profile.json",
        help="Path to the router request profile JSON (default: router_profile.json)",
    )
    parser.add_argument("--timeout", type=float, default=10.0, help="HTTP timeout in seconds")
    parser.add_argument("--insecure", action="store_true", help="Disable TLS certificate verification")
    parser.add_argument("--verbose", action="store_true", help="Print progress checkpoints")
    parser.add_argument("--dry-run", action="store_true", help="Validate config and login without mutating router state")
    parser.add_argument("--unblock", action="store_true", help="Remove the MAC from the block list instead of adding it")
    return parser


def _profile_defaults(profile: Mapping[str, object]) -> dict[str, str | None]:
    login = profile.get("login")
    login_payload = login.get("payload") if isinstance(login, Mapping) else None
    if not isinstance(login_payload, Mapping):
        login_payload = {}
    return {
        "NETGEAR_HOST": _string_value(profile.get("host")),
        "NETGEAR_USERNAME": _string_value(profile.get("username")) or _string_value(login_payload.get("username")),
        "NETGEAR_PASSWORD": _string_value(profile.get("password")) or _string_value(login_payload.get("password")),
    }


def _string_value(value: object) -> str | None:
    return value if isinstance(value, str) and value else None


def config_from_sources(profile: Mapping[str, object], timeout: float, verify_tls: bool) -> RouterConfig:
    defaults = _profile_defaults(profile)
    required = {
        "NETGEAR_HOST": os.getenv("NETGEAR_HOST") or defaults["NETGEAR_HOST"],
        "NETGEAR_USERNAME": os.getenv("NETGEAR_USERNAME") or defaults["NETGEAR_USERNAME"],
        "NETGEAR_PASSWORD": os.getenv("NETGEAR_PASSWORD") or defaults["NETGEAR_PASSWORD"],
    }
    missing = [name for name, value in required.items() if not value]
    if missing:
        raise ConfigError(
            f"missing required router settings: {', '.join(missing)}; set env vars or provide them in the profile"
        )
    return RouterConfig(
        host=required["NETGEAR_HOST"],
        username=required["NETGEAR_USERNAME"],
        password=required["NETGEAR_PASSWORD"],
        timeout=timeout,
        verify_tls=verify_tls,
    )


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    try:
        normalized_mac = normalize_mac(args.mac)
        profile = load_profile(Path(args.profile))
        config = config_from_sources(profile, timeout=args.timeout, verify_tls=not args.insecure)
        client = NetgearClient(config, profile, verbose=args.verbose)

        if args.verbose:
            print(f"validated MAC {normalized_mac}", file=sys.stderr)
            print(f"using router profile {args.profile}", file=sys.stderr)

        client.login()
        if args.dry_run:
            print(f"dry-run ok {normalized_mac}")
            return EXIT_OK

        result = client.unblock_mac(normalized_mac) if args.unblock else client.block_mac(normalized_mac)
        print(f"{result.status} {result.mac}")
        return EXIT_OK
    except AuthenticationError as exc:
        print(str(exc), file=sys.stderr)
        return EXIT_AUTH
    except ProtocolError as exc:
        print(str(exc), file=sys.stderr)
        return EXIT_PROTOCOL
    except (ConfigError, RequestError) as exc:
        print(str(exc), file=sys.stderr)
        return EXIT_RUNTIME


if __name__ == "__main__":
    raise SystemExit(main())
