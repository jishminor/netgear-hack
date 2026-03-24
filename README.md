# Netgear RAX43v2 MAC Block CLI

This project provides a small Python CLI that logs into a Netgear router and changes a MAC address on the access-control list. The current profile and client logic are wired for the Netgear RAX43v2 firmware flow captured from the admin UI.

## Prerequisites

- `uv`
- Local network access to the router
- Admin credentials for the router
- A request profile derived from browser devtools capture

The implementation uses only the Python standard library, and `uv` manages the interpreter and project commands.

## Files

- `netgear_block.py`: CLI entrypoint
- `netgear_client.py`: router client and request-profile handling
- `router_profile.example.json`: example profile shape to adapt to your firmware
- `tests/`: unit tests

## Required environment variables

- `NETGEAR_HOST`
- `NETGEAR_USERNAME`
- `NETGEAR_PASSWORD`

If those environment variables are absent, the CLI will also fall back to top-level `host`, `username`, and `password` fields in `router_profile.json`. For compatibility with early captures, it also accepts credentials embedded under `login.payload.username` and `login.payload.password`.

Example:

```bash
export NETGEAR_HOST=http://192.168.1.1
export NETGEAR_USERNAME=admin
export NETGEAR_PASSWORD='your-router-password'
```

## CLI usage

Block a MAC:

```bash
uv run netgear-block AA:BB:CC:DD:EE:FF --profile router_profile.json
```

Unblock a MAC:

```bash
uv run netgear-block AA:BB:CC:DD:EE:FF --profile router_profile.json --unblock
```

Dry run:

```bash
uv run netgear-block AA:BB:CC:DD:EE:FF --profile router_profile.json --dry-run
```

Optional flags:

- `--timeout <seconds>`
- `--insecure`
- `--verbose`
- `--dry-run`
- `--profile <path>`
- `--unblock`

## Exit codes

- `0`: blocked/unblocked successfully or already in the requested state
- `1`: validation, configuration, or network/runtime error
- `2`: authentication failure
- `3`: router protocol mismatch or unsupported firmware behavior

## Discovery workflow

The current implementation targets the RAX43v2 access-control flow observed from browser network capture:

- Basic auth to the router host
- ACL page at `DEV_control.htm`
- Mutation submit to `access_control.cgi?...`

If your firmware differs, capture a fresh HAR or request trace and update the profile/client accordingly.

1. Log into the Netgear admin UI manually.
2. Open browser devtools and go to the Network tab.
3. Clear the request list.
4. Perform the exact UI action that adds a test MAC to the blocked list.
5. Record:
   - the login request URL, method, headers, and form body
   - any cookies or anti-CSRF fields that appear after login
   - the page or endpoint that shows the current blocked MAC list
   - the submit endpoint that adds or updates blocked MACs
   - whether the router appends a MAC or expects the full list to be resubmitted
   - the response pattern that indicates success or auth failure
6. Redact your password.
7. Copy `router_profile.example.json` to `router_profile.json` and replace the credentials with your own values.

For convenience, you can also place static defaults at the top level of `router_profile.json`:

```json
{
  "host": "http://192.168.1.1",
  "username": "admin",
  "password": "your-router-password"
}
```

### Profile format

The request profile has four main sections:

- `login`: how to authenticate
- `blocked_list`: how to fetch current blocked MACs
- `block_action`: how to submit the mutation
- `unblock_action`: how to remove a blocked MAC

Placeholders supported in payloads and headers:

- `{{host}}`
- `{{username}}`
- `{{password}}`
- `{{target_mac}}`
- `{{blocked_macs_csv}}`
- `{{blocked_macs_newline}}`
- `{{blocked_macs_json}}`

Supported parser types for `blocked_list.parser`:

- `regex`
- `json_path`
- `html_acl`

Supported content types:

- `form`
- `json`
- `raw`

## Development

Run the test suite:

```bash
uv run python -m unittest discover -s tests -v
```

## Home Assistant example

This is designed to be called as a shell command.

```yaml
shell_command:
  block_device_mac: >-
    /usr/bin/env
    NETGEAR_HOST=http://192.168.1.1
    NETGEAR_USERNAME=admin
    NETGEAR_PASSWORD=!secret netgear_password
    /usr/bin/env uv run --directory /config/netgear-hack netgear-block {{ mac }}
```

A practical deployment is to keep the script and `router_profile.json` in a location Home Assistant can access, then call it from an automation or script with a `mac` variable.

## Home Assistant add-on

This repo also includes a custom Home Assistant add-on in [netgear-hack-addon](/Users/joshminor/code/netgear-hack/netgear-hack-addon).

To use it:

1. Add this GitHub repo as a custom add-on repository in Home Assistant.
2. Install the `Netgear Hack` add-on.
3. Fill in the add-on options with your router host, username, and password.
4. Start the add-on.
5. Call its HTTP API from Home Assistant using `rest_command`.

See [DOCS.md](/Users/joshminor/code/netgear-hack/netgear-hack-addon/DOCS.md) for the addon API and `rest_command` examples.

## Notes

- Firmware behavior varies across Netgear models and versions.
- The checked-in `router_profile.json` is currently tailored to this router's `DEV_control.htm` flow.
