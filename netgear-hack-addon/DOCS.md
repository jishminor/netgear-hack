# Netgear Hack Add-on

This add-on exposes a small HTTP API that blocks and unblocks MAC addresses on a Netgear RAX43v2 router.

## Installation

1. Add this GitHub repository as a custom add-on repository in Home Assistant.
2. Install the `Netgear Hack` add-on.
3. Configure the router credentials and host.
4. Start the add-on.
5. Check the add-on logs and verify `GET /health` returns `{"status":"ok"}`.

## Configuration

```yaml
host: http://192.168.1.1
username: admin
password: your-router-password
timeout: 30
verify_tls: true
api_token: ""
```

### Options

- `host`: Router base URL
- `username`: Router admin username
- `password`: Router admin password
- `timeout`: Request timeout in seconds
- `verify_tls`: Verify TLS certificates for HTTPS routers
- `api_token`: Optional bearer token for the addon API

## API

The add-on listens on port `8099`.

### Health check

```bash
curl http://HOME_ASSISTANT_HOST:8099/health
```

### Block a device

```bash
curl -X POST http://HOME_ASSISTANT_HOST:8099/block \
  -H 'Content-Type: application/json' \
  -d '{"mac":"0C:91:60:03:4F:84"}'
```

### Unblock a device

```bash
curl -X POST http://HOME_ASSISTANT_HOST:8099/unblock \
  -H 'Content-Type: application/json' \
  -d '{"mac":"0C:91:60:03:4F:84"}'
```

If `api_token` is set, include:

```bash
-H 'Authorization: Bearer YOUR_TOKEN'
```

## Home Assistant example

Add this to `configuration.yaml`:

```yaml
rest_command:
  netgear_block_mac:
    url: "http://HOME_ASSISTANT_HOST:8099/block"
    method: POST
    content_type: "application/json"
    payload: '{"mac":"{{ mac }}"}'

  netgear_unblock_mac:
    url: "http://HOME_ASSISTANT_HOST:8099/unblock"
    method: POST
    content_type: "application/json"
    payload: '{"mac":"{{ mac }}"}'
```

Then call those `rest_command` services from scripts or automations.

## Notes

- The add-on uses `host_network: true` so it can reach the router directly on the LAN.
- `api_token` is optional but recommended if anything outside Home Assistant might be able to reach port `8099`.
