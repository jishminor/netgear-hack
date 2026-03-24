# Netgear Hack Add-on

This add-on exposes a small HTTP API that blocks and unblocks MAC addresses on a Netgear RAX43v2 router.

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
