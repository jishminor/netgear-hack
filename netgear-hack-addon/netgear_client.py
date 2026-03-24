from __future__ import annotations

import json
import re
import socket
import ssl
from base64 import b64encode
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from http.cookiejar import CookieJar
from pathlib import Path
from typing import Any, Mapping


class NetgearError(Exception):
    pass


class ConfigError(NetgearError):
    pass


class AuthenticationError(NetgearError):
    pass


class ProtocolError(NetgearError):
    pass


class RequestError(NetgearError):
    pass


@dataclass(frozen=True)
class RouterConfig:
    host: str
    username: str
    password: str
    timeout: float
    verify_tls: bool


@dataclass(frozen=True)
class BlockResult:
    status: str
    mac: str


@dataclass(frozen=True)
class SimpleResponse:
    status_code: int
    headers: Mapping[str, str]
    text: str
    url: str


@dataclass(frozen=True)
class AccessControlDevice:
    mac: str
    status: str
    ip: str


@dataclass(frozen=True)
class AccessControlPage:
    action_url: str
    connected_devices: tuple[AccessControlDevice, ...]
    black_list_macs: tuple[str, ...]
    hidden_fields: Mapping[str, str]


def normalize_mac(value: str) -> str:
    cleaned = re.sub(r"[^0-9A-Fa-f]", "", value)
    if len(cleaned) != 12 or not re.fullmatch(r"[0-9A-Fa-f]{12}", cleaned):
        raise ConfigError(f"invalid MAC address: {value}")
    upper = cleaned.upper()
    return ":".join(upper[index : index + 2] for index in range(0, 12, 2))


def load_profile(path: str | Path) -> dict[str, Any]:
    profile_path = Path(path)
    if not profile_path.exists():
        raise ConfigError(f"profile file not found: {profile_path}")
    try:
        data = json.loads(profile_path.read_text())
    except json.JSONDecodeError as exc:
        raise ConfigError(f"invalid profile JSON: {exc}") from exc
    for key in ("login", "block_action"):
        if key not in data:
            raise ConfigError(f"profile missing required section: {key}")
    return data


def _json_path_lookup(payload: Any, path: str) -> Any:
    current = payload
    for part in path.split("."):
        if isinstance(current, list):
            try:
                current = current[int(part)]
            except (ValueError, IndexError) as exc:
                raise ProtocolError(f"JSON path not found: {path}") from exc
        elif isinstance(current, dict) and part in current:
            current = current[part]
        else:
            raise ProtocolError(f"JSON path not found: {path}")
    return current


def _render_value(value: Any, context: Mapping[str, Any]) -> Any:
    if isinstance(value, str):
        rendered = value
        for key, replacement in context.items():
            rendered = rendered.replace(f"{{{{{key}}}}}", str(replacement))
        return rendered
    if isinstance(value, list):
        return [_render_value(item, context) for item in value]
    if isinstance(value, dict):
        return {key: _render_value(item, context) for key, item in value.items()}
    return value


def _match_rule(response: SimpleResponse, rule: Mapping[str, Any]) -> bool:
    if not rule:
        return True
    status_codes = rule.get("status_codes")
    if status_codes and response.status_code not in status_codes:
        return False
    body_regex = rule.get("body_regex")
    if body_regex and not re.search(body_regex, response.text, re.IGNORECASE | re.MULTILINE):
        return False
    body_not_regex = rule.get("body_not_regex")
    if body_not_regex and re.search(body_not_regex, response.text, re.IGNORECASE | re.MULTILINE):
        return False
    final_url_regex = rule.get("final_url_regex")
    if final_url_regex and not re.search(final_url_regex, response.url, re.IGNORECASE):
        return False
    final_url_not_regex = rule.get("final_url_not_regex")
    if final_url_not_regex and re.search(final_url_not_regex, response.url, re.IGNORECASE):
        return False
    return True


def _extract_macs(response: SimpleResponse, parser: Mapping[str, Any]) -> set[str]:
    parser_type = parser.get("type")
    if parser_type == "regex":
        pattern = parser.get("pattern")
        if not pattern:
            raise ProtocolError("regex parser requires pattern")
        matches = re.findall(pattern, response.text, re.IGNORECASE | re.MULTILINE)
        values: list[str] = []
        for match in matches:
            values.append(match[0] if isinstance(match, tuple) else match)
        return {normalize_mac(value) for value in values}
    if parser_type == "json_path":
        path = parser.get("path")
        if not path:
            raise ProtocolError("json_path parser requires path")
        try:
            payload = json.loads(response.text)
        except json.JSONDecodeError as exc:
            raise ProtocolError("response body was not valid JSON") from exc
        values = _json_path_lookup(payload, path)
        if not isinstance(values, list):
            raise ProtocolError("json_path parser expected a list")
        return {normalize_mac(value) for value in values}
    raise ProtocolError(f"unsupported parser type: {parser_type}")


class UrlLibSession:
    def __init__(self, timeout: float, verify_tls: bool, basic_auth: tuple[str, str] | None = None):
        context = ssl.create_default_context()
        if not verify_tls:
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
        self._timeout = timeout
        self._basic_auth = basic_auth
        self._opener = urllib.request.build_opener(
            urllib.request.HTTPCookieProcessor(CookieJar()),
            urllib.request.HTTPSHandler(context=context),
        )

    def request(
        self,
        method: str,
        url: str,
        *,
        headers: Mapping[str, str] | None = None,
        data: bytes | None = None,
        auth_override: tuple[str, str] | bool | None = None,
    ) -> SimpleResponse:
        request_headers = dict(headers or {})
        auth = self._basic_auth if auth_override is None else None if auth_override is False else auth_override
        if auth and "Authorization" not in request_headers:
            username, password = auth
            token = b64encode(f"{username}:{password}".encode("utf-8")).decode("ascii")
            request_headers["Authorization"] = f"Basic {token}"
        request = urllib.request.Request(url=url, data=data, headers=request_headers, method=method.upper())
        try:
            with self._opener.open(request, timeout=self._timeout) as response:
                return SimpleResponse(
                    status_code=response.getcode(),
                    headers=dict(response.headers.items()),
                    text=response.read().decode("utf-8", errors="replace"),
                    url=response.geturl(),
                )
        except urllib.error.HTTPError as exc:
            return SimpleResponse(
                status_code=exc.code,
                headers=dict(exc.headers.items()),
                text=exc.read().decode("utf-8", errors="replace"),
                url=exc.geturl(),
            )
        except urllib.error.URLError as exc:
            raise RequestError(str(exc.reason)) from exc
        except (TimeoutError, socket.timeout) as exc:
            raise RequestError("router request timed out") from exc


class NetgearClient:
    def __init__(self, config: RouterConfig, profile: Mapping[str, Any], *, session: UrlLibSession | Any | None = None, verbose: bool = False):
        self.config = config
        self.profile = profile
        basic_auth = None
        if self.profile.get("login", {}).get("auth") == "basic":
            basic_auth = (config.username, config.password)
        self.session = session or UrlLibSession(timeout=config.timeout, verify_tls=config.verify_tls, basic_auth=basic_auth)
        self.verbose = verbose
        self._logged_in = False

    def login(self) -> None:
        login_spec = self.profile["login"]
        if login_spec.get("auth") == "basic" and login_spec.get("bootstrap_first"):
            self._bootstrap_basic_auth(login_spec)
        response = self._send_profile_request(login_spec, {})
        failure_rule = login_spec.get("auth_failure")
        if failure_rule and _match_rule(response, failure_rule):
            raise AuthenticationError("router rejected credentials")
        success_rule = login_spec.get("success")
        if success_rule and not _match_rule(response, success_rule):
            raise ProtocolError("login response did not match profile expectations")
        self._logged_in = True

    def _bootstrap_basic_auth(self, login_spec: Mapping[str, Any]) -> None:
        path = login_spec.get("bootstrap_path") or login_spec.get("path")
        if not path:
            raise ProtocolError("login bootstrap path missing from profile")
        url = urllib.parse.urljoin(f"{self.config.host.rstrip('/')}/", str(path).lstrip("/"))
        headers = _render_value(login_spec.get("bootstrap_headers", login_spec.get("headers", {})), {"host": self.config.host.rstrip("/")})
        self.session.request(str(login_spec.get("method", "GET")), url, headers=headers, auth_override=False)

    def get_blocked_macs(self) -> set[str]:
        if "blocked_list" not in self.profile:
            return set()
        response = self._send_profile_request(self.profile["blocked_list"], {})
        failure_rule = self.profile["blocked_list"].get("failure")
        if failure_rule and _match_rule(response, failure_rule):
            raise ProtocolError("router reported blocked-list retrieval failure")
        parser = self.profile["blocked_list"].get("parser")
        if not parser:
            raise ProtocolError("blocked_list parser missing from profile")
        if parser.get("type") == "html_acl":
            return self._fetch_access_control_page(response).blocked_macs
        return _extract_macs(response, parser)

    def block_mac(self, mac: str) -> BlockResult:
        return self._set_mac_block_state(mac, blocked=True)

    def unblock_mac(self, mac: str) -> BlockResult:
        return self._set_mac_block_state(mac, blocked=False)

    def _set_mac_block_state(self, mac: str, *, blocked: bool) -> BlockResult:
        normalized = normalize_mac(mac)
        if not self._logged_in:
            self.login()

        parser = self.profile.get("blocked_list", {}).get("parser", {})
        if parser.get("type") == "html_acl":
            page = self._fetch_access_control_page()
            return self._submit_acl_page_update(page, normalized, blocked=blocked)

        blocked_macs = self.get_blocked_macs()
        if blocked and normalized in blocked_macs:
            return BlockResult(status="already_blocked", mac=normalized)
        if not blocked and normalized not in blocked_macs:
            return BlockResult(status="already_unblocked", mac=normalized)

        request_spec = self.profile["block_action" if blocked else "unblock_action"]
        response = self._send_profile_request(request_spec, {})
        self._validate_action_response(response, request_spec, "router rejected access-control update")
        return BlockResult(status="blocked" if blocked else "unblocked", mac=normalized)

    def _validate_action_response(self, response: SimpleResponse, request_spec: Mapping[str, Any], failure_message: str) -> None:
        failure_rule = request_spec.get("failure")
        if failure_rule and _match_rule(response, failure_rule):
            raise ProtocolError(failure_message)
        success_rule = request_spec.get("success")
        if success_rule and not _match_rule(response, success_rule):
            raise ProtocolError("request did not match profile expectations")

    def _fetch_access_control_page(self, response: SimpleResponse | None = None) -> AccessControlPage:
        source = response or self._send_profile_request(self.profile["blocked_list"], {})
        return _parse_access_control_html(source)

    def _submit_acl_page_update(self, page: AccessControlPage, target_mac: str, *, blocked: bool) -> BlockResult:
        connected = list(page.connected_devices)
        target_device = next((device for device in connected if device.mac == target_mac), None)
        black_list = set(page.black_list_macs)
        action_name = "block" if blocked else "allow"

        if blocked and target_mac in black_list:
            return BlockResult(status="already_blocked", mac=target_mac)
        if not blocked and target_device is None and target_mac not in black_list:
            return BlockResult(status="already_unblocked", mac=target_mac)

        if target_device is not None:
            router_user = page.hidden_fields.get("router_access_user", "")
            if blocked and router_user and target_device.ip == router_user:
                raise ProtocolError("cannot block the device currently administering the router")

            updated_devices = [
                AccessControlDevice(
                    mac=device.mac,
                    status="block" if device.mac == target_mac and blocked else "allow" if device.mac == target_mac else device.status,
                    ip=device.ip,
                )
                for device in connected
            ]
            response = self._send_profile_request(
                self.profile["block_action" if blocked else "unblock_action"],
                self._acl_payload_context(page, updated_devices, action_name=action_name),
                absolute_url=page.action_url,
                pre_rendered=True,
            )
            self._validate_action_response(response, self.profile["block_action" if blocked else "unblock_action"], "router rejected ACL update")
        else:
            delete_payload = {
                **page.hidden_fields,
                "delete_white_lists": "",
                "delete_black_lists": f"1:{target_mac}:",
                "edit_lists": "",
                "edit_device_name": "",
                "buttonHit": "delete_black",
                "buttonValue": "Delete",
                "delete_black": "Delete",
            }
            response = self._send_profile_request(self.profile["unblock_action"], delete_payload, absolute_url=page.action_url, pre_rendered=True)
            self._validate_action_response(response, self.profile["unblock_action"], "router rejected ACL update")

        confirmed = self._fetch_access_control_page()
        is_blocked = target_mac in confirmed.blocked_macs
        if is_blocked != blocked:
            raise ProtocolError("router accepted request but MAC state did not update")
        return BlockResult(status="blocked" if blocked else "unblocked", mac=target_mac)

    def _acl_payload_context(self, page: AccessControlPage, devices: list[AccessControlDevice], *, action_name: str) -> dict[str, Any]:
        access_all = "allow_all" if page.hidden_fields.get("access_all_setting", "1") == "1" else "block_all"
        rule_status_org = [device.status for device in devices]
        rule_settings = f"{len(devices)}:" + "".join(f"{device.mac}:{1 if device.status == 'allow' else 0}:" for device in devices)
        return {
            action_name: action_name,
            "enable_acl": "enable_acl",
            "access_all": access_all,
            "select": "-1",
            "rule_status_org": rule_status_org,
            **page.hidden_fields,
            "rule_settings": rule_settings,
            "delete_white_lists": "",
            "delete_black_lists": "",
            "edit_lists": "",
            "edit_device_name": "",
            "buttonHit": action_name,
            "buttonValue": action_name,
        }

    def _send_profile_request(
        self,
        request_spec: Mapping[str, Any],
        context: Mapping[str, Any],
        *,
        absolute_url: str | None = None,
        pre_rendered: bool = False,
    ) -> SimpleResponse:
        merged_context = {
            "host": self.config.host.rstrip("/"),
            "username": self.config.username,
            "password": self.config.password,
            **context,
        }
        if absolute_url:
            url = absolute_url
        else:
            path = request_spec.get("path")
            if not path:
                raise ProtocolError("request spec missing path")
            url = urllib.parse.urljoin(f"{self.config.host.rstrip('/')}/", str(path).lstrip("/"))
        method = request_spec.get("method", "GET")
        headers = _render_value(request_spec.get("headers", {}), merged_context)
        payload = context if pre_rendered else _render_value(request_spec.get("payload"), merged_context)
        data = self._encode_payload(request_spec.get("content_type", "form"), payload, headers)
        return self.session.request(method, url, headers=headers, data=data)

    @staticmethod
    def _encode_payload(content_type: str, payload: Any, headers: Mapping[str, str]) -> bytes | None:
        if payload is None:
            return None
        if content_type == "form":
            if not isinstance(payload, Mapping):
                raise ProtocolError("form payload must be an object")
            if "Content-Type" not in headers:
                headers["Content-Type"] = "application/x-www-form-urlencoded"
            return urllib.parse.urlencode(payload, doseq=True).encode("utf-8")
        if content_type == "json":
            if "Content-Type" not in headers:
                headers["Content-Type"] = "application/json"
            return json.dumps(payload).encode("utf-8")
        if content_type == "raw":
            if isinstance(payload, bytes):
                return payload
            return str(payload).encode("utf-8")
        raise ProtocolError(f"unsupported content type: {content_type}")


def _parse_access_control_html(response: SimpleResponse) -> AccessControlPage:
    html = response.text
    action_match = re.search(r'<form[^>]+id="target"[^>]+action="([^"]+)"', html)
    if not action_match:
        raise ProtocolError("access control form action not found")
    action_url = urllib.parse.urljoin(response.url, action_match.group(1))
    row_pattern = re.compile(
        r'<tr name="row_rules">.*?<span name="rule_status" class="acl_(allowed|blocked)">.*?</span>.*?'
        r'<span name="rule_ip">([^<]*)</span>.*?'
        r'<span name="rule_mac" class="">([^<]+)</span><input type="hidden" name="rule_status_org" value="([^"]+)"',
        re.DOTALL,
    )
    connected_devices = tuple(
        AccessControlDevice(mac=normalize_mac(mac), status=status_org.strip().lower(), ip=ip.strip())
        for _, ip, mac, status_org in row_pattern.findall(html)
    )
    if not connected_devices:
        raise ProtocolError("access control page did not contain connected devices")
    black_list_macs = tuple(normalize_mac(mac) for mac in re.findall(r'<span name="rule_mac_black" class="">([^<]+)</span>', html))
    hidden_fields = {
        name: value
        for name, value in re.findall(r'<input name="([^"]+)" type="hidden" value= "([^"]*)">', html)
        if name
    }
    return AccessControlPage(action_url=action_url, connected_devices=connected_devices, black_list_macs=black_list_macs, hidden_fields=hidden_fields)


def _blocked_macs(page: AccessControlPage) -> set[str]:
    return {device.mac for device in page.connected_devices if device.status == "block"} | set(page.black_list_macs)


AccessControlPage.blocked_macs = property(_blocked_macs)
