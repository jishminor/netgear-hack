import os
import tempfile
import unittest
from unittest import mock

from netgear_block import EXIT_AUTH, EXIT_OK, EXIT_PROTOCOL, config_from_sources, main
from netgear_client import (
    AccessControlPage,
    AuthenticationError,
    BlockResult,
    NetgearClient,
    ProtocolError,
    RouterConfig,
    SimpleResponse,
    _parse_access_control_html,
    normalize_mac,
)


class FakeSession:
    def __init__(self, responses):
        self.responses = list(responses)
        self.calls = []

    def request(self, method, url, *, headers=None, data=None, auth_override=None):
        self.calls.append(
            {
                "method": method,
                "url": url,
                "headers": headers or {},
                "data": data,
                "auth_override": auth_override,
            }
        )
        if not self.responses:
            raise AssertionError("unexpected extra request")
        return self.responses.pop(0)


def make_response(status=200, text="", url="http://router.local/ok"):
    return SimpleResponse(status_code=status, headers={}, text=text, url=url)


class NormalizeMacTests(unittest.TestCase):
    def test_normalizes_multiple_formats(self):
        self.assertEqual(normalize_mac("aa-bb-cc-dd-ee-ff"), "AA:BB:CC:DD:EE:FF")
        self.assertEqual(normalize_mac("aabbccddeeff"), "AA:BB:CC:DD:EE:FF")
        self.assertEqual(normalize_mac("AA:BB:CC:DD:EE:FF"), "AA:BB:CC:DD:EE:FF")

    def test_rejects_invalid_mac(self):
        with self.assertRaisesRegex(Exception, "invalid MAC"):
            normalize_mac("not-a-mac")


class ConfigTests(unittest.TestCase):
    def test_missing_env_vars_raise(self):
        with mock.patch.dict(os.environ, {}, clear=True):
            with self.assertRaisesRegex(Exception, "missing required router settings"):
                config_from_sources({}, timeout=5.0, verify_tls=True)

    def test_profile_fallback_supplies_missing_env_vars(self):
        profile = {
            "host": "http://192.168.1.1",
            "login": {
                "payload": {
                    "username": "admin",
                    "password": "secret",
                }
            },
        }

        with mock.patch.dict(os.environ, {}, clear=True):
            config = config_from_sources(profile, timeout=5.0, verify_tls=True)

        self.assertEqual(config.host, "http://192.168.1.1")
        self.assertEqual(config.username, "admin")
        self.assertEqual(config.password, "secret")


class ClientFlowTests(unittest.TestCase):
    def setUp(self):
        self.config = RouterConfig(
            host="http://192.168.1.1",
            username="admin",
            password="secret",
            timeout=5.0,
            verify_tls=True,
        )
        self.profile = {
            "confirm_after_block": True,
            "login": {
                "method": "POST",
                "path": "/login.cgi",
                "content_type": "form",
                "payload": {"username": "{{username}}", "password": "{{password}}"},
                "success": {"status_codes": [200], "final_url_not_regex": "login"},
            },
            "blocked_list": {
                "method": "GET",
                "path": "/blocked",
                "parser": {
                    "type": "json_path",
                    "path": "blocked",
                },
            },
            "block_action": {
                "method": "POST",
                "path": "/apply",
                "content_type": "json",
                "payload": {"blocked": "{{blocked_macs_json}}", "new_mac": "{{target_mac}}"},
                "success": {"status_codes": [200], "body_not_regex": "failed"},
            },
            "unblock_action": {
                "method": "POST",
                "path": "/apply",
                "content_type": "json",
                "payload": {"blocked": "{{blocked_macs_json}}"},
                "success": {"status_codes": [200], "body_not_regex": "failed"},
            },
        }

    def test_login_request_construction(self):
        session = FakeSession([make_response(text="ok")])
        client = NetgearClient(self.config, self.profile, session=session)

        client.login()

        self.assertEqual(session.calls[0]["method"], "POST")
        self.assertEqual(session.calls[0]["url"], "http://192.168.1.1/login.cgi")
        self.assertIn(b"username=admin", session.calls[0]["data"])

    def test_already_blocked_returns_success_without_mutation(self):
        session = FakeSession(
            [
                make_response(text="ok"),
                make_response(text='{"blocked":["AA:BB:CC:DD:EE:FF"]}'),
            ]
        )
        client = NetgearClient(self.config, self.profile, session=session)

        result = client.block_mac("AA:BB:CC:DD:EE:FF")

        self.assertEqual(result, BlockResult(status="already_blocked", mac="AA:BB:CC:DD:EE:FF"))
        self.assertEqual(len(session.calls), 2)

    def test_block_submit_path(self):
        session = FakeSession(
            [
                make_response(text="ok"),
                make_response(text='{"blocked":["11:22:33:44:55:66"]}'),
                make_response(text="updated"),
                make_response(text='{"blocked":["11:22:33:44:55:66","AA:BB:CC:DD:EE:FF"]}'),
            ]
        )
        client = NetgearClient(self.config, self.profile, session=session)

        result = client.block_mac("AA:BB:CC:DD:EE:FF")

        self.assertEqual(result.status, "blocked")
        self.assertEqual(len(session.calls), 4)
        self.assertIn(b"AA:BB:CC:DD:EE:FF", session.calls[2]["data"])

    def test_auth_failure_maps_to_exception(self):
        profile = {
            **self.profile,
            "login": {
                **self.profile["login"],
                "auth_failure": {"body_regex": "invalid password"},
            },
        }
        session = FakeSession([make_response(text="invalid password")])
        client = NetgearClient(self.config, profile, session=session)

        with self.assertRaises(AuthenticationError):
            client.login()

    def test_unexpected_router_response_raises_protocol(self):
        session = FakeSession([make_response(status=500, text="oops")])
        client = NetgearClient(self.config, self.profile, session=session)

        with self.assertRaises(ProtocolError):
            client.login()

    def test_replace_list_payload_preserves_existing_macs(self):
        session = FakeSession(
            [
                make_response(text="ok"),
                make_response(text='{"blocked":["11:22:33:44:55:66"]}'),
                make_response(text="updated"),
                make_response(text='{"blocked":["11:22:33:44:55:66","AA:BB:CC:DD:EE:FF"]}'),
            ]
        )
        client = NetgearClient(self.config, self.profile, session=session)

        client.block_mac("AA:BB:CC:DD:EE:FF")

        self.assertIn(b"11:22:33:44:55:66", session.calls[2]["data"])
        self.assertIn(b"AA:BB:CC:DD:EE:FF", session.calls[2]["data"])

    def test_redirect_away_from_login_is_accepted(self):
        session = FakeSession([make_response(text="ok", url="http://192.168.1.1/start.htm")])
        client = NetgearClient(self.config, self.profile, session=session)

        client.login()

        self.assertEqual(len(session.calls), 1)

    def test_basic_auth_bootstrap_first(self):
        profile = {
            **self.profile,
            "login": {
                "auth": "basic",
                "bootstrap_first": True,
                "method": "GET",
                "path": "/start.htm",
                "success": {"status_codes": [200], "body_regex": "NETGEAR Router"},
                "auth_failure": {"status_codes": [401]},
            },
        }
        session = FakeSession(
            [
                make_response(status=401, text="unauthorized", url="http://192.168.1.1/start.htm"),
                make_response(status=200, text="NETGEAR Router", url="http://192.168.1.1/start.htm"),
            ]
        )
        client = NetgearClient(self.config, profile, session=session)

        client.login()

        self.assertEqual(len(session.calls), 2)
        self.assertIs(session.calls[0]["auth_override"], False)
        self.assertIsNone(session.calls[1]["auth_override"])

    def test_unblock_returns_already_when_missing(self):
        session = FakeSession(
            [
                make_response(text="ok"),
                make_response(text='{"blocked":["11:22:33:44:55:66"]}'),
            ]
        )
        client = NetgearClient(self.config, self.profile, session=session)

        result = client.unblock_mac("AA:BB:CC:DD:EE:FF")

        self.assertEqual(result, BlockResult(status="already_unblocked", mac="AA:BB:CC:DD:EE:FF"))
        self.assertEqual(len(session.calls), 2)


class HtmlAclTests(unittest.TestCase):
    def setUp(self):
        self.config = RouterConfig(
            host="http://192.168.1.1",
            username="admin",
            password="secret",
            timeout=5.0,
            verify_tls=True,
        )
        self.profile = {
            "confirm_after_block": True,
            "login": {
                "auth": "basic",
                "bootstrap_first": True,
                "method": "GET",
                "path": "/start.htm",
                "success": {"status_codes": [200], "body_regex": "NETGEAR Router"},
                "auth_failure": {"status_codes": [401]},
            },
            "blocked_list": {
                "method": "GET",
                "path": "/DEV_control.htm",
                "parser": {"type": "html_acl"},
            },
            "block_action": {
                "method": "POST",
                "content_type": "form",
                "headers": {
                    "Referer": "{{host}}/DEV_control.htm",
                    "Origin": "{{host}}",
                },
                "success": {"status_codes": [200]},
            },
            "unblock_action": {
                "method": "POST",
                "content_type": "form",
                "headers": {
                    "Referer": "{{host}}/DEV_control.htm",
                    "Origin": "{{host}}",
                },
                "success": {"status_codes": [200]},
            },
        }
        self.page_allow = make_response(
            text="""
<form id="target" name="frmLan" method="POST" action="access_control.cgi?id=token">
<tr name="row_rules">
  <td><span name="rule_status" class="acl_allowed">Allowed</span></td>
  <td><span name="rule_ip">192.168.1.25</span></td>
  <td><span name="rule_mac" class="">0C:91:60:03:4F:84</span><input type="hidden" name="rule_status_org" value="allow"></td>
</tr>
<tr name="row_rules">
  <td><span name="rule_status" class="acl_allowed">Allowed</span></td>
  <td><span name="rule_ip">192.168.1.30</span></td>
  <td><span name="rule_mac" class="">AA:BB:CC:DD:EE:FF</span><input type="hidden" name="rule_status_org" value="allow"></td>
</tr>
<input name="enable_access_control" type="hidden" value= "0">
<input name="access_all_setting" type="hidden" value= "1">
<input name="allowed_text" type="hidden" value= "Allowed">
<input name="blocked_text" type="hidden" value= "Blocked">
<input name="router_access_user" type="hidden" value= "192.168.1.153">
<input name="spc_provisioned" type="hidden" value= "">
<input name="enable_ap_mode" type="hidden" value= "0">
<input name="delete_white_lists" type="hidden" value="">
<input name="delete_black_lists" type="hidden" value="">
<input name="edit_lists" type="hidden" value="">
<input name="edit_device_name" type="hidden" value="">
<input type="hidden" name="buttonHit"><input type="hidden" name="buttonValue">
</form>
""",
            url="http://192.168.1.1/DEV_control.htm",
        )
        self.page_blocked = make_response(
            text=self.page_allow.text.replace('value="allow"></td>', 'value="block"></td>', 1).replace(
                'class="acl_allowed">Allowed', 'class="acl_blocked">Blocked', 1
            ),
            url="http://192.168.1.1/access_control.cgi?id=token",
        )
        self.page_blacklist_only = make_response(
            text=self.page_allow.text.replace("0C:91:60:03:4F:84", "11:22:33:44:55:66", 1)
            + '<span name="rule_mac_black" class="">0C:91:60:03:4F:84</span>',
            url="http://192.168.1.1/DEV_control.htm",
        )

    def test_parse_acl_page(self):
        page = _parse_access_control_html(self.page_allow)
        self.assertEqual(page.action_url, "http://192.168.1.1/access_control.cgi?id=token")
        self.assertEqual(page.connected_devices[0].mac, "0C:91:60:03:4F:84")
        self.assertEqual(page.blocked_macs, set())

    def test_block_connected_device_posts_acl_form(self):
        session = FakeSession(
            [
                make_response(status=401, text="unauthorized", url="http://192.168.1.1/start.htm"),
                make_response(text="NETGEAR Router", url="http://192.168.1.1/start.htm"),
                self.page_allow,
                self.page_blocked,
                self.page_blocked,
            ]
        )
        client = NetgearClient(self.config, self.profile, session=session)

        result = client.block_mac("0C:91:60:03:4F:84")

        self.assertEqual(result, BlockResult(status="blocked", mac="0C:91:60:03:4F:84"))
        post_body = session.calls[3]["data"].decode("utf-8")
        self.assertIn("block=block", post_body)
        self.assertIn("rule_settings=2%3A0C%3A91%3A60%3A03%3A4F%3A84%3A0%3AAA%3ABB%3ACC%3ADD%3AEE%3AFF%3A1%3A", post_body)

    def test_unblock_connected_device_posts_allow(self):
        session = FakeSession(
            [
                make_response(status=401, text="unauthorized", url="http://192.168.1.1/start.htm"),
                make_response(text="NETGEAR Router", url="http://192.168.1.1/start.htm"),
                self.page_blocked,
                self.page_allow,
                self.page_allow,
            ]
        )
        client = NetgearClient(self.config, self.profile, session=session)

        result = client.unblock_mac("0C:91:60:03:4F:84")

        self.assertEqual(result, BlockResult(status="unblocked", mac="0C:91:60:03:4F:84"))
        post_body = session.calls[3]["data"].decode("utf-8")
        self.assertIn("allow=allow", post_body)

    def test_unblock_blacklist_only_uses_delete_black(self):
        session = FakeSession(
            [
                make_response(status=401, text="unauthorized", url="http://192.168.1.1/start.htm"),
                make_response(text="NETGEAR Router", url="http://192.168.1.1/start.htm"),
                self.page_blacklist_only,
                self.page_allow,
                self.page_allow,
            ]
        )
        client = NetgearClient(self.config, self.profile, session=session)

        result = client.unblock_mac("0C:91:60:03:4F:84")

        self.assertEqual(result, BlockResult(status="unblocked", mac="0C:91:60:03:4F:84"))
        post_body = session.calls[3]["data"].decode("utf-8")
        self.assertIn("delete_black=Delete", post_body)
        self.assertIn("delete_black_lists=1%3A0C%3A91%3A60%3A03%3A4F%3A84%3A", post_body)


class CliTests(unittest.TestCase):
    def test_main_auth_exit_code(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            profile_path = os.path.join(tmpdir, "router_profile.json")
            with open(profile_path, "w", encoding="utf-8") as handle:
                handle.write(
                    '{"login":{"method":"POST","path":"/login.cgi","auth_failure":{"body_regex":"bad"}},"block_action":{"method":"POST","path":"/apply"}}'
                )
            with mock.patch.dict(
                os.environ,
                {
                    "NETGEAR_HOST": "http://192.168.1.1",
                    "NETGEAR_USERNAME": "admin",
                    "NETGEAR_PASSWORD": "secret",
                },
                clear=True,
            ):
                with mock.patch("netgear_client.UrlLibSession.request", return_value=make_response(text="bad")):
                    self.assertEqual(main(["AA:BB:CC:DD:EE:FF", "--profile", profile_path]), EXIT_AUTH)

    def test_main_protocol_exit_code(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            profile_path = os.path.join(tmpdir, "router_profile.json")
            with open(profile_path, "w", encoding="utf-8") as handle:
                handle.write(
                    '{"login":{"method":"POST","path":"/login.cgi","success":{"status_codes":[200], "body_regex":"expected"}},"block_action":{"method":"POST","path":"/apply"}}'
                )
            with mock.patch.dict(
                os.environ,
                {
                    "NETGEAR_HOST": "http://192.168.1.1",
                    "NETGEAR_USERNAME": "admin",
                    "NETGEAR_PASSWORD": "secret",
                },
                clear=True,
            ):
                with mock.patch("netgear_client.UrlLibSession.request", return_value=make_response(text="mismatch")):
                    self.assertEqual(main(["AA:BB:CC:DD:EE:FF", "--profile", profile_path]), EXIT_PROTOCOL)

    def test_main_dry_run(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            profile_path = os.path.join(tmpdir, "router_profile.json")
            with open(profile_path, "w", encoding="utf-8") as handle:
                handle.write(
                    '{"login":{"method":"POST","path":"/login.cgi","success":{"status_codes":[200]}},"block_action":{"method":"POST","path":"/apply"}}'
                )
            with mock.patch.dict(
                os.environ,
                {
                    "NETGEAR_HOST": "http://192.168.1.1",
                    "NETGEAR_USERNAME": "admin",
                    "NETGEAR_PASSWORD": "secret",
                },
                clear=True,
            ):
                with mock.patch("netgear_client.UrlLibSession.request", return_value=make_response(text="ok")):
                    self.assertEqual(main(["AA:BB:CC:DD:EE:FF", "--profile", profile_path, "--dry-run"]), EXIT_OK)


if __name__ == "__main__":
    unittest.main()
