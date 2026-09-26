import base64
import json
import unittest

from proxy_uri.parse import parse_share


def b64(text: str) -> str:
    return base64.urlsafe_b64encode(text.encode()).decode().rstrip("=")


class ParseTest(unittest.TestCase):
    def test_ss_legacy(self) -> None:
        link = "ss://" + b64("aes-256-gcm:s3cret-token@example.com:443") + "#home"
        got = parse_share(link)
        self.assertEqual((got.scheme, got.host, got.port, got.name), ("ss", "example.com", 443, "home"))
        self.assertNotIn("s3cret-token", got.format())

    def test_ss_sip002(self) -> None:
        user = b64("aes-256-gcm:secret")
        got = parse_share(f"ss://{user}@example.com:8443")
        self.assertEqual(got.port, 8443)
        self.assertTrue(got.userinfo_set)

    def test_vmess(self) -> None:
        payload = b64(json.dumps({"add": "example.com", "port": "443", "id": "abc", "ps": "node"}))
        got = parse_share("vmess://" + payload)
        self.assertEqual(got.name, "node")
        self.assertEqual(got.host, "example.com")
        self.assertNotIn("abc", got.format())

    def test_trojan_and_hy2(self) -> None:
        trojan = parse_share("trojan://secret@example.com:443#office")
        hy2 = parse_share("hy2://secret@example.com:443/?name=edge")
        self.assertEqual(trojan.name, "office")
        self.assertEqual(hy2.scheme, "hysteria2")
        self.assertEqual(hy2.name, "edge")

    def test_reject(self) -> None:
        with self.assertRaises(ValueError):
            parse_share("https://example.com")


if __name__ == "__main__":
    unittest.main()
