"""Parse proxy share links locally. Secrets stay masked."""
from __future__ import annotations

import base64
import json
from dataclasses import dataclass
from urllib.parse import parse_qs, unquote, urlsplit


@dataclass(frozen=True)
class Share:
    scheme: str
    host: str
    port: int
    name: str
    userinfo_set: bool

    def format(self) -> str:
        flag = "secret" if self.userinfo_set else "no-secret"
        label = self.name or "-"
        return f"{self.scheme} {self.host}:{self.port} {flag} {label}"


def parse_share(text: str) -> Share:
    raw = (text or "").strip()
    if "://" not in raw:
        raise ValueError("不是分享链接")
    scheme = raw.split("://", 1)[0].lower()
    if scheme == "hy2":
        scheme = "hysteria2"
    if scheme == "ss":
        return _parse_ss(raw)
    if scheme == "vmess":
        return _parse_vmess(raw)
    if scheme in {"trojan", "hysteria2"}:
        return _parse_userinfo(raw, scheme)
    raise ValueError(f"不认识的协议: {scheme}")


def _parse_ss(raw: str) -> Share:
    body, name = _split_name(raw.split("://", 1)[1])
    if "@" in body:
        user, hostport = body.rsplit("@", 1)
        secret = _b64_text(user)
        if ":" not in secret:
            raise ValueError("ss 用户信息无法解码")
        host, port = _hostport(hostport)
        return Share("ss", host, port, name, True)
    decoded = _b64_text(body)
    if "@" not in decoded:
        raise ValueError("ss 链接无法解码")
    _method, hostport = decoded.rsplit("@", 1)
    host, port = _hostport(hostport)
    return Share("ss", host, port, name, True)


def _parse_vmess(raw: str) -> Share:
    body, name = _split_name(raw.split("://", 1)[1])
    try:
        data = json.loads(_b64_text(body))
    except json.JSONDecodeError as exc:
        raise ValueError("vmess 不是 JSON") from exc
    if not isinstance(data, dict):
        raise ValueError("vmess 不是 JSON 对象")
    host = str(data.get("add") or "").strip()
    port = int(str(data.get("port") or "0"))
    if not host or not 1 <= port <= 65535:
        raise ValueError("vmess 缺少地址或端口")
    label = name or str(data.get("ps") or "").strip()
    secret = bool(str(data.get("id") or "").strip())
    return Share("vmess", host, port, label, secret)


def _parse_userinfo(raw: str, scheme: str) -> Share:
    parts = urlsplit(raw)
    host = parts.hostname or ""
    port = parts.port or 0
    if not host or not 1 <= port <= 65535:
        raise ValueError(f"{scheme} 缺少地址或端口")
    name = unquote(parts.fragment or "")
    if not name:
        name = unquote((parse_qs(parts.query).get("name") or [""])[0])
    return Share(scheme, host, port, name, bool(parts.username or parts.password))


def _split_name(body: str) -> tuple[str, str]:
    if "#" not in body:
        return body, ""
    left, right = body.split("#", 1)
    return left, unquote(right)


def _hostport(text: str) -> tuple[str, int]:
    host, sep, port_s = text.rpartition(":")
    if not sep:
        raise ValueError("缺少端口")
    port = int(port_s)
    if not host or not 1 <= port <= 65535:
        raise ValueError("地址或端口不合法")
    return host, port


def _b64_text(text: str) -> str:
    pad = "=" * (-len(text) % 4)
    try:
        raw = base64.urlsafe_b64decode(text + pad)
    except Exception:
        raw = base64.b64decode(text + pad)
    return raw.decode("utf-8")
