# proxy-uri

在本机解析 `ss://`、`vmess://`、`trojan://`、`hysteria2://`（含 `hy2://`）。只打印协议、主机、端口和名称。密码和 UUID 不输出。

不联网，不发起连接。

## 用法

```bash
python -m proxy_uri 'trojan://secret@example.com:443#office'
```

输出：

```text
trojan example.com:443 secret office
```

`secret` 表示链接里带了凭据，不是把凭据打印出来。

## 能认的格式

| 链接 | 处理 |
| --- | --- |
| `ss://` 整段 base64 | `method:password@host:port` |
| `ss://` SIP002 | `base64(method:password)@host:port` |
| `vmess://` | base64 的 JSON，读 `add` / `port` / `ps` |
| `trojan://` `hysteria2://` `hy2://` | 用户信息留在本地，只取主机、端口、fragment 或 `name` |

## 测试

```bash
python -m unittest tests/test_parse.py
```

## 许可

MIT
