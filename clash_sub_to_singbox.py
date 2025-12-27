#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
import base64
import hashlib
import json
import sys
import urllib.request
import urllib.parse
from urllib.error import URLError, HTTPError

try:
    import yaml  # PyYAML
except ImportError:
    print("缺少依赖 PyYAML，请先运行：python3 -m pip install --user pyyaml", file=sys.stderr)
    sys.exit(1)


def fetch_text(url: str, timeout: int = 20) -> str:
    req = urllib.request.Request(
        url,
        headers={
            "User-Agent": "Mozilla/5.0 (sub-to-singbox)",
            "Accept": "*/*",
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.read().decode("utf-8", errors="replace")
    except HTTPError as e:
        raise RuntimeError(f"HTTP 错误：{e.code} {e.reason}")
    except URLError as e:
        raise RuntimeError(f"URL 错误：{e.reason}")
    except Exception as e:
        raise RuntimeError(f"拉取订阅失败：{e}")


def _try_base64_decode_to_text(data: str) -> str | None:
    """
    Try to base64-decode `data` to UTF-8 text. Returns None if it doesn't look like valid base64.
    """
    s = data.strip()
    # base64 padding is optional in many subscriptions; fix it up before decoding.
    padding = len(s) % 4
    if padding:
        s += "=" * (4 - padding)
    try:
        decoded = base64.b64decode(s, validate=False)
        return decoded.decode("utf-8", errors="replace")
    except Exception:
        return None


def load_clash_subscription(raw: str) -> dict:
    """Parse Clash subscription content into a dict.

    Some providers return plain YAML, others return base64-encoded YAML/JSON. This helper
    tries both forms and falls back with a helpful error if parsing still fails.
    """

    def try_yaml(text: str):
        try:
            return yaml.safe_load(text)
        except Exception:
            return None

    # First attempt: raw YAML
    doc = try_yaml(raw)
    if isinstance(doc, dict):
        return doc

    # Second attempt: base64 -> YAML/JSON
    decoded_text = None
    if isinstance(doc, str):
        decoded_text = _try_base64_decode_to_text(doc)
    if decoded_text is None:
        decoded_text = _try_base64_decode_to_text(raw)

    if decoded_text:
        doc2 = try_yaml(decoded_text)
        if isinstance(doc2, dict):
            return doc2
        try:
            doc_json = json.loads(decoded_text)
            if isinstance(doc_json, dict):
                return doc_json
        except Exception:
            pass

    # Some rare cases may provide a top-level list; treat it as proxies directly.
    if isinstance(doc, list):
        return {"proxies": doc}

    # Try common \"universal\" (V2Ray/SSR) subscription: base64 -> newline separated URIs.
    # Only convert SS/Trojan since脚本目前仅支持这两类。
    text_candidates = [decoded_text, raw]
    for txt in text_candidates:
        if not txt or not isinstance(txt, str):
            continue
        proxies = parse_uri_subscription(txt)
        if proxies:
            return {"proxies": proxies}

    raise SystemExit(
        "订阅内容不是 Clash YAML（找不到 proxies）。如果这是 V2Ray/通用订阅，请先转换为 Clash 格式或使用含 proxies 的订阅。"
    )


def parse_uri_subscription(text: str):
    """
    Parse newline-separated ss:// or trojan:// links (base64-decoded already) into Clash-like proxies.
    Unsupported/unknown lines are ignored.
    """
    proxies = []
    for line in text.splitlines():
        url = line.strip()
        if not url or url.startswith("#"):
            continue
        if url.startswith("ss://"):
            p = parse_ss_uri(url)
            if p:
                proxies.append(p)
        elif url.startswith("trojan://"):
            p = parse_trojan_uri(url)
            if p:
                proxies.append(p)
    return proxies


def _b64decode_auto(s: str) -> bytes:
    """Decode base64 string with missing padding tolerated."""
    padding = len(s) % 4
    if padding:
        s += "=" * (4 - padding)
    return base64.urlsafe_b64decode(s)


def parse_ss_uri(uri: str):
    """
    Handle both RFC (plain) form and legacy base64 form.
    Examples:
      ss://YWVzLTI1Ni1nY206cGFzc0BleGFtcGxlLmNvbTo4NDQz#name
      ss://aes-256-gcm:pass@example.com:8443#name
    """
    try:
        parsed = urllib.parse.urlparse(uri)
        fragment_name = urllib.parse.unquote(parsed.fragment or "") or None

        if parsed.username is None and parsed.netloc and "@" not in parsed.netloc:
            # base64 part in netloc/path
            b64_part = parsed.netloc or parsed.path
            info = _b64decode_auto(b64_part.split("#")[0].split("?")[0]).decode("utf-8")
            # method:password@host:port
            creds, hostport = info.rsplit("@", 1)
            method, password = creds.split(":", 1)
            host, port = hostport.split(":", 1)
            query = parsed.query
        else:
            method = urllib.parse.unquote(parsed.username or "")
            password = urllib.parse.unquote(parsed.password or "")
            host = parsed.hostname
            port = parsed.port
            query = parsed.query

        if not (host and port and method and password):
            return None

        q = urllib.parse.parse_qs(query)
        plugin = q.get("plugin", [None])[0]

        p = {
            "type": "ss",
            "name": fragment_name or host,
            "server": host,
            "port": int(port),
            "cipher": method,
            "password": password,
        }
        if plugin:
            p["plugin"] = plugin
        return p
    except Exception:
        return None


def parse_trojan_uri(uri: str):
    """
    trojan://password@host:port?allowInsecure=1&sni=example#name
    """
    try:
        parsed = urllib.parse.urlparse(uri)
        password = urllib.parse.unquote(parsed.username or "")
        host = parsed.hostname
        port = parsed.port
        q = urllib.parse.parse_qs(parsed.query)
        sni = q.get("sni", q.get("peer", q.get("peername", [None])))[0]
        insecure = q.get("allowInsecure", ["0"])[0] in ("1", "true", "yes")
        name = urllib.parse.unquote(parsed.fragment or "") or host

        if not (host and port and password):
            return None

        return {
            "type": "trojan",
            "name": name,
            "server": host,
            "port": int(port),
            "password": password,
            "sni": sni,
            "skip-cert-verify": insecure,
        }
    except Exception:
        return None


def stable_port_assign(keys, base_port: int, port_range: int):
    """
    使用 hash(key) % port_range 做初始落点，碰撞则线性探测，确保稳定映射。
    """
    used = set()
    mapping = {}  # key -> port
    for k in keys:
        h = hashlib.sha1(k.encode("utf-8")).digest()
        start = int.from_bytes(h[:4], "big") % port_range
        for i in range(port_range):
            port = base_port + ((start + i) % port_range)
            if port not in used:
                used.add(port)
                mapping[k] = port
                break
        else:
            raise RuntimeError("端口池耗尽：port_range 太小，装不下这么多节点")
    return mapping


def norm_bool(v, default=False):
    if v is None:
        return default
    if isinstance(v, bool):
        return v
    if isinstance(v, (int, float)):
        return v != 0
    s = str(v).strip().lower()
    return s in ("1", "true", "yes", "y", "on")


def build_outbound_from_clash_proxy(p: dict):
    ptype = str(p.get("type", "")).strip().lower()

    name = str(p.get("name", "")).strip() or f"{ptype}-{p.get('server','')}"
    tag = sanitize_tag(name)

    if ptype in ("ss", "shadowsocks"):
        server = p.get("server")
        port = int(p.get("port"))
        method = p.get("cipher") or p.get("method")
        password = p.get("password")

        if not (server and port and method and password):
            raise ValueError(f"SS 节点字段不完整：{name}")

        ob = {
            "type": "shadowsocks",
            "tag": tag,
            "server": server,
            "server_port": port,
            "method": method,
            "password": password,
        }

        # Clash 的 plugin/plugin-opts 很多花样，sing-box 也支持部分插件，但字段差异较大。
        # 这里默认不自动转换，避免生成错误配置。需要的话你再告诉我你的 plugin 类型，我帮你补。
        if p.get("plugin"):
            ob["_warning"] = f"该 SS 节点包含 plugin={p.get('plugin')}，脚本未自动转换（避免不兼容）"

        uniq_key = f"ss|{server}|{port}|{method}|{password}"
        return tag, uniq_key, ob

    if ptype == "trojan":
        server = p.get("server")
        port = int(p.get("port"))
        password = p.get("password")
        sni = p.get("sni") or p.get("servername") or p.get("server_name")
        insecure = norm_bool(p.get("skip-cert-verify"), default=False)

        if not (server and port and password):
            raise ValueError(f"Trojan 节点字段不完整：{name}")

        ob = {
            "type": "trojan",
            "tag": tag,
            "server": server,
            "server_port": port,
            "password": password,
            "tls": {
                "enabled": True,
                "insecure": insecure,
            },
        }
        if sni:
            ob["tls"]["server_name"] = sni

        uniq_key = f"trojan|{server}|{port}|{password}|{sni or ''}|insecure={int(insecure)}"
        return tag, uniq_key, ob

    return None, None, None


def sanitize_tag(s: str) -> str:
    # sing-box tag 用于引用，避免奇怪字符
    # 保留中英文数字和常见符号，其它替换为 _
    out = []
    for ch in s:
        if ch.isalnum() or ch in ("-", "_", ".", " ", "(", ")", "[", "]"):
            out.append(ch)
        else:
            out.append("_")
    return "".join(out).strip().replace(" ", "_")[:64] or "node"


def main():
    ap = argparse.ArgumentParser(
        description="从 Clash 订阅（YAML）生成 sing-box 多端口 SOCKS->(SS/Trojan) 配置"
    )
    ap.add_argument("--sub-url", required=True, help="Clash 订阅链接（YAML）")
    ap.add_argument("--output", default="config.json", help="输出 sing-box 配置文件路径")
    ap.add_argument("--listen", default="127.0.0.1", help="SOCKS 监听地址（默认 127.0.0.1）")
    ap.add_argument("--base-port", type=int, default=20000, help="端口起始值（默认 20000）")
    ap.add_argument("--port-range", type=int, default=2000, help="端口池大小（默认 2000：20000-21999）")
    ap.add_argument(
        "--types",
        default="ss,trojan",
        help="处理的节点类型（逗号分隔，支持 ss,trojan；默认 ss,trojan）",
    )
    ap.add_argument("--socks-user", default=None, help="可选：SOCKS 用户名（开启认证）")
    ap.add_argument("--socks-pass", default=None, help="可选：SOCKS 密码（开启认证）")
    ap.add_argument("--timeout", type=int, default=20, help="订阅拉取超时秒数（默认 20）")
    args = ap.parse_args()

    want_types = {t.strip().lower() for t in args.types.split(",") if t.strip()}
    if args.socks_user and not args.socks_pass:
        ap.error("设置了 --socks-user 必须同时设置 --socks-pass")
    if args.socks_pass and not args.socks_user:
        ap.error("设置了 --socks-pass 必须同时设置 --socks-user")

    raw = fetch_text(args.sub_url, timeout=args.timeout)
    doc = load_clash_subscription(raw)

    proxies = doc.get("proxies")
    if not isinstance(proxies, list):
        raise SystemExit(
            "订阅里没找到 proxies 列表。若你的订阅用了 proxy-providers 动态拉取，需要先在 Clash/Mihomo 侧展开或换成含 proxies 的订阅。"
        )

    nodes = []
    warnings = []
    for p in proxies:
        if not isinstance(p, dict):
            continue
        ptype = str(p.get("type", "")).strip().lower()
        if ptype not in want_types:
            continue
        tag, uniq_key, outbound = build_outbound_from_clash_proxy(p)
        if outbound:
            if "_warning" in outbound:
                warnings.append(f"{tag}: {outbound['_warning']}")
                outbound.pop("_warning", None)
            nodes.append((tag, uniq_key, outbound))

    if not nodes:
        raise SystemExit(f"没有找到匹配类型的节点（types={sorted(want_types)}）")

    # 稳定分配端口
    uniq_keys = [u for (_, u, _) in nodes]
    port_map = stable_port_assign(uniq_keys, args.base_port, args.port_range)

    inbounds = []
    outbounds = []
    rules = []

    for (tag, uniq_key, outbound) in nodes:
        port = port_map[uniq_key]
        in_tag = f"in_{tag}"
        out_tag = f"out_{tag}"

        inbound = {
            "type": "socks",
            "tag": in_tag,
            "listen": args.listen,
            "listen_port": port,
            "sniff": True
        }
        if args.socks_user:
            inbound["users"] = [{"username": args.socks_user, "password": args.socks_pass}]

        outbound["tag"] = out_tag

        inbounds.append(inbound)
        outbounds.append(outbound)
        rules.append({"inbound": in_tag, "outbound": out_tag})

    # 加一个 direct 作为 final，避免漏匹配时出错
    outbounds.append({"type": "direct", "tag": "direct"})

    config = {
        "log": {"level": "info"},
        "inbounds": inbounds,
        "outbounds": outbounds,
        "route": {
            "rules": rules,
            "final": "direct"
        }
    }

    with open(args.output, "w", encoding="utf-8") as f:
        json.dump(config, f, ensure_ascii=False, indent=2)

    print(f"已生成：{args.output}")
    print(f"节点数：{len(nodes)}，SOCKS 端口范围：{args.base_port} - {args.base_port + args.port_range - 1}")
    print("示例测试：curl --socks5 127.0.0.1:<port> https://ifconfig.me")
    if warnings:
        print("\n注意：发现部分节点包含 plugin 等字段，脚本未自动转换：")
        for w in warnings[:20]:
            print("  -", w)
        if len(warnings) > 20:
            print(f"  ... 还有 {len(warnings)-20} 条")


if __name__ == "__main__":
    main()
