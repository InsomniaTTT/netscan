#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
netscan.py —— 内网存活主机(ping)与开放端口探测工具
仅使用 Python 标准库(装有 psutil 时接口识别更准), 无需管理员权限。

功能:
  1. 枚举本机网络接口 / IP / 掩码 / 所在网段                  (--ifaces)
  2. 对目标网段并发 ICMP ping, 找出存活(可 ping)主机并记录延迟  (调用系统 ping, 兼容中英文输出)
  3. 对存活主机并发扫描 TCP 开放端口, 识别常见服务              (内置 ~60 常用端口, -p 可自定义)
  4. 可选增强:
       --tcp-ping  对 ping 不通的主机用常见 TCP 端口二次判定存活(应对禁 ICMP 的网络)
       --banner    对开放端口抓取服务指纹(HTTP/SSH/FTP 等)
       自动用系统 ARP 表回填存活主机的 MAC 地址
  5. 结果实时打印, 支持 --json / --csv 导出

声明: 仅在你获得授权的网络(自己的办公网/家庭网/授权测试环境)中使用。
示例:
  python netscan.py --ifaces                                 # 查看本机接口与网段
  python netscan.py                                           # 自动扫描本机所在网段(默认端口)
  python netscan.py 192.168.1.0/24                            # 扫描指定网段
  python netscan.py 192.168.1.10 10.8.0.0/24 -p 22,80,3389,8000-8100
  python netscan.py 192.168.1.0/24 --tcp-ping --banner --csv result.csv
  python netscan.py 192.168.1.0/24 --no-ports                  # 只探测可 ping 的主机
"""

from __future__ import annotations

import argparse
import concurrent.futures as cf
import csv
import ipaddress
import json
import locale
import platform
import re
import socket
import subprocess
import sys
import time

IS_WIN = platform.system() == "Windows"
# 无控制台进程(如 --noconsole 打包的 exe)调用 ping/ipconfig 等控制台程序时,
# 每个子进程都会弹一个 cmd 窗口; 此标志强制子进程不创建窗口
NO_WINDOW = getattr(subprocess, "CREATE_NO_WINDOW", 0)
try:
    LOCAL_ENCODING = locale.getpreferredencoding(False) or "utf-8"
except Exception:
    LOCAL_ENCODING = "utf-8"

IPV4_RE = re.compile(r"\d{1,3}(?:\.\d{1,3}){3}")
# 无论中英文系统, 真正收到回包时输出必含 "TTL=xx", 以此判定存活(比退出码可靠)
TTL_RE = re.compile(r"ttl[=: \t]+\d+", re.IGNORECASE)
LATENCY_RE = re.compile(r"(?:time|时间)\s*[=<]\s*(\d+)\s*ms", re.IGNORECASE)

# 内置常用端口 -> 服务名(同时也是默认扫描端口列表)
SERVICES = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS", 69: "TFTP", 80: "HTTP",
    110: "POP3", 111: "RPCbind", 135: "MSRPC", 139: "NetBIOS", 143: "IMAP", 389: "LDAP",
    443: "HTTPS", 445: "SMB", 465: "SMTPS", 514: "Syslog", 587: "SMTP-sub", 636: "LDAPS",
    873: "Rsync", 993: "IMAPS", 995: "POP3S", 1080: "SOCKS", 1433: "MSSQL", 1521: "Oracle",
    2049: "NFS", 2181: "ZooKeeper", 2375: "Docker", 2376: "Docker-TLS", 3000: "Grafana",
    3128: "Squid", 3260: "iSCSI", 3306: "MySQL", 3389: "RDP", 5000: "UPnP",
    5432: "PostgreSQL", 5601: "Kibana", 5900: "VNC", 5985: "WinRM", 5986: "WinRM-TLS",
    6379: "Redis", 6443: "K8s-API", 7001: "WebLogic", 8000: "HTTP-alt", 8069: "Odoo",
    8080: "HTTP-proxy", 8081: "HTTP-alt", 8088: "HTTP-alt", 8089: "Splunk", 8161: "ActiveMQ",
    8443: "HTTPS-alt", 8848: "Nacos", 8888: "HTTP-alt", 9000: "HTTP-alt", 9001: "HTTP-alt",
    9090: "Prometheus", 9200: "Elasticsearch", 9300: "ES-cluster", 9999: "HTTP-alt",
    10000: "Webmin", 11211: "Memcached", 15672: "RabbitMQ-UI", 27017: "MongoDB",
    50070: "HDFS-UI",
}

# --tcp-ping 二次存活判定依次尝试的端口
TCP_PING_PORTS = (135, 139, 445, 22, 80, 443, 3389, 8080)

# 这类端口上的服务不会主动说话, 需要先发个 HTTP 请求才有回应(抓 banner 用)
HTTP_LIKE_PORTS = {80, 3000, 5000, 5601, 6443, 7001, 8000, 8008, 8069, 8080, 8081,
                   8088, 8089, 8161, 8443, 8848, 8888, 9000, 9001, 9090, 9200,
                   9999, 10000, 15672}


# ---------------------------------------------------------------- 基础工具

def setup_stdio():
    # 输出重定向到文件/管道时统一用 UTF-8, 避免中文乱码; 终端下仍走系统 Unicode 输出
    for stream in (sys.stdout, sys.stderr):
        if not stream.isatty():
            try:
                stream.reconfigure(encoding="utf-8", errors="replace")
            except Exception:
                pass


def run_cmd(cmd, timeout=15):
    """运行系统命令, 返回 stdout 文本; 失败返回 None(不影响主流程)"""
    try:
        r = subprocess.run(cmd, capture_output=True, timeout=timeout,
                           creationflags=NO_WINDOW)
    except Exception:
        return None
    return (r.stdout or b"").decode(LOCAL_ENCODING, errors="replace")


def progress_tick(total, done):
    if sys.stdout.isatty():
        print(f"\r    进度 {done}/{total}", end="", flush=True)


def progress_done():
    if sys.stdout.isatty():
        print("\r" + " " * 48 + "\r", end="", flush=True)


# ---------------------------------------------------------------- 探测原语

def ping_host(ip, timeout_ms=1000):
    """调用系统 ping 探测一次, 返回 (是否存活, 延迟ms)"""
    if IS_WIN:
        cmd = ["ping", "-n", "1", "-w", str(int(timeout_ms)), ip]
    else:
        cmd = ["ping", "-c", "1", "-W", str(max(1, int(round(timeout_ms / 1000)))), ip]
    t0 = time.monotonic()
    try:
        r = subprocess.run(cmd, capture_output=True, timeout=timeout_ms / 1000 + 3,
                           creationflags=NO_WINDOW)
    except Exception:
        return False, None
    out = (r.stdout or b"").decode(LOCAL_ENCODING, errors="replace")
    out += (r.stderr or b"").decode(LOCAL_ENCODING, errors="replace")
    if not TTL_RE.search(out):
        return False, None
    m = LATENCY_RE.search(out)
    if m:
        return True, float(m.group(1))
    return True, round((time.monotonic() - t0) * 1000)


def port_open(ip, port, timeout=1.0):
    try:
        with socket.create_connection((ip, port), timeout=timeout):
            return True
    except OSError:
        return False


def grab_banner(ip, port, timeout=1.5):
    """连接后尝试读取服务主动发送的标识; HTTP 类端口先发一个 HEAD 请求"""
    try:
        s = socket.create_connection((ip, port), timeout=timeout)
    except OSError:
        return ""
    try:
        s.settimeout(timeout)
        if port in HTTP_LIKE_PORTS:
            try:
                s.sendall(b"HEAD / HTTP/1.0\r\nHost: scan\r\nConnection: close\r\n\r\n")
            except OSError:
                return ""
        try:
            data = s.recv(256)
        except OSError:
            return ""
        if not data:
            return ""
        text = " ".join(data.decode("utf-8", errors="replace").split())
        # TLS 等二进制响应大多不可读, 过滤掉避免误导
        if sum(ch.isprintable() for ch in text) / len(text) < 0.7:
            return ""
        return text[:120]
    except Exception:
        return ""
    finally:
        try:
            s.close()
        except OSError:
            pass


# ---------------------------------------------------------------- 本机接口发现

def get_interfaces():
    """枚举本机 IPv4 接口: [{name, ip, netmask, network}]"""
    raw = []
    try:
        import psutil
    except ImportError:
        psutil = None
    if psutil is not None:
        try:
            for name, addrs in psutil.net_if_addrs().items():
                for a in addrs:
                    if a.family == socket.AF_INET and a.address:
                        raw.append({"name": name, "ip": a.address, "netmask": a.netmask})
        except Exception:
            raw = []
    if not raw:
        raw = _ifaces_from_ipconfig() if IS_WIN else (_ifaces_from_ip() or _ifaces_from_ifconfig())
    result = []
    for it in raw:
        ip = it.get("ip") or ""
        # 跳过回环与链路本地地址
        if not ip or ip.startswith("127.") or ip.startswith("169.254.") or ip == "0.0.0.0":
            continue
        network = None
        if it.get("netmask"):
            try:
                network = ipaddress.ip_network(f"{ip}/{it['netmask']}", strict=False)
            except ValueError:
                network = None
        result.append({"name": it.get("name") or "?", "ip": ip,
                       "netmask": it.get("netmask"), "network": network})
    return result


def _ifaces_from_ipconfig():
    """解析 ipconfig 输出(兼容中文/英文系统)"""
    text = run_cmd(["ipconfig"]) or ""
    ifaces, cur_name, cur_ip = [], "", None
    for rawline in text.splitlines():
        line = rawline.strip()
        if not line:
            continue
        if ("适配器" in line) or ("adapter" in line.lower()):
            m = re.search(r"(?:适配器|adapter)\s*(.+?)\s*[:：]?\s*$", line, re.IGNORECASE)
            cur_name = m.group(1).strip() if m else line
            cur_ip = None
            continue
        if "ipv4" in line.lower():
            m = IPV4_RE.search(line)
            if m:
                cur_ip = m.group(0)
            continue
        if cur_ip:
            m = re.search(r"(255(?:\.\d{1,3}){3})", line)
            if m:
                ifaces.append({"name": cur_name, "ip": cur_ip, "netmask": m.group(1)})
                cur_ip = None
    if cur_ip:  # 没配到掩码的接口(如 PPP/VPN), 仅供展示
        ifaces.append({"name": cur_name, "ip": cur_ip, "netmask": None})
    return ifaces


def _ifaces_from_ip():
    text = run_cmd(["ip", "-o", "-4", "addr", "show"]) or ""
    out = []
    for m in re.finditer(r"inet\s+(\d{1,3}(?:\.\d{1,3}){3})/(\d{1,2})\s+.*?dev\s+(\S+)", text):
        ip, plen, dev = m.groups()
        try:
            mask = str(ipaddress.ip_network(f"{ip}/{plen}").netmask)
        except ValueError:
            continue
        out.append({"name": dev, "ip": ip, "netmask": mask})
    return out


def _ifaces_from_ifconfig():
    text = run_cmd(["ifconfig"]) or ""
    out = []
    for m in re.finditer(r"inet\s+(\d{1,3}(?:\.\d{1,3}){3})\s+netmask\s+(0x[0-9A-Fa-f]+)", text):
        ip, hx = m.groups()
        try:
            mask = str(ipaddress.ip_address(int(hx, 16)))
        except ValueError:
            continue
        out.append({"name": "", "ip": ip, "netmask": mask})
    return out


# ---------------------------------------------------------------- ARP / 服务名

def get_arp_table():
    """读取系统 ARP 表, 返回 {ip: mac}; ping 扫过后存活邻居通常都在表里"""
    table = {}
    if IS_WIN:
        text = run_cmd(["arp", "-a"], timeout=10) or ""
        for m in re.finditer(
                r"(\d{1,3}(?:\.\d{1,3}){3})\s+([0-9A-Fa-f]{2}(?:[-:][0-9A-Fa-f]{2}){5})\s+(\S+)", text):
            ip, mac, typ = m.groups()
            if ip not in table or "动" in typ or "dyn" in typ.lower():
                table[ip] = mac
    else:
        text = run_cmd(["ip", "neigh"], timeout=10) or ""
        for m in re.finditer(
                r"(\d{1,3}(?:\.\d{1,3}){3})\s+dev\s+\S+\s+lladdr\s+([0-9A-Fa-f:]{17})", text):
            table[m.group(1)] = m.group(2)
    return table


def service_name(port):
    name = SERVICES.get(port)
    if name:
        return name
    try:
        return socket.getservbyport(port, "tcp")
    except OSError:
        return ""


# ---------------------------------------------------------------- 并发扫描

def ping_sweep(ips, timeout_ms, workers):
    """并发 ping, 返回 ({ip: 延迟ms或None}, 是否被中断)"""
    alive, interrupted = {}, False
    total = len(ips)
    with cf.ThreadPoolExecutor(max_workers=max(1, workers)) as ex:
        futs = {ex.submit(ping_host, str(ip), timeout_ms): str(ip) for ip in ips}
        done = 0
        try:
            for fut in cf.as_completed(futs):
                ip = futs[fut]
                try:
                    ok, latency = fut.result()
                except Exception:
                    ok, latency = False, None
                if ok:
                    alive[ip] = latency
                done += 1
                progress_tick(total, done)
        except KeyboardInterrupt:
            interrupted = True
            for f in futs:
                f.cancel()
            print("\n[!] 已中断, 使用已探测到的部分结果")
    progress_done()
    return alive, interrupted


def tcp_ping_pass(ips, timeout, workers):
    """ICMP 不通的主机逐个试常见 TCP 端口, 任一成功即视为存活, 返回 {ip: 命中的端口}"""
    def probe(ip):
        for p in TCP_PING_PORTS:
            if port_open(ip, p, timeout):
                return ip, p
        return ip, None

    found = {}
    total = len(ips)
    with cf.ThreadPoolExecutor(max_workers=max(1, workers)) as ex:
        futs = {ex.submit(probe, ip): ip for ip in ips}
        done = 0
        try:
            for fut in cf.as_completed(futs):
                try:
                    ip, hit = fut.result()
                except Exception:
                    continue
                if hit:
                    found[ip] = hit
                done += 1
                progress_tick(total, done)
        except KeyboardInterrupt:
            for f in futs:
                f.cancel()
            print("\n[!] 已中断")
    progress_done()
    return found


def scan_ports(ips, ports, timeout, workers):
    """并发 TCP connect 扫描, 返回 ({ip: [开放端口]}, 是否被中断)"""
    open_map = {ip: [] for ip in ips}
    interrupted = False
    tasks = [(ip, p) for ip in ips for p in ports]
    total = len(tasks)
    with cf.ThreadPoolExecutor(max_workers=max(1, workers)) as ex:
        futs = {ex.submit(port_open, ip, p, timeout): (ip, p) for ip, p in tasks}
        done = 0
        try:
            for fut in cf.as_completed(futs):
                ip, p = futs[fut]
                try:
                    if fut.result():
                        open_map[ip].append(p)
                except Exception:
                    pass
                done += 1
                progress_tick(total, done)
        except KeyboardInterrupt:
            interrupted = True
            for f in futs:
                f.cancel()
            print("\n[!] 已中断, 使用已探测到的部分结果")
    progress_done()
    for lst in open_map.values():
        lst.sort()
    return open_map, interrupted


def grab_banners(pairs, timeout=1.5, workers=32):
    """对 (ip, port) 列表并发抓 banner, 返回 {ip: {port: banner}}"""
    result = {ip: {} for ip, _ in pairs}
    with cf.ThreadPoolExecutor(max_workers=workers) as ex:
        futs = {ex.submit(grab_banner, ip, p, timeout): (ip, p) for ip, p in pairs}
        for fut in cf.as_completed(futs):
            ip, p = futs[fut]
            try:
                b = fut.result()
            except Exception:
                b = ""
            if b:
                result[ip][p] = b
    return result


# ---------------------------------------------------------------- 目标与参数解析

def resolve_target(part):
    """支持 x.x.x.x / x.x.x.x/nn / x.x.x.x/掩码 / 主机名"""
    try:
        return ipaddress.ip_interface(part).network
    except ValueError:
        pass
    try:
        ip = socket.gethostbyname(part)
        return ipaddress.ip_network(f"{ip}/32")
    except socket.gaierror:
        sys.exit(f"[x] 无法解析目标: {part}")


def dedup_nets(nets):
    seen = {}
    for n in nets:
        seen[str(n)] = n
    return list(seen.values())


def collect_hosts(nets):
    seen = {}
    for net in nets:
        hosts = list(net.hosts()) or [net.network_address]
        for h in hosts:
            seen[str(h)] = h
    return sorted(seen.values(), key=int)


def parse_ports(spec):
    ports = set()
    for part in spec.split(","):
        part = part.strip()
        if not part:
            continue
        try:
            if "-" in part:
                lo, _, hi = part.partition("-")
                lo, hi = int(lo), int(hi)
                if not (1 <= lo <= hi <= 65535):
                    raise ValueError
                ports.update(range(lo, hi + 1))
            else:
                p = int(part)
                if not (1 <= p <= 65535):
                    raise ValueError
                ports.add(p)
        except ValueError:
            sys.exit(f"[x] 无效端口定义: {part} (示例: 22,80,8000-8100)")
    return sorted(ports)


# ---------------------------------------------------------------- 结果导出

def export_json(path, rows, nets, total_scanned):
    data = {
        "scan_time": time.strftime("%Y-%m-%d %H:%M:%S"),
        "targets": [str(n) for n in nets],
        "total_addresses_scanned": total_scanned,
        "alive_hosts": len(rows),
        "hosts": rows,
    }
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)


def export_csv(path, rows):
    # utf-8-sig 带 BOM, Excel 双击打开不乱码
    with open(path, "w", encoding="utf-8-sig", newline="") as f:
        w = csv.writer(f)
        w.writerow(["ip", "alive_via", "latency_ms", "mac", "open_ports", "banners"])
        for r in rows:
            w.writerow([
                r["ip"], r["alive_via"],
                r["latency_ms"] if r["latency_ms"] is not None else "",
                r["mac"],
                ";".join(map(str, r["open_ports"])),
                ";".join(f"{p}={b}" for p, b in r["banners"].items()),
            ])


# ---------------------------------------------------------------- 命令行

def parse_args(argv=None):
    p = argparse.ArgumentParser(
        prog="netscan.py",
        description="内网存活主机(ping)与开放端口探测工具 —— 仅限授权网络使用",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""示例:
  python netscan.py --ifaces                     查看本机网络接口与所在网段
  python netscan.py                             自动扫描本机所在网段(默认常用端口)
  python netscan.py 192.168.1.0/24              扫描指定网段
  python netscan.py 192.168.1.10 10.8.0.0/24 -p 22,80,3389,8000-8100
  python netscan.py 192.168.1.0/24 --tcp-ping --banner --csv result.csv
  python netscan.py 192.168.1.0/24 --no-ports  只探测可 ping 的主机, 不扫端口
""")
    p.add_argument("targets", nargs="*", metavar="目标",
                   help="IP / 主机名 / CIDR 网段(如 192.168.1.0/24), 空格分隔多个; 缺省自动用本机网段")
    p.add_argument("-p", "--ports", metavar="PORTS",
                   help="TCP 端口列表, 如 22,80,8000-8100; 缺省为内置常用端口")
    p.add_argument("--no-ports", action="store_true", help="只做 ping 存活探测, 不扫端口")
    p.add_argument("--tcp-ping", action="store_true",
                   help="ping 不通的主机再用常见 TCP 端口做二次存活判定")
    p.add_argument("--banner", action="store_true", help="抓取开放端口的服务指纹")
    p.add_argument("--ifaces", action="store_true", help="只列出本机网络接口后退出")
    p.add_argument("--ping-timeout", type=int, default=1000, metavar="MS", help="ping 超时毫秒(默认 1000)")
    p.add_argument("--port-timeout", type=float, default=1.0, metavar="S", help="TCP 连接超时秒(默认 1.0)")
    p.add_argument("--ping-workers", type=int, default=64, metavar="N", help="ping 并发数(默认 64)")
    p.add_argument("--port-workers", type=int, default=150, metavar="N", help="端口扫描并发数(默认 150)")
    p.add_argument("--json", metavar="FILE", help="结果导出为 JSON")
    p.add_argument("--csv", metavar="FILE", help="结果导出为 CSV(Excel 可直接打开)")
    return p.parse_args(argv)


def main(argv=None):
    setup_stdio()
    args = parse_args(argv)
    started = time.time()

    ifaces = get_interfaces()
    if args.ifaces:
        print("本机网络接口:")
        if not ifaces:
            print("    (未发现可用 IPv4 接口)")
        for it in ifaces:
            net = it["network"]
            print(f"    {str(it['name'])[:24]:<24} {it['ip']:<16} "
                  f"掩码 {str(it['netmask'] or '?'):<16} 网段 {net if net is not None else '未知'}")
        return 0

    # --- 解析目标 ---
    if args.targets:
        nets = []
        for spec in args.targets:
            for part in spec.split(","):
                part = part.strip()
                if part:
                    nets.append(resolve_target(part))
    else:
        nets = [it["network"] for it in ifaces if it["network"]]
        if not nets:
            print("[x] 未能自动获取本机网段, 请显式指定, 例如: python netscan.py 192.168.1.0/24")
            return 2
        print(f"[*] 未指定目标, 自动使用本机所在网段: {', '.join(str(n) for n in nets)}")

    nets = dedup_nets(nets)
    ips = collect_hosts(nets)
    if not ips:
        print("[x] 目标网段内没有可扫描的主机地址")
        return 2
    est = len(ips) / max(1, args.ping_workers) * args.ping_timeout / 1000.0
    print(f"[*] 目标: {', '.join(str(n) for n in nets)} | 共 {len(ips)} 个地址 | ping 阶段预计 ~{est:.0f}s")

    # --- 阶段 1: ICMP ping ---
    print(f"[*] ICMP ping 存活探测 (并发 {args.ping_workers}, 超时 {args.ping_timeout}ms)...")
    alive, interrupted = ping_sweep(ips, args.ping_timeout, args.ping_workers)
    sources = {ip: "icmp" for ip in alive}
    print(f"[+] ping 存活: {len(alive)}/{len(ips)}")

    # --- 阶段 2: TCP 二次存活判定 ---
    if args.tcp_ping and not interrupted:
        rest = [ip for ip in ips if ip not in alive]
        if rest:
            print(f"[*] 对 {len(rest)} 台 ping 不通的主机做 TCP 二次存活判定...")
            extra = tcp_ping_pass(rest, args.port_timeout, args.port_workers)
            for ip, p in extra.items():
                alive[ip] = None
                sources[ip] = f"tcp:{p}"
            if extra:
                print(f"[+] TCP 判定新增存活: {len(extra)} 台")

    # --- 阶段 3: TCP 端口扫描 ---
    open_map = {ip: [] for ip in alive}
    if not args.no_ports and alive and not interrupted:
        ports = parse_ports(args.ports) if args.ports else sorted(SERVICES)
        print(f"[*] TCP 端口扫描: {len(alive)} 台 x {len(ports)} 端口 (并发 {args.port_workers})...")
        open_map, interrupted = scan_ports(list(alive), ports, args.port_timeout, args.port_workers)

    # --- 阶段 4: 服务指纹 ---
    banners = {ip: {} for ip in alive}
    if args.banner and not interrupted:
        pairs = [(ip, p) for ip, ps in open_map.items() for p in ps]
        if pairs:
            print(f"[*] 抓取服务指纹 ({len(pairs)} 个开放端口)...")
            banners = grab_banners(pairs)

    # --- ARP 回填 MAC ---
    print("[*] 读取 ARP 表补充 MAC 地址...")
    arp = get_arp_table()

    # --- 汇总输出 ---
    rows = []
    for ip in sorted(alive, key=lambda s: ipaddress.ip_address(s)):
        rows.append({
            "ip": ip,
            "alive_via": sources.get(ip, "icmp"),
            "latency_ms": alive[ip],
            "mac": arp.get(ip, ""),
            "open_ports": open_map.get(ip, []),
            "banners": banners.get(ip, {}),
        })

    print("\n" + "=" * 62)
    print("探测结果")
    print("=" * 62)
    if not rows:
        print("  未发现存活主机。可尝试 --tcp-ping(应对禁 ping 的网络), 或核对目标网段。")
    for row in rows:
        head = f"{row['ip']:<16} 存活({row['alive_via']})"
        if row["latency_ms"] is not None:
            head += f" 延迟 {row['latency_ms']:.0f}ms"
        if row["mac"]:
            head += f"  MAC {row['mac']}"
        print(head)
        if row["open_ports"]:
            for p in row["open_ports"]:
                line = f"    {p:<6}/tcp  {service_name(p) or '?':<15}"
                b = row["banners"].get(p, "")
                if b:
                    line += f"  {b}"
                print(line)
        elif not args.no_ports and not interrupted:
            print("    (默认端口范围内无开放端口, 可用 -p 指定更多端口)")

    n_open = sum(len(r["open_ports"]) for r in rows)
    print(f"\n[+] 完成: 存活 {len(rows)}/{len(ips)} 台 | 开放端口 {n_open} 个 | 耗时 {time.time() - started:.1f}s")

    if args.json:
        export_json(args.json, rows, nets, len(ips))
        print(f"[*] 已导出 JSON: {args.json}")
    if args.csv:
        export_csv(args.csv, rows)
        print(f"[*] 已导出 CSV: {args.csv}")
    return 130 if interrupted else 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\n[x] 已中断")
        sys.exit(130)