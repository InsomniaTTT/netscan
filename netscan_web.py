#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
netscan_gui.py —— netscan 的本地 Web 界面版(仪器面板视觉 + 地址扫掠轴)
启动后自动打开浏览器, 配置、启动、停止、查看结果、导出全部在网页中完成,
窗口不会一闪而过, 结果一直保留在页面上。探测逻辑复用 netscan.py。

用法:
  python netscan_gui.py               # 默认 127.0.0.1:8765, 自动打开浏览器
  python netscan_gui.py --port 9000 --no-browser
声明: 仅在你获得授权的网络中使用。
"""

from __future__ import annotations

import argparse
import concurrent.futures as cf
import csv
import http.server
import io
import ipaddress
import json
import socket
import threading
import time
import webbrowser

import netscan  # 复用探测引擎(ping_host / port_open / grab_banner / get_interfaces ...)

HOST = "127.0.0.1"
RUNNING_PHASES = {"prepare", "ping", "tcp_ping", "ports", "banner", "arp"}

LOCK = threading.Lock()
STOP = threading.Event()
STATE: dict = {}


def new_state() -> dict:
    return {
        "phase": "idle", "phase_text": "待机", "error": "",
        "targets": [], "options": {},
        "total": 0, "scanned": 0,
        "tcp_total": 0, "tcp_done": 0,
        "ports_total": 0, "ports_done": 0,
        "banner_total": 0, "banner_done": 0,
        "open_count": 0,
        "hosts": {},            # ip -> {ip, via, latency_ms, mac, ports[], banners{}}
        "started_ts": None, "finished_ts": None,
        "axis_start": None, "axis_end": None,   # 扫掠轴的地址区间(整数形式)
    }


STATE.update(new_state())


# ---------------------------------------------------------------- 扫描逻辑

def _resolve(part: str):
    """同 netscan.resolve_target, 但解析失败抛 ValueError 而不是退出进程"""
    try:
        return ipaddress.ip_interface(part).network
    except ValueError:
        pass
    try:
        return ipaddress.ip_network(f"{socket.gethostbyname(part)}/32")
    except Exception:
        raise ValueError(f"无法解析目标: {part}")


def _parse_ports(spec: str):
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
            raise ValueError(f"无效端口定义: {part} (示例: 22,80,8000-8100)")
    return sorted(ports)


def _clamp(v, lo, hi, default):
    try:
        v = type(default)(v)
    except (TypeError, ValueError):
        v = default
    return max(lo, min(hi, v))


def sanitize_cfg(b: dict) -> dict:
    return {
        "targets": str(b.get("targets") or "").strip(),
        "ports": str(b.get("ports") or "").strip(),
        "tcp_ping": bool(b.get("tcp_ping")),
        "banner": bool(b.get("banner")),
        "no_ports": bool(b.get("no_ports")),
        "ping_workers": _clamp(b.get("ping_workers"), 1, 512, 64),
        "port_workers": _clamp(b.get("port_workers"), 1, 512, 150),
        "ping_timeout": _clamp(b.get("ping_timeout"), 100, 10000, 1000),
        "port_timeout": _clamp(b.get("port_timeout"), 0.2, 10, 1.0),
    }


def _set_phase(phase, text):
    with LOCK:
        STATE["phase"] = phase
        STATE["phase_text"] = text


def _finish(t0, phase, text, error=""):
    with LOCK:
        STATE["phase"] = phase
        STATE["phase_text"] = text
        STATE["error"] = error
        STATE["finished_ts"] = time.time()


def do_scan(cfg: dict):
    """后台线程执行: 解析目标 -> ping -> (tcp 二次) -> 端口 -> (指纹) -> ARP"""
    t0 = time.time()
    try:
        _set_phase("prepare", "正在解析目标...")
        nets = []
        for part in cfg["targets"].replace("，", ",").split(","):
            part = part.strip()
            if part:
                nets.append(_resolve(part))
        if not nets:  # 未填目标则自动用本机网段
            nets = [it["network"] for it in netscan.get_interfaces() if it["network"]]
        nets = netscan.dedup_nets(nets)
        ips = netscan.collect_hosts(nets)
        if not ips:
            raise ValueError("目标网段内没有可扫描的主机地址")
        ports = _parse_ports(cfg["ports"]) if cfg["ports"] else sorted(netscan.SERVICES)
        with LOCK:
            STATE.update(targets=[str(n) for n in nets], total=len(ips),
                         options=cfg, started_ts=time.time(),
                         axis_start=int(ips[0]), axis_end=int(ips[-1]))
        if STOP.is_set():
            return _finish(t0, "stopped", "已停止（部分结果）")

        # --- 阶段 1: ICMP ping ---
        _set_phase("ping", f"ICMP ping 存活探测 0/{len(ips)}")
        with cf.ThreadPoolExecutor(max_workers=cfg["ping_workers"]) as ex:
            futs = {ex.submit(netscan.ping_host, str(ip), cfg["ping_timeout"]): str(ip) for ip in ips}
            for f in cf.as_completed(futs):
                ip = futs[f]
                try:
                    ok, lat = f.result()
                except Exception:
                    ok, lat = False, None
                with LOCK:
                    STATE["scanned"] += 1
                    if ok:
                        STATE["hosts"][ip] = {"ip": ip, "via": "icmp", "latency_ms": lat,
                                              "mac": "", "ports": [], "banners": {}}
                    STATE["phase_text"] = f"ICMP ping 存活探测 {STATE['scanned']}/{STATE['total']}"
                if STOP.is_set():
                    for f2 in futs:
                        f2.cancel()
                    return _finish(t0, "stopped", "已停止（部分结果）")

        # --- 阶段 2: TCP 二次存活判定 ---
        if cfg["tcp_ping"]:
            with LOCK:
                rest = [str(ip) for ip in ips if str(ip) not in STATE["hosts"]]
                STATE["tcp_total"], STATE["tcp_done"] = len(rest), 0
            if rest:
                _set_phase("tcp_ping", f"TCP 二次存活判定 0/{len(rest)}")

                def probe(ip):
                    for p in netscan.TCP_PING_PORTS:
                        if netscan.port_open(ip, p, cfg["port_timeout"]):
                            return ip, p
                    return ip, None

                with cf.ThreadPoolExecutor(max_workers=cfg["port_workers"]) as ex:
                    futs = {ex.submit(probe, ip): ip for ip in rest}
                    for f in cf.as_completed(futs):
                        try:
                            ip, hit = f.result()
                        except Exception:
                            continue
                        with LOCK:
                            STATE["tcp_done"] += 1
                            if hit:
                                STATE["hosts"][ip] = {"ip": ip, "via": f"tcp:{hit}", "latency_ms": None,
                                                      "mac": "", "ports": [], "banners": {}}
                            STATE["phase_text"] = f"TCP 二次存活判定 {STATE['tcp_done']}/{STATE['tcp_total']}"
                        if STOP.is_set():
                            for f2 in futs:
                                f2.cancel()
                            return _finish(t0, "stopped", "已停止（部分结果）")

        # --- 阶段 3: 端口扫描 ---
        with LOCK:
            alive_ips = sorted(STATE["hosts"].keys(), key=lambda s: int(ipaddress.ip_address(s)))
        if cfg["no_ports"]:
            _set_phase("done", f"完成 — 存活 {len(alive_ips)}/{len(ips)}（未扫端口）")
        elif alive_ips and not STOP.is_set():
            tasks = [(ip, p) for ip in alive_ips for p in ports]
            with LOCK:
                STATE["ports_total"], STATE["ports_done"] = len(tasks), 0
            _set_phase("ports", f"TCP 端口扫描 0/{len(tasks)}")
            with cf.ThreadPoolExecutor(max_workers=cfg["port_workers"]) as ex:
                futs = {ex.submit(netscan.port_open, ip, p, cfg["port_timeout"]): (ip, p) for ip, p in tasks}
                for f in cf.as_completed(futs):
                    ip, p = futs[f]
                    try:
                        hit = f.result()
                    except Exception:
                        hit = False
                    with LOCK:
                        STATE["ports_done"] += 1
                        if hit:
                            h = STATE["hosts"].get(ip)
                            if h is not None:
                                h["ports"].append(p)
                                STATE["open_count"] += 1
                        STATE["phase_text"] = f"TCP 端口扫描 {STATE['ports_done']}/{STATE['ports_total']}"
                    if STOP.is_set():
                        for f2 in futs:
                            f2.cancel()
                        return _finish(t0, "stopped", "已停止（部分结果）")
            with LOCK:
                for h in STATE["hosts"].values():
                    h["ports"].sort()

            # --- 阶段 4: 服务指纹 ---
            if cfg["banner"]:
                with LOCK:
                    pairs = [(h["ip"], p) for h in STATE["hosts"].values() for p in h["ports"]]
                    STATE["banner_total"], STATE["banner_done"] = len(pairs), 0
                if pairs:
                    _set_phase("banner", f"抓取服务指纹 0/{len(pairs)}")
                    with cf.ThreadPoolExecutor(max_workers=16) as ex:
                        futs = {ex.submit(netscan.grab_banner, ip, p): (ip, p) for ip, p in pairs}
                        for f in cf.as_completed(futs):
                            ip, p = futs[f]
                            try:
                                b = f.result()
                            except Exception:
                                b = ""
                            with LOCK:
                                STATE["banner_done"] += 1
                                if b:
                                    h = STATE["hosts"].get(ip)
                                    if h is not None:
                                        h["banners"][str(p)] = b
                                STATE["phase_text"] = f"抓取服务指纹 {STATE['banner_done']}/{STATE['banner_total']}"
                            if STOP.is_set():
                                break

        # --- 阶段 5: ARP 回填 MAC ---
        _set_phase("arp", "读取 ARP 表补充 MAC 地址...")
        arp = netscan.get_arp_table()
        with LOCK:
            for ip, h in STATE["hosts"].items():
                h["mac"] = arp.get(ip, "")
            n_alive = len(STATE["hosts"])
            n_open = STATE["open_count"]
        _finish(t0, "done", f"完成 — 存活 {n_alive}/{len(ips)} 台 · 开放端口 {n_open} 个")
    except Exception as e:
        _finish(t0, "error", f"出错: {e}", error=str(e))


def is_running() -> bool:
    with LOCK:
        return STATE["phase"] in RUNNING_PHASES


def snapshot() -> dict:
    with LOCK:
        hosts = []
        for h in sorted(STATE["hosts"].values(), key=lambda x: int(ipaddress.ip_address(x["ip"]))):
            hosts.append({"ip": h["ip"], "via": h["via"], "latency_ms": h["latency_ms"],
                          "mac": h["mac"], "ports": list(h["ports"]), "banners": dict(h["banners"])})
        if STATE["started_ts"]:
            elapsed = (STATE["finished_ts"] or time.time()) - STATE["started_ts"]
        else:
            elapsed = 0
        return {
            "phase": STATE["phase"], "phase_text": STATE["phase_text"], "error": STATE["error"],
            "targets": list(STATE["targets"]), "total": STATE["total"], "scanned": STATE["scanned"],
            "tcp_total": STATE["tcp_total"], "tcp_done": STATE["tcp_done"],
            "ports_total": STATE["ports_total"], "ports_done": STATE["ports_done"],
            "banner_total": STATE["banner_total"], "banner_done": STATE["banner_done"],
            "open_count": STATE["open_count"], "no_ports": STATE["options"].get("no_ports", False),
            "hosts": hosts, "elapsed": elapsed,
            "started_ts": STATE["started_ts"],
            "axis_start": STATE["axis_start"], "axis_end": STATE["axis_end"],
        }


def _export_rows():
    return snapshot()["hosts"]


def build_csv() -> bytes:
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["ip", "alive_via", "latency_ms", "mac", "open_ports", "banners"])
    for r in _export_rows():
        w.writerow([r["ip"], r["via"], r["latency_ms"] if r["latency_ms"] is not None else "",
                    r["mac"], ";".join(map(str, r["ports"])),
                    ";".join(f"{p}={b}" for p, b in r["banners"].items())])
    return buf.getvalue().encode("utf-8-sig")  # 带 BOM, Excel 直接打开不乱码


def build_json_export() -> bytes:
    data = {"scan_time": time.strftime("%Y-%m-%d %H:%M:%S"), "hosts": _export_rows()}
    return json.dumps(data, ensure_ascii=False, indent=2).encode("utf-8")


# ---------------------------------------------------------------- 前端页面

_TEMPLATE = r"""<!doctype html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>NetScan · 内网探测</title>
<link rel="icon" href="data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24'%3E%3Ccircle cx='12' cy='12' r='9' fill='none' stroke='%23f5a524' stroke-width='2'/%3E%3Ccircle cx='12' cy='12' r='3' fill='%233dd68c'/%3E%3C/svg%3E">
<style>
*{box-sizing:border-box;margin:0;padding:0}
:root{
  --bg:#0e1216; --panel:#141a22; --sunken:#0b0f13;
  --edge:rgba(255,255,255,.07); --edge2:rgba(255,255,255,.12);
  --ink:#e8e4d9; --muted:#7e8899; --dim:#5b6675;
  --amber:#f5a524; --amber-soft:rgba(245,165,36,.13);
  --green:#3dd68c; --green-soft:rgba(61,214,140,.12);
  --red:#f0565f;
  --mono:'Cascadia Code','Consolas','JetBrains Mono',monospace;
  --sans:'Segoe UI','Microsoft YaHei UI',system-ui,sans-serif;
}
html{color-scheme:dark}
body{background:var(--bg);color:var(--ink);font-family:var(--sans);font-size:14px;min-height:100vh;
  -webkit-font-smoothing:antialiased}
body::before{content:'';position:fixed;inset:0;pointer-events:none;z-index:0;
  background:radial-gradient(900px 280px at 50% 0%,rgba(245,165,36,.05),transparent 70%)}
.wrap{position:relative;z-index:1;max-width:1040px;margin:0 auto;padding:24px 20px 64px}
::-webkit-scrollbar{width:10px;height:10px}
::-webkit-scrollbar-thumb{background:rgba(255,255,255,.12);border-radius:8px}
::-webkit-scrollbar-track{background:transparent}
:focus-visible{outline:2px solid rgba(245,165,36,.6);outline-offset:2px}

/* ---- 顶栏:词标 + 仪器读数 ---- */
header{display:flex;align-items:center;justify-content:space-between;margin-bottom:20px;gap:14px}
.brand{display:flex;align-items:center;gap:10px;min-width:0}
.mark{width:19px;height:19px;color:var(--amber);flex:none}
.wordmark{font-family:var(--mono);font-size:16px;font-weight:700;letter-spacing:.14em;white-space:nowrap}
.cursor{display:inline-block;width:8px;height:15px;margin-left:6px;background:var(--amber);
  vertical-align:-2px;animation:blink 1.6s steps(1) infinite}
@keyframes blink{50%{opacity:0}}
.sub{font-size:12px;color:var(--muted);white-space:nowrap}
@media(max-width:560px){.sub{display:none}}
.readout{display:flex;align-items:center;gap:9px;font-size:13px;color:var(--muted);white-space:nowrap}
.led{width:8px;height:8px;border-radius:50%;background:var(--dim);flex:none}
.led.run{background:var(--amber);animation:breathe 1.4s ease-in-out infinite}
.led.done{background:var(--green)}
.led.stop{background:var(--amber)}
.led.err{background:var(--red)}
@keyframes breathe{50%{opacity:.35}}
.ro-time{font-family:var(--mono);color:var(--dim);font-size:12px}

/* ---- 面板与表单 ---- */
.panel{background:var(--panel);border:1px solid var(--edge);border-radius:10px;padding:16px 18px;margin-bottom:14px}
label{display:block;font-size:12px;color:var(--muted);margin-bottom:6px;letter-spacing:.08em}
input[type=text],input[type=number],input[type=search]{
  width:100%;background:var(--sunken);border:1px solid var(--edge);border-radius:8px;
  padding:9px 12px;color:var(--ink);font-size:14px;outline:none;transition:border-color .15s,box-shadow .15s}
input:focus{border-color:rgba(245,165,36,.55);box-shadow:0 0 0 3px rgba(245,165,36,.09)}
input::placeholder{color:var(--dim)}
.cfg-grid{display:grid;grid-template-columns:1fr 280px;gap:14px}
@media(max-width:820px){.cfg-grid{grid-template-columns:1fr}}
.chips{display:flex;gap:7px;flex-wrap:wrap;margin-top:8px}
.chip{font-family:var(--mono);font-size:12px;padding:4px 10px;border-radius:6px;border:1px solid var(--edge);
  background:transparent;color:var(--muted);cursor:pointer;transition:.15s}
.chip:hover{color:var(--amber);border-color:rgba(245,165,36,.4)}
.toggles{display:flex;gap:8px;flex-wrap:wrap}
.toggle input{display:none}
.tl{padding:8px 13px;border-radius:8px;border:1px solid var(--edge);color:var(--muted);cursor:pointer;
  font-size:13px;transition:.15s;user-select:none;background:transparent}
.toggle input:checked+.tl{color:var(--amber);border-color:rgba(245,165,36,.5);background:var(--amber-soft)}
details.adv{margin-top:12px}
details.adv summary{cursor:pointer;color:var(--dim);font-size:12px;user-select:none}
.adv-grid{display:grid;grid-template-columns:repeat(4,1fr);gap:10px;margin-top:10px}
@media(max-width:720px){.adv-grid{grid-template-columns:repeat(2,1fr)}}

/* ---- 按钮 ---- */
.actions{display:flex;gap:9px;flex-wrap:wrap;margin-top:15px;align-items:center}
.btn{padding:9px 18px;border-radius:8px;border:1px solid transparent;font-size:13.5px;font-weight:600;
  cursor:pointer;transition:.15s;font-family:var(--sans)}
.btn:disabled{opacity:.45;cursor:default}
.btn-primary{background:var(--amber);color:#161006}
.btn-primary:not(:disabled):hover{background:#ffb63e}
.btn-stop{background:transparent;color:var(--red);border-color:rgba(240,86,95,.45)}
.btn-ghost{background:transparent;color:var(--muted);border-color:var(--edge2)}
.btn-ghost:not(:disabled):hover{color:var(--ink);border-color:rgba(255,255,255,.2)}
.spacer{flex:1}

/* ---- 签名:地址扫掠轴 ---- */
.axis-wrap{padding:14px 18px;background:var(--panel);border:1px solid var(--edge);border-radius:10px;margin-bottom:14px}
.axis{position:relative;height:44px;border-radius:6px;overflow:hidden;background:var(--sunken);cursor:crosshair}
.axis-track{position:absolute;inset:0;
  background:repeating-linear-gradient(90deg,rgba(255,255,255,.09) 0 1px,transparent 1px 12px),
             repeating-linear-gradient(90deg,rgba(255,255,255,.035) 0 1px,transparent 1px 3px)}
.axis-trail{position:absolute;top:0;bottom:0;left:0;width:0;
  background:linear-gradient(90deg,rgba(245,165,36,.02),rgba(245,165,36,.13));
  border-right:1px solid rgba(245,165,36,.35);transition:width .4s linear}
.axis-cursor{position:absolute;top:0;bottom:0;width:2px;left:0;background:transparent;transition:left .4s linear}
.axis-cursor.on{background:var(--amber);box-shadow:0 0 10px rgba(245,165,36,.55)}
.axis.done .axis-trail{opacity:.4}
.axis.done .axis-cursor{opacity:0}
.tick{position:absolute;top:0;bottom:0;width:3px;margin-left:-1.5px;background:var(--green);
  border-radius:1px;cursor:pointer;transform-origin:50% 100%;animation:tickIn .5s ease}
.tick:hover{box-shadow:0 0 8px rgba(61,214,140,.6)}
@keyframes tickIn{0%{transform:scaleY(.15);opacity:0}60%{transform:scaleY(1.2)}100%{transform:scaleY(1)}}
.axis-edges{display:flex;justify-content:space-between;font-family:var(--mono);font-size:11px;color:var(--dim);margin-top:6px}
.readline{display:flex;gap:14px;flex-wrap:wrap;align-items:baseline;margin-top:10px;font-size:12.5px;color:var(--muted)}
.readline b{font-family:var(--mono);color:var(--ink);font-weight:700}
#phaseText{color:var(--ink);font-size:13px}
.subtrack{height:2px;background:rgba(255,255,255,.05);border-radius:2px;margin-top:10px;overflow:hidden}
#subbar{height:100%;width:0;background:var(--amber);opacity:.6;transition:width .35s ease;border-radius:2px}

/* ---- 结果 ---- */
.res-head{display:flex;justify-content:space-between;align-items:center;gap:12px;margin:18px 2px 12px;flex-wrap:wrap}
.res-head input{max-width:260px}
#hostCount{font-size:13px;color:var(--muted)}
.hosts{display:grid;grid-template-columns:repeat(auto-fill,minmax(330px,1fr));gap:12px}
.host{position:relative;background:var(--panel);border:1px solid var(--edge);border-radius:10px;
  padding:14px 16px 14px 18px;transition:border-color .15s;animation:fadeUp .25s ease}
@keyframes fadeUp{from{opacity:0;transform:translateY(6px)}to{opacity:1}}
.host:hover{border-color:rgba(61,214,140,.35)}
.host::before{content:'';position:absolute;left:0;top:12px;bottom:12px;width:3px;
  border-radius:0 2px 2px 0;background:var(--green)}
.h-top{display:flex;justify-content:space-between;align-items:center;gap:10px}
.h-ip{font-family:var(--mono);font-size:16.5px;font-weight:700}
.h-lat{font-size:12px;color:var(--muted);margin-left:9px;font-family:var(--mono)}
.badge{font-family:var(--mono);font-size:11px;padding:3px 8px;border-radius:6px;border:1px solid;white-space:nowrap}
.b-icmp{color:var(--green);border-color:rgba(61,214,140,.4);background:var(--green-soft)}
.b-tcp{color:var(--amber);border-color:rgba(245,165,36,.4);background:var(--amber-soft)}
.h-meta{font-size:12px;color:var(--muted);font-family:var(--mono);margin-top:6px}
.h-meta:empty{display:none}
.portchips{display:flex;flex-wrap:wrap;gap:6px;margin-top:10px}
.h-noports{font-size:12px;color:var(--dim)}
.pchip{font-family:var(--mono);font-size:12px;padding:4px 8px;border-radius:6px;border:1px solid;cursor:default;white-space:nowrap}
.pchip b{font-weight:700}
.pchip i{font-style:normal;opacity:.7;font-size:11px}
.pc-blue{color:#8ab6e8;border-color:rgba(138,182,232,.3);background:rgba(138,182,232,.06)}
.pc-violet{color:#b9a6ef;border-color:rgba(185,166,239,.3);background:rgba(185,166,239,.06)}
.pc-amber{color:#f0b45c;border-color:rgba(240,180,92,.3);background:rgba(240,180,92,.06)}
.pc-cyan{color:#7cc4d4;border-color:rgba(124,196,212,.3);background:rgba(124,196,212,.06)}
.pc-gray{color:#aab4c2;border-color:rgba(170,180,194,.22);background:rgba(170,180,194,.05)}
.empty{border:1px dashed rgba(255,255,255,.14);border-radius:10px;padding:44px;text-align:center;color:var(--muted);font-size:14px}
footer{margin-top:30px;text-align:center;font-size:12px;color:var(--dim)}
.toast{position:fixed;left:50%;bottom:28px;transform:translateX(-50%) translateY(8px);background:#1d2632;
  border:1px solid var(--edge2);color:var(--ink);padding:10px 18px;border-radius:8px;font-size:13px;
  opacity:0;transition:.3s;pointer-events:none;z-index:50;box-shadow:0 10px 34px rgba(0,0,0,.45)}
.toast.show{opacity:1;transform:translateX(-50%) translateY(0)}
@media(prefers-reduced-motion:reduce){
  .cursor,.led.run,.tick,.host{animation:none}
  .axis-cursor,.axis-trail,#subbar{transition:none}
}
</style>
</head>
<body>
<div class="wrap">
  <header>
    <div class="brand">
      <svg class="mark" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
        <path d="M19.07 4.93A10 10 0 1 0 21 12"/>
        <path d="M15.54 8.46A5 5 0 1 0 17 12"/>
        <line x1="12" y1="12" x2="21" y2="3"/>
      </svg>
      <span class="wordmark">NETSCAN<span class="cursor"></span></span>
      <span class="sub">内网存活与端口探测</span>
    </div>
    <div class="readout"><i class="led" id="led"></i><span id="pillText">待机</span><span class="ro-time" id="roTime"></span></div>
  </header>

  <section class="panel">
    <div class="cfg-grid">
      <div>
        <label>目标网段</label>
        <input type="text" id="targets" placeholder="192.168.1.0/24, 10.8.0.0/16 — 留空自动使用本机网段">
        <div class="chips" id="netChips"></div>
      </div>
      <div>
        <label>端口范围</label>
        <input type="text" id="ports" placeholder="留空 = 默认常用端口">
      </div>
    </div>
    <div style="margin-top:14px">
      <label>选项</label>
      <div class="toggles">
        <label class="toggle"><input type="checkbox" id="optTcpPing"><span class="tl">TCP 二次存活</span></label>
        <label class="toggle"><input type="checkbox" id="optBanner" checked><span class="tl">服务指纹</span></label>
        <label class="toggle"><input type="checkbox" id="optNoPorts"><span class="tl">仅 ping 不扫端口</span></label>
      </div>
    </div>
    <details class="adv">
      <summary>高级选项</summary>
      <div class="adv-grid">
        <div><label>Ping 并发</label><input type="number" id="pingWorkers" value="64" min="1" max="512"></div>
        <div><label>端口并发</label><input type="number" id="portWorkers" value="150" min="1" max="512"></div>
        <div><label>Ping 超时(ms)</label><input type="number" id="pingTimeout" value="1000" min="100" max="10000" step="100"></div>
        <div><label>端口超时(s)</label><input type="number" id="portTimeout" value="1" min="0.2" max="10" step="0.1"></div>
      </div>
    </details>
    <div class="actions">
      <button class="btn btn-primary" id="btnStart">开始扫描</button>
      <button class="btn btn-stop" id="btnStop" disabled>停止扫描</button>
      <div class="spacer"></div>
      <button class="btn btn-ghost" id="btnCsv" disabled>导出 CSV</button>
      <button class="btn btn-ghost" id="btnJson" disabled>导出 JSON</button>
    </div>
  </section>

  <section class="axis-wrap" id="axisWrap" style="display:none">
    <div class="axis" id="axis">
      <div class="axis-track"></div>
      <div class="axis-trail" id="axisTrail"></div>
      <div class="axis-cursor" id="axisCursor"></div>
    </div>
    <div class="axis-edges"><span id="edgeL"></span><span id="edgeR"></span></div>
    <div class="readline">
      <span id="phaseText">—</span>
      <span>目标 <b id="rTotal">0</b></span>
      <span>已探测 <b id="rScanned">0</b></span>
      <span>存活 <b id="rAlive">0</b></span>
      <span>开放端口 <b id="rOpen">0</b></span>
    </div>
    <div class="subtrack"><div id="subbar"></div></div>
  </section>

  <div class="res-head">
    <input type="search" id="search" placeholder="筛选 IP / 端口 / 服务…">
    <span id="hostCount">尚无结果</span>
  </div>
  <div class="hosts" id="hostGrid"></div>
  <div class="empty" id="emptyState">点击「开始扫描」，存活主机会实时出现在这里</div>

  <footer>仅限授权网络使用 · 结果仅保存在本机内存中 · 关闭控制台窗口即退出程序</footer>
</div>
<div class="toast" id="toast"></div>

<script>
const SERVICES = __SERVICES__;
const RUNNING = ['prepare','ping','tcp_ping','ports','banner','arp'];
const $ = id => document.getElementById(id);
let last = {phase:'idle', hosts:[]};
let poller = null;
let wasRunning = false;
const cardMap = new Map();

function el(tag, cls, text){
  const e = document.createElement(tag);
  if (cls) e.className = cls;
  if (text != null) e.textContent = text;
  return e;
}
function svcName(p){ return SERVICES[String(p)] || ''; }
function cat(name){
  name = (name||'').toLowerCase();
  if (/(rdp|smb|winrm|msrpc|netbios|ldap|rpc)/.test(name)) return 'pc-blue';
  if (/(ssh|ftp|telnet)/.test(name)) return 'pc-violet';
  if (/(mysql|mssql|oracle|postgres|redis|mongo|memcached|elastic|es-)/.test(name)) return 'pc-amber';
  if (/(http|web|kibana|grafana|prometheus|nacos|odoo|splunk|activemq|rabbitmq|k8s)/.test(name)) return 'pc-cyan';
  return 'pc-gray';
}
function ipNum(ip){
  const p = ip.split('.').map(Number);
  return ((p[0]<<24)|(p[1]<<16)|(p[2]<<8)|p[3])>>>0;
}
function fmtIp(n){
  return [(n>>>24)&255,(n>>>16)&255,(n>>>8)&255,n&255].join('.');
}
function fmtTime(s){
  s = Math.max(0, s||0);
  return s < 60 ? s.toFixed(1)+'s' : Math.floor(s/60)+'m '+Math.round(s%60)+'s';
}
function frac(s){
  switch(s.phase){
    case 'ping':      return s.total ? s.scanned/s.total*0.6 : 0;
    case 'tcp_ping':  return 0.6 + (s.tcp_total ? s.tcp_done/s.tcp_total*0.08 : 0);
    case 'ports':     return 0.68 + (s.ports_total ? s.ports_done/s.ports_total*0.28 : 0);
    case 'banner':    return 0.96 + (s.banner_total ? s.banner_done/s.banner_total*0.03 : 0);
    case 'arp':       return 0.995;
    case 'done':      return 1;
    default:          return s.total && s.scanned ? s.scanned/s.total*0.6 : 0;
  }
}
const PILL = {idle:['待机','led'], prepare:['正在准备','led run'], ping:['正在扫描','led run'],
  tcp_ping:['二次判定','led run'], ports:['正在扫端口','led run'], banner:['抓取指纹','led run'],
  arp:['读取 ARP','led run'], done:['已完成','led done'], stopped:['已停止','led stop'],
  error:['出错','led err']};
function setPill(s){
  const [text, cls] = PILL[s.phase] || ['待机','led'];
  $('led').className = cls;
  $('pillText').textContent = text;
  $('roTime').textContent = s.elapsed ? fmtTime(s.elapsed) : '';
}
let toastTimer = null;
function toast(msg){
  const t = $('toast');
  t.textContent = msg;
  t.classList.add('show');
  clearTimeout(toastTimer);
  toastTimer = setTimeout(()=>t.classList.remove('show'), 2600);
}
function matchFilter(h, q){
  if (!q) return true;
  if (h.ip.toLowerCase().includes(q) || (h.mac||'').toLowerCase().includes(q)) return true;
  return h.ports.some(p => String(p).includes(q) || svcName(p).toLowerCase().includes(q));
}

/* ---- 地址扫掠轴 ---- */
const axisState = {started:null, ticks:new Map()};
function renderAxis(s){
  const wrap = $('axisWrap');
  if (s.axis_start == null || (s.phase === 'idle' && !s.hosts.length)){
    wrap.style.display = 'none';
    return;
  }
  wrap.style.display = '';
  // 新一次扫描: 清空旧刻度
  if (axisState.started !== s.started_ts){
    axisState.ticks.forEach(t=>t.remove());
    axisState.ticks.clear();
    axisState.started = s.started_ts;
    $('edgeL').textContent = fmtIp(s.axis_start);
    $('edgeR').textContent = fmtIp(s.axis_end);
  }
  const span = Math.max(1, s.axis_end - s.axis_start);
  const running = RUNNING.includes(s.phase);
  const p = s.phase === 'ping' ? (s.total ? s.scanned/s.total : 0) : 1;
  $('axisTrail').style.width = (p*100).toFixed(2)+'%';
  $('axisCursor').style.left = 'calc('+((p*100).toFixed(2))+'% - 1px)';
  $('axisCursor').classList.toggle('on', running);
  $('axis').classList.toggle('done', !running);
  s.hosts.forEach(h=>{
    if (axisState.ticks.has(h.ip)) return;
    const f = s.axis_start === s.axis_end ? 50 : (ipNum(h.ip)-s.axis_start)/span*100;
    const t = el('div','tick');
    t.style.left = Math.min(100, Math.max(0, f)).toFixed(2)+'%';
    t.title = h.ip + (h.latency_ms != null ? ' · '+Math.round(h.latency_ms)+'ms' : '');
    t.onclick = ()=>{ $('search').value = h.ip; render(last); };
    $('axis').appendChild(t);
    axisState.ticks.set(h.ip, t);
  });
}

/* ---- 主机卡片 ---- */
function buildCard(){
  const c = el('div','host');
  const top = el('div','h-top');
  const left = el('div');
  c._ip = el('span','h-ip');
  c._lat = el('span','h-lat');
  left.appendChild(c._ip); left.appendChild(c._lat);
  const bd = el('div','h-badges');
  c._badge = el('span','badge');
  bd.appendChild(c._badge);
  top.appendChild(left); top.appendChild(bd);
  c._meta = el('div','h-meta');
  c._ports = el('div','portchips');
  c.appendChild(top); c.appendChild(c._meta); c.appendChild(c._ports);
  return c;
}
function updateCard(c, h, s){
  c._ip.textContent = h.ip;
  c._lat.textContent = h.latency_ms != null ? Math.round(h.latency_ms)+'ms' : '';
  const isIcmp = h.via === 'icmp';
  c._badge.className = 'badge ' + (isIcmp ? 'b-icmp' : 'b-tcp');
  c._badge.textContent = isIcmp ? 'ICMP' : h.via.replace('tcp:','TCP·');
  c._meta.textContent = h.mac ? 'MAC ' + h.mac : '';
  c._ports.textContent = '';
  if (!h.ports.length){
    c._ports.appendChild(el('div','h-noports', s.no_ports ? '仅存活探测' : '常用端口无开放'));
    return;
  }
  h.ports.forEach(p=>{
    const name = svcName(p);
    const chip = el('span','pchip '+cat(name));
    chip.appendChild(el('b',null,String(p)));
    if (name) chip.appendChild(el('i',null,' '+name));
    const b = h.banners[String(p)];
    chip.title = b ? p+' '+name+' — '+b : p+' '+name;
    c._ports.appendChild(chip);
  });
}
function renderHosts(s){
  const running = RUNNING.includes(s.phase);
  const grid = $('hostGrid');
  if (!running && wasRunning){          // 扫描结束时按 IP 排序重排一次
    cardMap.forEach(c=>c.remove());
    cardMap.clear();
  }
  wasRunning = running;
  const q = $('search').value.trim().toLowerCase();
  s.hosts.forEach(h=>{
    let c = cardMap.get(h.ip);
    if (!c){ c = buildCard(); cardMap.set(h.ip, c); grid.appendChild(c); }
    updateCard(c, h, s);
    c.style.display = matchFilter(h, q) ? '' : 'none';
  });
}

function render(s){
  last = s;
  setPill(s);
  renderAxis(s);
  $('phaseText').textContent = s.phase_text;
  $('rTotal').textContent = s.total;
  $('rScanned').textContent = s.scanned;
  $('rAlive').textContent = s.hosts.length;
  $('rOpen').textContent = s.open_count;
  $('subbar').style.width = (frac(s)*100).toFixed(1) + '%';
  const running = RUNNING.includes(s.phase);
  $('btnStart').disabled = running;
  $('btnStop').disabled = !running;
  const has = s.hosts.length > 0;
  $('btnCsv').disabled = !has;
  $('btnJson').disabled = !has;
  $('hostCount').textContent = has ? '存活主机 '+s.hosts.length : '尚无结果';
  $('emptyState').style.display = has ? 'none' : '';
  renderHosts(s);
}
function schedule(s){
  clearTimeout(poller);
  if (RUNNING.includes(s.phase)) poller = setTimeout(poll, 450);
}
function poll(){
  fetch('/api/status').then(r=>r.json()).then(s=>{ render(s); schedule(s); })
    .catch(()=>schedule(last));
}

$('btnStart').onclick = async () => {
  try{
    const body = {
      targets: $('targets').value, ports: $('ports').value,
      tcp_ping: $('optTcpPing').checked, banner: $('optBanner').checked,
      no_ports: $('optNoPorts').checked,
      ping_workers: +$('pingWorkers').value || 64,
      port_workers: +$('portWorkers').value || 150,
      ping_timeout: +$('pingTimeout').value || 1000,
      port_timeout: +$('portTimeout').value || 1.0
    };
    const r = await fetch('/api/start', {method:'POST',
      headers:{'Content-Type':'application/json'}, body: JSON.stringify(body)});
    if (!r.ok){ toast(await r.text()); return; }
    toast('开始扫描');
    poll();
  }catch(e){ toast('启动失败: '+e.message); }
};
$('btnStop').onclick = () => {
  fetch('/api/stop', {method:'POST'}).then(()=>{ toast('正在停止…'); poll(); });
};
$('search').oninput = () => render(last);
$('btnCsv').onclick = () => location.href = '/api/export/csv';
$('btnJson').onclick = () => location.href = '/api/export/json';

$('ports').placeholder = '留空 = 默认 ' + Object.keys(SERVICES).length + ' 个常用端口';
fetch('/api/interfaces').then(r=>r.json()).then(list=>{
  const nets = list.filter(x=>x.network).map(x=>x.network);
  if (!$('targets').value && nets.length) $('targets').value = nets.join(', ');
  const box = $('netChips');
  list.forEach(it=>{
    if (!it.network) return;
    const c = el('button','chip', it.network);
    c.type = 'button';
    c.onclick = () => {
      const cur = $('targets').value.split(',').map(t=>t.trim()).filter(Boolean);
      const i = cur.indexOf(it.network);
      if (i >= 0) cur.splice(i,1); else cur.push(it.network);
      $('targets').value = cur.join(', ');
    };
    box.appendChild(c);
  });
});
poll();
</script>
</body>
</html>
"""
INDEX_HTML = _TEMPLATE.replace(
    "__SERVICES__", json.dumps({str(k): v for k, v in netscan.SERVICES.items()}, ensure_ascii=False))


# ---------------------------------------------------------------- HTTP 服务

class Handler(http.server.BaseHTTPRequestHandler):
    server_version = "NetScan/1.0"

    def log_message(self, fmt, *args):
        pass  # 静默访问日志

    def _send(self, code, ctype, body, extra=None):
        if isinstance(body, str):
            body = body.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def _json(self, obj, code=200):
        self._send(code, "application/json; charset=utf-8", json.dumps(obj, ensure_ascii=False))

    def do_GET(self):
        path = self.path.split("?", 1)[0]
        if path in ("/", "/index.html"):
            self._send(200, "text/html; charset=utf-8", INDEX_HTML)
        elif path == "/api/interfaces":
            out = [{"name": it["name"], "ip": it["ip"], "netmask": it["netmask"] or "",
                    "network": str(it["network"]) if it["network"] else None}
                   for it in netscan.get_interfaces()]
            self._json(out)
        elif path == "/api/status":
            self._json(snapshot())
        elif path == "/api/export/csv":
            stamp = time.strftime("%Y%m%d_%H%M%S")
            self._send(200, "text/csv; charset=utf-8", build_csv(),
                       {"Content-Disposition": f'attachment; filename="netscan_{stamp}.csv"'})
        elif path == "/api/export/json":
            stamp = time.strftime("%Y%m%d_%H%M%S")
            self._send(200, "application/json; charset=utf-8", build_json_export(),
                       {"Content-Disposition": f'attachment; filename="netscan_{stamp}.json"'})
        else:
            self._send(404, "text/plain; charset=utf-8", "not found")

    def do_POST(self):
        path = self.path.split("?", 1)[0]
        n = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(n) if n else b"{}"
        try:
            body = json.loads(raw.decode("utf-8") or "{}")
        except Exception:
            body = {}
        if path == "/api/start":
            if is_running():
                self._send(409, "text/plain; charset=utf-8", "已有扫描正在进行, 请先停止")
                return
            cfg = sanitize_cfg(body)
            STATE.clear()
            STATE.update(new_state())
            STOP.clear()
            threading.Thread(target=do_scan, args=(cfg,), daemon=True).start()
            self._json({"ok": True})
        elif path == "/api/stop":
            STOP.set()
            self._json({"ok": True})
        else:
            self._send(404, "text/plain; charset=utf-8", "not found")


def find_port(start: int) -> int:
    for p in range(start, start + 60):
        try:
            with socket.socket() as s:
                s.bind((HOST, p))
                return p
        except OSError:
            continue
    return 0


def main():
    ap = argparse.ArgumentParser(description="netscan 本地 Web 界面")
    ap.add_argument("--port", type=int, default=8765, help="监听端口(默认 8765, 被占用时自动顺延)")
    ap.add_argument("--no-browser", action="store_true", help="不自动打开浏览器")
    args = ap.parse_args()

    port = find_port(args.port)
    if not port:
        print("[x] 没有可用端口, 请用 --port 指定")
        raise SystemExit(1)
    httpd = http.server.ThreadingHTTPServer((HOST, port), Handler)
    url = f"http://{HOST}:{port}/"
    print("=" * 52)
    print("  NetScan 图形界面已启动")
    print(f"  地址  : {url}")
    print(f"  退出  : 关闭本窗口 或 按 Ctrl+C")
    print("  提示  : 仅限授权网络使用, 结果只存在本机内存")
    print("=" * 52)
    if not args.no_browser:
        threading.Timer(0.4, lambda: webbrowser.open(url)).start()
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        httpd.shutdown()
        print("\n已退出")


if __name__ == "__main__":
    main()