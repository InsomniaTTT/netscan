#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
netscan_tk.py —— NetScan 原生桌面界面(tkinter, 无需浏览器)
复用 netscan_web 的扫描状态机与 netscan 探测引擎, 双击 exe 即开窗口。

用法:
  python netscan_tk.py                       # 打开窗口, 手动点击开始
  python netscan_tk.py --scan 192.168.1.0/24 # 启动后自动开始扫描
声明: 仅在你获得授权的网络中使用。
"""

from __future__ import annotations

import argparse
import ipaddress
import math
import platform
import re
import threading
import time

import tkinter as tk
from tkinter import ttk, filedialog, messagebox

import netscan
import netscan_web as core   # 复用 STATE / LOCK / STOP / do_scan / snapshot / 导出

# ---- 仪器面板配色(与网页版同源) ----
BG = "#0e1216"
PANEL = "#141a22"
PANEL_HI = "#1a222c"
FIELD = "#0b0f13"
INK = "#e8e4d9"
MUTED = "#7e8899"
DIM = "#5b6675"
EDGE = "#242e3a"
AMBER = "#f5a524"
AMBER_HI = "#ffb63e"
AMBER_DIM = "#c98a1e"
AMBER_GLOW = "#40300f"
GREEN = "#3dd68c"
RED = "#f0565f"
INK_DARK = "#161006"
DISABLED_FG = "#4a5361"
RULER_MIN = "#161d26"
RULER_MAJ = "#1f2935"
TRAIL = "#33270e"

F_TEXT = ("Microsoft YaHei UI", 10)
F_TEXT_S = ("Microsoft YaHei UI", 9)
F_TEXT_B = ("Microsoft YaHei UI", 10, "bold")
F_MONO = ("Consolas", 10)
F_MONO_S = ("Consolas", 9)
F_WORD = ("Consolas", 15, "bold")

HINT_DEFAULT = "Enter 开始 · Esc 停止 · 双击行复制 IP · 点击刻度定位主机 · 仅限授权网络使用"

PILL = {
    "idle": ("待机", DIM), "prepare": ("正在准备", AMBER), "ping": ("正在扫描", AMBER),
    "tcp_ping": ("二次判定", AMBER), "ports": ("正在扫端口", AMBER),
    "banner": ("抓取指纹", AMBER), "arp": ("读取 ARP", AMBER),
    "done": ("已完成", GREEN), "stopped": ("已停止", AMBER), "error": ("出错", RED),
}


def enable_dpi():
    """Windows 高分屏下让 tkinter 渲染清晰"""
    if platform.system() == "Windows":
        try:
            import ctypes
            ctypes.windll.shcore.SetProcessDpiAwareness(1)
        except Exception:
            pass


def dark_title_bar(root):
    """Win10/11 把窗口标题栏也调成暗色, 避免亮色系统边框破坏深色主题"""
    if platform.system() == "Windows":
        try:
            import ctypes
            root.update_idletasks()
            hwnd = ctypes.windll.user32.GetParent(root.winfo_id())
            val = ctypes.c_int(1)
            for attr in (20, 19):  # DWMWA_USE_IMMERSIVE_DARK_MODE, 新旧两个值
                if ctypes.windll.dwmapi.DwmSetWindowAttribute(
                        hwnd, attr, ctypes.byref(val), ctypes.sizeof(val)) == 0:
                    break
        except Exception:
            pass


def fmt_ip(n: int) -> str:
    return f"{(n >> 24) & 255}.{(n >> 16) & 255}.{(n >> 8) & 255}.{n & 255}"


def ip_int(ip: str) -> int:
    return int(ipaddress.ip_address(ip))


def fmt_time(s: float) -> str:
    s = max(0.0, s or 0.0)
    return f"{s:.1f}s" if s < 60 else f"{int(s // 60)}m {round(s % 60)}s"


def ports_str(host: dict) -> str:
    out = []
    for p in host["ports"]:
        out.append(f"{p} {netscan.service_name(p)}".rstrip())
    return ", ".join(out) if out else "—"


def icon_pixel(x: int, y: int, s: int = 32):
    """品牌图标逐像素设计: 深色圆角底 + 琥珀雷达弧 + 绿芯, 供窗口图标与 .ico 生成共用"""
    cx = cy = (s - 1) / 2
    dx, dy = x - cx, y - cy
    r = math.hypot(dx, dy)
    m, corner = 2, 7
    w = s - m
    px, py = x - m + 0.5, y - m + 0.5
    qx = max(corner, min(px, w - corner))
    qy = max(corner, min(py, w - corner))
    if (px - qx) ** 2 + (py - qy) ** 2 > corner * corner:
        return "#000000", False
    ang = math.degrees(math.atan2(-dy, dx)) % 360
    opening = min(abs(ang - 45), 360 - abs(ang - 45)) < 38  # 弧线朝右上开口
    if r <= 3.2:
        return GREEN, True
    if not opening and (10.4 <= r <= 12.8 or 5.6 <= r <= 7.8):
        return AMBER, True
    return BG, True


class App:
    def __init__(self, root: tk.Tk, autostart: str | None = None,
                 prefill_ports: str | None = None, geometry: str | None = None):
        self.root = root
        root.title("NetScan — 内网存活与端口探测")
        root.configure(bg=BG)

        self._s: dict | None = None
        self._scan_ts = None            # 当前展示的扫描批次(用于清空旧结果)
        self._row_sig: dict = {}
        self._was_running = False
        self._last_phase = "idle"
        self._pulse = False
        self._blink_on = True
        self._adv_open = False

        self._build_style()
        self._build_ui(prefill_ports)
        # 最小尺寸 = 内容自然尺寸: 窗口不能再小, 避免布局被 pack 硬撑后抖动
        root.update_idletasks()
        root.minsize(root.winfo_reqwidth(), root.winfo_reqheight())
        self._center(1020, 680, geometry)
        dark_title_bar(root)
        self.icon_img = self._make_icon()
        root.iconphoto(True, self.icon_img)

        self.refresh()
        self._blink_loop()
        if autostart:
            root.after(400, lambda: self.start_scan(preset=autostart))

    # ---------------------------------------------------------------- 样式

    def _build_style(self):
        style = ttk.Style(self.root)
        style.theme_use("clam")
        style.configure("Treeview", background=FIELD, foreground=INK, fieldbackground=FIELD,
                        rowheight=28, borderwidth=0, font=("Microsoft YaHei UI", 10),
                        bordercolor=BG, lightcolor=BG, darkcolor=BG)
        style.configure("Treeview.Heading", background="#18202b", foreground=MUTED,
                        relief="flat", font=F_TEXT_S, padding=(8, 6),
                        bordercolor=BG, lightcolor=BG, darkcolor=BG)
        style.map("Treeview.Heading", background=[("active", "#1f2836")])
        style.map("Treeview", background=[("selected", "#26415a")],
                 foreground=[("selected", "#eef6ff")])
        style.layout("Vertical.TScrollbar", [
            ("Vertical.Scrollbar.trough", {
                "children": [("Vertical.Scrollbar.thumb", {"expand": "1", "sticky": "nswe"})],
                "sticky": "ns"})])
        style.configure("Vertical.TScrollbar", troughcolor=BG, background="#232f3d",
                        bordercolor=BG, lightcolor="#232f3d", darkcolor="#232f3d",
                        relief="flat", gripcount=0)
        style.map("Vertical.TScrollbar", background=[("active", "#2b3a4d")])

    def _card(self, parent) -> tk.Frame:
        return tk.Frame(parent, bg=PANEL, highlightthickness=1, highlightbackground=EDGE)

    def _label(self, parent, text, fg=INK, font=F_TEXT, bg=PANEL):
        return tk.Label(parent, text=text, fg=fg, bg=bg, font=font)

    def _entry(self, parent, font=F_MONO):
        return tk.Entry(parent, bg=FIELD, fg=INK, insertbackground=INK, relief="flat",
                        bd=5, highlightthickness=1, highlightbackground=EDGE,
                        highlightcolor=AMBER, font=font, disabledbackground=FIELD,
                        disabledforeground=DISABLED_FG)

    def _button(self, parent, text, bg, fg, cmd, active_bg=None, outline=None):
        edge = outline or bg
        b = tk.Button(parent, text=text, command=cmd, bg=bg, fg=fg, bd=0, relief="flat",
                      font=F_TEXT_B, cursor="hand2", activebackground=active_bg or bg,
                      activeforeground=fg, padx=16, pady=7, disabledforeground=DISABLED_FG,
                      highlightthickness=1, highlightbackground=edge, highlightcolor=edge)
        return b

    def _toggle(self, parent, label, var):
        """文字开关: ◉ 开 / ○ 关"""
        def render():
            on = var.get()
            b.config(text=("◉ " if on else "○ ") + label, fg=AMBER if on else MUTED)
        def flip():
            var.set(not var.get())
            render()
        b = tk.Button(parent, command=flip, bg=PANEL, bd=0, relief="flat",
                      font=F_TEXT, cursor="hand2", activebackground=PANEL,
                      activeforeground=INK, anchor="w", padx=0, pady=3)
        render()
        return b

    # ---------------------------------------------------------------- 界面

    def _build_ui(self, prefill_ports: str | None):
        root = self.root

        # ── 顶栏 ──
        head = tk.Frame(root, bg=PANEL, highlightthickness=1, highlightbackground=EDGE)
        head.pack(fill="x")
        hb = tk.Frame(head, bg=PANEL)
        hb.pack(fill="x", padx=16, pady=10)
        left = tk.Frame(hb, bg=PANEL)
        left.pack(side="left")
        self._label(left, "NETSCAN", font=F_WORD).pack(side="left")
        self.blink = tk.Canvas(left, width=8, height=18, bg=PANEL, highlightthickness=0)
        self.blink.pack(side="left", padx=(7, 12))
        self.blink_rect = self.blink.create_rectangle(0, 3, 8, 18, fill=AMBER, outline="")
        self._label(left, "内网存活与端口探测", fg=MUTED, font=F_TEXT).pack(side="left")
        right = tk.Frame(hb, bg=PANEL)
        right.pack(side="right")
        self.led = self._label(right, "●", fg=DIM, font=("Segoe UI", 10))
        self.led.pack(side="left", padx=(0, 8))
        self.pill = self._label(right, "待机", fg=DIM, font=F_TEXT)
        self.pill.pack(side="left")
        self.elapsed = self._label(right, "", fg=DIM, font=F_MONO_S)
        self.elapsed.pack(side="left", padx=(10, 0))

        # ── 配置卡片 ──
        cfg = self._card(root)
        cfg.pack(fill="x", padx=10, pady=(10, 6))
        pad = tk.Frame(cfg, bg=PANEL)
        pad.pack(fill="x", padx=14, pady=12)

        row1 = tk.Frame(pad, bg=PANEL)
        row1.pack(fill="x")
        tgt_f = tk.Frame(row1, bg=PANEL)
        tgt_f.pack(side="left", fill="x", expand=True, padx=(0, 12), anchor="nw")
        self._label(tgt_f, "目标网段", fg=MUTED, font=F_TEXT_S).pack(anchor="w")
        nets = ", ".join(str(it["network"]) for it in netscan.get_interfaces() if it["network"])
        self.e_targets = self._entry(tgt_f)
        if nets:
            self.e_targets.insert(0, nets)
        self.e_targets.pack(fill="x", ipady=3)
        port_f = tk.Frame(row1, bg=PANEL)
        port_f.pack(side="left", fill="x")
        self._label(port_f, "端口范围", fg=MUTED, font=F_TEXT_S).pack(anchor="w")
        self.e_ports = self._entry(port_f)
        if prefill_ports:
            self.e_ports.insert(0, prefill_ports)
        self.e_ports.pack(fill="x", ipady=3)
        self._label(port_f, "留空 = 默认常用端口", fg=DIM, font=F_TEXT_S).pack(anchor="w", pady=(3, 0))

        row2 = tk.Frame(pad, bg=PANEL)
        row2.pack(fill="x", pady=(10, 4))
        self.v_tcp = tk.BooleanVar(value=False)
        self.v_banner = tk.BooleanVar(value=True)
        self.v_noports = tk.BooleanVar(value=False)
        self._toggle(row2, "TCP 二次存活", self.v_tcp).pack(side="left", padx=(0, 16))
        self._toggle(row2, "服务指纹", self.v_banner).pack(side="left", padx=(0, 16))
        self._toggle(row2, "仅 ping 不扫端口", self.v_noports).pack(side="left")
        self.b_adv = tk.Button(row2, text="高级 ▾", command=self._toggle_adv, bg=PANEL,
                               bd=0, relief="flat", font=F_TEXT_S, cursor="hand2",
                               fg=DIM, activebackground=PANEL, activeforeground=INK)
        self.b_adv.pack(side="right")

        self.adv = tk.Frame(pad, bg=PANEL)
        self.adv.pack(fill="x", pady=(4, 2))
        self.adv.pack_forget()
        for text, default, width in (("Ping 并发", "64", 6), ("端口并发", "150", 6),
                                     ("Ping 超时ms", "1000", 8), ("端口超时s", "1", 6)):
            f = tk.Frame(self.adv, bg=PANEL)
            f.pack(side="left", padx=(0, 14))
            self._label(f, text, fg=MUTED, font=F_TEXT_S).pack(anchor="w")
            e = self._entry(f, font=F_MONO)
            e.config(width=width)
            e.insert(0, default)
            e.pack()
            if not hasattr(self, "adv_entries"):
                self.adv_entries = []
            self.adv_entries.append(e)

        row3 = tk.Frame(pad, bg=PANEL)
        row3.pack(fill="x", pady=(10, 0))
        self.b_start = self._button(row3, "开始扫描", AMBER, INK_DARK, self.start_scan, AMBER_HI)
        self.b_start.pack(side="left")
        self.b_stop = self._button(row3, "停止扫描", FIELD, RED, self.stop_scan,
                                   "#161014", outline=EDGE)
        self.b_stop.pack(side="left", padx=(8, 0))
        self.b_stop.config(state="disabled")
        tk.Frame(row3, bg=PANEL).pack(side="left", fill="x", expand=True)
        self.b_csv = self._button(row3, "导出 CSV", FIELD, MUTED, self.export_csv,
                                  "#10161e", outline=EDGE)
        self.b_csv.pack(side="left")
        self.b_csv.config(state="disabled")
        self.b_json = self._button(row3, "导出 JSON", FIELD, MUTED, self.export_json,
                                   "#10161e", outline=EDGE)
        self.b_json.pack(side="left", padx=(8, 0))
        self.b_json.config(state="disabled")

        # ── 地址扫掠轴 ──
        axis_card = self._card(root)
        axis_card.pack(fill="x", padx=10, pady=(0, 6))
        ax = tk.Frame(axis_card, bg=PANEL)
        ax.pack(fill="x", padx=14, pady=(12, 10))
        self.canvas = tk.Canvas(ax, height=44, bg=FIELD, highlightthickness=0)
        self.canvas.pack(fill="x")
        edges = tk.Frame(ax, bg=PANEL)
        edges.pack(fill="x")
        self.edgeL = self._label(edges, "—", fg=DIM, font=F_MONO_S)
        self.edgeL.pack(side="left")
        self.edgeR = self._label(edges, "—", fg=DIM, font=F_MONO_S)
        self.edgeR.pack(side="right")
        self.phase = self._label(ax, "待启动", fg=INK, font=F_MONO)
        self.phase.pack(anchor="w", pady=(8, 0))
        self.canvas.bind("<Configure>", lambda e: self._redraw_axis())

        # ── 结果列表 ──
        res = tk.Frame(root, bg=BG)
        res.pack(fill="both", expand=True, padx=10, pady=(2, 4))
        cols = ("ip", "via", "lat", "mac", "ports")
        self.tree = ttk.Treeview(res, columns=cols, show="headings",
                                 selectmode="browse", height=6)
        heads = {"ip": ("IP 地址", 140), "via": ("存活方式", 90),
                 "lat": ("延迟", 70), "mac": ("MAC", 150), "ports": ("开放端口 · 服务", 220)}
        for cid, (text, w) in heads.items():
            self.tree.heading(cid, text=text, anchor="w")
            self.tree.column(cid, width=w, anchor="w",
                             stretch=(cid == "ports"))
        ysb = ttk.Scrollbar(res, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=ysb.set)
        ysb.pack(side="right", fill="y")
        self.tree.pack(fill="both", expand=True)
        self.tree.tag_configure("odd", background="#10161e")
        self.tree.bind("<Double-1>", lambda e: self._copy_selected())
        self.empty_lbl = tk.Label(res, text="尚无结果 — 点击「开始扫描」开始探测",
                                  fg=DIM, bg=BG, font=F_TEXT)
        self.empty_lbl.place(relx=0.5, rely=0.35, anchor="center")

        # ── 状态栏 ──
        sb = tk.Frame(root, bg=BG)
        sb.pack(fill="x", padx=12, pady=(0, 8))
        self.hint_lbl = self._label(sb, HINT_DEFAULT, fg=DIM, font=F_TEXT_S, bg=BG)
        self.hint_lbl.pack(side="left")

        # 键盘操作: 表单内回车开扫, Esc 停止
        for entry in (self.e_targets, self.e_ports):
            entry.bind("<Return>", lambda e: self.start_scan())
        root.bind("<Escape>", lambda e: self.stop_scan())

    def _center(self, w, h, geometry=None):
        self.root.update_idletasks()
        if geometry:
            m = re.match(r"(\d+)[xX](\d+)", geometry.strip())
            if m:
                w, h = int(m.group(1)), int(m.group(2))
        sw, sh = self.root.winfo_screenwidth(), self.root.winfo_screenheight()
        self.root.geometry(f"{w}x{h}+{max(0, (sw - w) // 2)}+{max(0, (sh - h) // 2 - 30)}")

    # ---------------------------------------------------------------- 交互

    def _toggle_adv(self):
        self._adv_open = not self._adv_open
        if self._adv_open:
            self.adv.pack(fill="x", pady=(4, 2))
            self.b_adv.config(text="高级 ▴")
        else:
            self.adv.pack_forget()
            self.b_adv.config(text="高级 ▾")

    def start_scan(self, preset: str | None = None):
        if core.is_running():
            return
        if preset is not None and preset.strip() and preset.strip() != self.e_targets.get():
            self.e_targets.delete(0, "end")
            self.e_targets.insert(0, preset.strip())   # 让输入框反映实际扫描目标
        cfg = core.sanitize_cfg({
            "targets": (preset if preset is not None else self.e_targets.get()).strip(),
            "ports": self.e_ports.get().strip(),
            "tcp_ping": self.v_tcp.get(),
            "banner": self.v_banner.get(),
            "no_ports": self.v_noports.get(),
            "ping_workers": self._num(self.adv_entries[0], 64),
            "port_workers": self._num(self.adv_entries[1], 150),
            "ping_timeout": self._num(self.adv_entries[2], 1000),
            "port_timeout": self._num(self.adv_entries[3], 1.0),
        })
        core.STATE.clear()
        core.STATE.update(core.new_state())
        core.STOP.clear()
        threading.Thread(target=core.do_scan, args=(cfg,), daemon=True).start()

    def _num(self, entry, default):
        try:
            return float(entry.get())
        except ValueError:
            return default

    def stop_scan(self):
        core.STOP.set()

    def _copy_selected(self):
        sel = self.tree.selection()
        if sel:
            self.root.clipboard_clear()
            self.root.clipboard_append(sel[0])
            self._hint(f"已复制 {sel[0]}")

    def _hint(self, msg):
        self.hint_lbl.config(text=msg)
        self.root.after(2600, lambda: self.hint_lbl.config(text=HINT_DEFAULT))

    def export_csv(self):
        rows = core.snapshot()["hosts"]
        if not rows:
            return
        path = filedialog.asksaveasfilename(
            defaultextension=".csv", confirmoverwrite=True,
            initialfile=f"netscan_{time.strftime('%Y%m%d_%H%M%S')}.csv",
            filetypes=[("CSV 文件", "*.csv")])
        if path:
            with open(path, "wb") as f:
                f.write(core.build_csv())
            self._hint(f"已导出 {path}")

    def export_json(self):
        rows = core.snapshot()["hosts"]
        if not rows:
            return
        path = filedialog.asksaveasfilename(
            defaultextension=".json", confirmoverwrite=True,
            initialfile=f"netscan_{time.strftime('%Y%m%d_%H%M%S')}.json",
            filetypes=[("JSON 文件", "*.json")])
        if path:
            with open(path, "wb") as f:
                f.write(core.build_json_export())
            self._hint(f"已导出 {path}")

    def _locate(self, ip):
        if self.tree.exists(ip):
            self.tree.selection_set(ip)
            self.tree.see(ip)

    # ---------------------------------------------------------------- 扫掠轴

    def _redraw_axis(self):
        c = self.canvas
        c.delete("all")
        w = max(20, c.winfo_width())
        for x in range(4, w - 4, 6):
            fill = RULER_MAJ if x % 48 < 6 else RULER_MIN
            c.create_line(x, 5, x, 39, fill=fill)
        s = self._s
        c.create_rectangle(0, 0, 3, 44, fill=TRAIL, outline="", tags="trail")
        c.create_line(3, 4, 3, 40, fill=AMBER_GLOW, width=6, tags="glow")
        c.create_line(3, 0, 3, 44, fill=FIELD, width=2, tags="cursor")
        if not s or s.get("axis_start") is None:
            c.itemconfigure("glow", state="hidden")
            return
        start, end = s["axis_start"], s["axis_end"]
        span = max(1, end - start)
        inner = w - 6
        for h in s["hosts"]:
            f = 0.5 if start == end else (ip_int(h["ip"]) - start) / span
            x = int(f * inner) + 3
            tag = "ip:" + h["ip"]
            c.create_line(x, 6, x, 38, fill=GREEN, width=3, tags=(tag,))
            tip = h["ip"] + (f" · {h['latency_ms']:.0f}ms" if h["latency_ms"] is not None else "")
            c.tag_bind(tag, "<Enter>", lambda e, t=tip: self._hint(t))
            c.tag_bind(tag, "<Button-1>", lambda e, ip=h["ip"]: self._locate(ip))
        p = s["scanned"] / s["total"] if (s["phase"] == "ping" and s["total"]) else 1.0
        x = int(p * inner) + 3
        c.coords("trail", 0, 0, x, 44)
        c.coords("cursor", x, 0, x, 44)
        running = s["phase"] in core.RUNNING_PHASES
        c.itemconfigure("cursor", fill=AMBER if running else FIELD)
        c.coords("glow", x, 4, x, 40)
        c.itemconfigure("glow", state="normal" if running else "hidden")
        trail_fill = TRAIL if (running and p > 0.02) else FIELD
        c.itemconfigure("trail", fill=trail_fill)

    def _make_icon(self):
        """把品牌图标设计渲染成窗口图标"""
        S = 32
        img = tk.PhotoImage(width=S, height=S)
        for y in range(S):
            row = " ".join(icon_pixel(x, y, S)[0] for x in range(S))
            img.put("{" + row + "}", to=(0, y))
        for y in range(S):
            for x in range(S):
                if not icon_pixel(x, y, S)[1]:
                    img.transparency_set(x, y, True)
        return img

    # ---------------------------------------------------------------- 状态刷新

    def _blink_loop(self):
        self._blink_on = not self._blink_on
        self.blink.itemconfigure(self.blink_rect, fill=AMBER if self._blink_on else PANEL)
        self.root.after(800, self._blink_loop)

    def refresh(self):
        self.root.after(200, self.refresh)
        try:
            self._apply(core.snapshot())
        except Exception:
            import traceback
            traceback.print_exc()

    def _apply(self, s: dict):
        self._s = s
        running = s["phase"] in core.RUNNING_PHASES

        # 顶栏(运行中 LED 呼吸)
        text, color = PILL.get(s["phase"], ("待机", DIM))
        if running:
            self._pulse = not self._pulse
            color = AMBER if self._pulse else AMBER_DIM
        self.led.config(text="●", fg=color)
        self.pill.config(text=text, fg=color)
        self.elapsed.config(text=fmt_time(s["elapsed"]) if s["elapsed"] else "")

        # 阶段文字与轴端点
        self.phase.config(text=s["phase_text"] or "待启动",
                          fg=RED if s["phase"] == "error" else INK)
        if s["phase"] == "error" and self._last_phase != "error":
            messagebox.showerror("扫描出错", s["error"] or "未知错误")
        self._last_phase = s["phase"]
        if s["axis_start"] is not None:
            self.edgeL.config(text=fmt_ip(s["axis_start"]))
            self.edgeR.config(text=fmt_ip(s["axis_end"]))

        # 新一轮扫描: 清空旧结果与轴端点(避免失败后残留上一次的信息)
        if s["started_ts"] != self._scan_ts:
            self._scan_ts = s["started_ts"]
            for iid in self.tree.get_children():
                self.tree.delete(iid)
            self._row_sig.clear()
            self.edgeL.config(text="—")
            self.edgeR.config(text="—")

        # 扫描结束时按 IP 重排一次, 并重算斑马纹
        if self._was_running and not running:
            for idx, h in enumerate(s["hosts"]):
                if self.tree.exists(h["ip"]):
                    self.tree.move(h["ip"], "", idx)
            for idx, iid in enumerate(self.tree.get_children()):
                self.tree.item(iid, tags=("odd",) if idx % 2 else ())
        self._was_running = running

        # 结果表
        for h in s["hosts"]:
            iid = h["ip"]
            values = (h["ip"], "ICMP" if h["via"] == "icmp" else h["via"].replace("tcp:", "TCP·"),
                      f"{h['latency_ms']:.0f}ms" if h["latency_ms"] is not None else "—",
                      h["mac"] or "—", ports_str(h))
            sig = tuple(values)
            if iid not in self._row_sig:
                idx = len(self.tree.get_children())
                self.tree.insert("", "end", iid=iid, values=values,
                                 tags=("odd",) if idx % 2 else ())
                self._row_sig[iid] = sig
            elif self._row_sig[iid] != sig:
                self.tree.item(iid, values=values)
                self._row_sig[iid] = sig

        # 扫掠轴
        self._redraw_axis()

        # 空状态覆盖层
        if s["hosts"]:
            if self.empty_lbl.winfo_ismapped():
                self.empty_lbl.place_forget()
        elif not self.empty_lbl.winfo_ismapped():
            self.empty_lbl.place(relx=0.5, rely=0.35, anchor="center")

        # 按钮
        self.b_start.config(state="disabled" if running else "normal")
        self.b_stop.config(state="normal" if running else "disabled")
        has = bool(s["hosts"])
        self.b_csv.config(state="normal" if has else "disabled")
        self.b_json.config(state="normal" if has else "disabled")


def main():
    enable_dpi()
    ap = argparse.ArgumentParser(description="NetScan 桌面版(无需浏览器)")
    ap.add_argument("--scan", help="启动后自动开始扫描的目标, 如 192.168.1.0/24")
    ap.add_argument("--ports", help="预填端口列表, 如 22,80,8000-8100")
    ap.add_argument("--geometry", help="初始窗口尺寸, 如 760x720")
    args = ap.parse_args()

    root = tk.Tk()
    App(root, autostart=args.scan, prefill_ports=args.ports, geometry=args.geometry)
    root.mainloop()


if __name__ == "__main__":
    main()