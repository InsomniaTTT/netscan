# NetScan · 内网存活主机与端口探测工具

零依赖的 Windows 内网探测工具：并发 ping 存活探测、TCP 端口扫描、服务识别、MAC 地址回填，提供**桌面、网页、命令行**三种界面，共用同一套探测引擎。

## 功能

- **接口发现** — 自动枚举本机网卡、IP、掩码与所在网段
- **存活探测** — 并发 ICMP ping（兼容中英文系统输出），记录延迟
- **TCP 二次存活判定** — 对禁 ping 主机用常见端口做二次判定，避免漏报
- **端口扫描** — 内置约 64 个常用端口（SSH / RDP / SMB / MySQL / Redis / WebLogic / Docker 等），支持自定义端口与范围
- **服务指纹** — 对开放端口抓取 banner（HTTP / SSH / FTP 等）
- **MAC 地址** — 通过系统 ARP 表自动回填
- **地址扫掠轴** — 把被扫网段画成一条刻度带，存活主机按地址位置点亮绿色刻度，扫完即一张“网段地图”
- **结果导出** — CSV（Excel 直接打开）与 JSON

## 三个版本

| 源文件 | 打包产物 | 形态 | 适用 |
|---|---|---|---|
| `netscan_tk.py` | `netscan_gui.exe` | tkinter 原生窗口 | 日常使用，双击即开 |
| `netscan_web.py` | `netscan_web.exe` | 本地网页界面（自动开浏览器） | 备用 |
| `netscan.py` | `netscan.exe` | 命令行 | 脚本化 / 自动化 |

架构分层：`netscan.py`（探测引擎）→ `netscan_web.py` 内的后端（扫描状态机，网页界面直接使用）→ `netscan_tk.py`（复用同一状态机的桌面界面）。

## 使用

### 桌面版（推荐）

双击 `netscan_gui.exe`：目标网段自动填入本机所在网段，点「开始扫描」即可。支持命令行参数：

```bat
netscan_gui.exe --scan 192.168.1.0/24 --ports 22,80,3389 --geometry 900x700
```

- `--scan` 启动后自动开扫；`--ports` 预填端口；`--geometry` 初始窗口尺寸
- 键盘：**Enter** 开始 / **Esc** 停止；双击行复制 IP；点击扫掠轴刻度定位对应主机

### 命令行版

```bat
python netscan.py --ifaces                                  REM 查看本机接口与网段
python netscan.py 192.168.1.0/24                            REM 扫指定网段(默认常用端口)
python netscan.py 192.168.1.10 10.8.0.0/24 -p 22,80,8000-8100
python netscan.py 192.168.1.0/24 --tcp-ping --banner --csv result.csv
python netscan.py 192.168.1.0/24 --no-ports                 REM 只探测可 ping 的主机
```

### 网页版

```bat
python netscan_web.py            REM 默认 127.0.0.1:8765, 自动打开浏览器
python netscan_web.py --port 9000 --no-browser
```

仅监听本机回环地址，不暴露到局域网。

## 依赖与构建

- **运行**：Python 3.8+，纯标准库；装有 `psutil` 时接口识别更准（可选）
- **打包**：PyInstaller 6+

```bat
python gen_icon.py
python -m PyInstaller --onefile --noconsole --icon=icon.ico --name netscan_gui netscan_tk.py
python -m PyInstaller --onefile --name netscan netscan.py
python -m PyInstaller --onefile --name netscan_web netscan_web.py
```

## 目录结构

```
netscan.py       探测引擎: ping / TCP 端口 / banner / ARP / 接口发现
netscan_web.py   扫描状态机 + 本地 Web 界面(前端内嵌, 无外部资源)
netscan_tk.py    tkinter 桌面界面(仪器面板风格)
gen_icon.py      品牌图标生成(逐像素设计, 输出窗口图标与 icon.ico)
icon.ico         exe 文件图标
```

## 已知设计决策

- 无控制台（`--noconsole`）打包的 exe 中，所有子进程调用都带 `CREATE_NO_WINDOW`，否则每次 ping 都会弹一个 cmd 窗口
- 存活判定不依赖 ping 退出码而是解析输出中的 `TTL=` 字段（中英文系统一致可靠）
- 扫描结果只存内存，导出与否由使用者决定

## 注意

**仅限对你获得授权的网络使用**（自己的办公网 / 家庭网 / 授权测试环境）。对大规模网段的并发探测可能触发安全设备的告警。