# EasyBwrap

基于 [bubblewrap](https://github.com/containers/bubblewrap) (`bwrap`) 的配置驱动型应用沙箱启动器与进程管理器。

> **提示**：个人自用项目，主要在 Arch Linux 环境下调试与使用，不做通用环境保证。

---

## 核心特性

* **声明式 TOML 配置**：支持全局默认 `[defaults]`、预设继承 `extends` 与层级化覆盖。未显式放行的路径/特性一律默认隔离。
* **Pasta 用户态网络隔离**：三挡位网络控制（`net = "isolated"` / `"shared"` / `"off"`）。默认通过 `pasta` 隔离网络命名空间，彻底杜绝沙箱程序借由窗口管理器创建的 X11 抽象套接字（`@/tmp/.X11-unix/X*`）逃逸。
* **systemd 作用域集成**：自动探测并接入 `systemd-run --user --scope`，支持 Cgroup v2 硬件配额（内存、CPU、任务数限制与 IO 权重）；无 systemd 时自动平滑降级。
* **Seccomp 动态过滤**：在配置中编写规则 DSL，运行时即时编译为 BPF 字节码并按内容哈希自动缓存；默认防御 TIOCSTI 终端注入与各类提权逃逸调用，可选支持 32 位兼容模式 (`compat32`)。
* **桌面与外设直通**：按需直通 Wayland、PipeWire 音频、GPU 驱动节点（NVIDIA / DRI）；支持动态隔离的 X11 会话（基于 `xwayland-satellite`）。
* **进程与生命周期控制**：内置任务状态跟踪与生命周期管理（`ps` / `stop` / `kill`），支持平滑升级终止信号（SIGINT -> SIGTERM -> SIGKILL）并自动清理临时环境。

---

## 系统依赖

* **必需**：Linux 内核、Python 3.11+、`bubblewrap` (`bwrap`)
* **可选（按需）**：
  * `passt`（提供 `pasta` 命令，用于 `net = "isolated"` 用户态网络隔离）
  * `systemd`（用于瞬态作用域与 Cgroup 资源限制，缺省时自动降级）
  * `libseccomp` + C 编译器 (`cc`/`gcc`/`clang`)（用于 Seccomp 规则即时编译）
  * `xdg-dbus-proxy`（用于 `dbus = "proxy"` 过滤模式）
  * `xwayland-satellite`（用于 `x11 = true` 独立 X11 协议包装）

---

## 快速上手

默认加载同目录下的 `easy-bwrap.toml`（亦支持通过环境变量 `EASY_BWRAP_CONF` 指定配置路径）。

```sh
# 运行默认预设
./easy-bwrap.py

# 运行指定预设并传递参数
./easy-bwrap.py zsh -l

# 借用 zsh 预设的沙箱环境运行自定义程序
./easy-bwrap.py --as zsh /path/to/my-tool --arg

# 临时覆盖参数 (不修改配置文件)
./easy-bwrap.py --override net=off --override pwd=true opencode

# 仅预览拟执行的完整命令与环境脚本 (不实际启动)
./easy-bwrap.py --print splayer file.mp4

# 查看与管理后台沙箱任务
./easy-bwrap.py ps
./easy-bwrap.py stop <run-id>
./easy-bwrap.py kill <run-id>
```

---

## 配置文件结构速览

配置优先级：`[defaults]` < `extends` < `[presets.<name>]` < `--override`。

```toml
[general]
default = "zsh"
security = true
state_dir = "/tmp/easy-bwrap-state"
systemd = "auto"
blocklist = ["/", "/etc", "/usr", "~:exact", "~/.ssh"]

[defaults]
base = true            # 系统核心基础目录只读挂载
net = "isolated"       # pasta 用户态网络隔离
gpu_dri = true         # GPU /dev/dri 图形直通
pwd = false            # 绑定宿主当前工作目录
vhome = false          # 虚拟隔离家目录
seccomp = true         # 启用系统调用安全过滤

[presets.zsh]
program = "/usr/bin/zsh"
pwd = true
vhome = true
bind = [
  "~/.zshrc:ro-try",
  "~/.config/fontconfig:ro-try",
]

[presets.opencode]
program = "/usr/bin/opencode"
alias = "oc"
pwd = true
seccomp = "browser"
memory_max = "4G"
cpu_quota = "200%"
bind = [
  "~/.config/opencode:create",
  "~/.local/share/opencode:create",
]
```

详细配置项与语法说明请参阅 `easy-bwrap.toml` 内部注释。

---

## 许可协议

GPL-3.0，详见 `LICENSE`。

