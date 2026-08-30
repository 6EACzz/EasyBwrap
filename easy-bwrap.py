#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""run-sandbox — 配置驱动的通用 bwrap 沙箱启动器（Python 重写版）

与旧版 run-sandbox.sh 的区别 / 改进:
  * Python 在启动时一次性解析并编译整个脚本, 运行期间修改脚本文件不会影响本次运行;
  * 使用标准库 tomllib 解析 TOML, 不再手写逐行解析, 引号/注释/类型错误都能可靠处理;
  * --print 仅打印将要执行的命令, 不启动 bwrap / xdg-dbus-proxy, 不做交互确认;
  * --override KEY=VALUE 可多次出现, 在运行时临时覆盖参数 (优先级最高);
  * --as/--preset PRESET 可借用某一预设的沙箱配置, 运行另一个预设的程序或自定义可执行程序;
  * 预设可通过 extends 引用另一预设, 优先级:
        全局默认([features]/[general]) < extends 引用的预设 < 预设自身配置 < --override
  * [seccomp] 支持 default + 多个自定义过滤文本 (filterA 等); 运行时生成 C
        并即时编译, 导出 BPF 后通过 --add-seccomp-fd 传给 bwrap (参考 flatpak);
  * X11 display 在 200..999 动态分配, 避免硬编码编号冲突。

用法:
  run-sandbox [选项] [<预设名|别名>] [程序参数...]
  run-sandbox edit [编辑器参数...]
  run-sandbox ps [--json]                     # 列出正在运行的任务
  run-sandbox stop <run-id>                   # 中断 (SIGINT, 按需升级)
  run-sandbox kill <run-id>                   # 强行停止 (SIGKILL)

ps/stop/kill/edit 为保留命令; 若配置中恰有同名预设/别名, 该名称优先解析为预设。

选项 (只能出现在 <程序> 之前; 程序及其参数永远放在末尾):
  -h, --help                 显示本帮助
  --print                    仅打印拟执行的命令, 不实际运行任何程序
  --override KEY=VALUE       临时覆盖参数, 可重复使用
                             (特性/dbus/dbus_whitelist/setenv/bind/security/blocklist/program)
  --as, --preset PRESET      使用 PRESET(预设名或别名) 的沙箱配置; 其后的程序可以是:
                             - 另一已登记预设名/别名 (执行该预设的 program)
                             - 自定义可执行文件 (绝对/相对路径, 或 PATH 中的命令;
                               当前目录下的裸文件名请写成 ./foo)

示例:
  run-sandbox                                    # 运行 [general] default
  run-sandbox zsh -l                             # 运行 zsh 预设
  run-sandbox --print splayer file.mp4           # 只打印 bwrap 命令
  run-sandbox --override pwd=on --override dbus=off opencode
  run-sandbox --as zsh opencode --some-flag      # 用 zsh 的沙箱配置运行 opencode 的程序
  run-sandbox --as zsh --override net=off /opt/bin/custom --arg

配置: 默认使用本脚本同目录的 run-sandbox.toml, 可用环境变量 RUN_SANDBOX_CONF 覆盖。
状态: 每个运行任务在 [general] state_dir 下有唯一子目录, 退出或被 stop/kill 后自动清理。
原则: 显式指定才分配 —— 未列出的特性/绑定/程序一律不生效
(唯一例外: seccomp 特性默认 true, 可在 [features] 或预设中显式关闭)。
"""

from __future__ import annotations

import copy
import fcntl
import hashlib
import json
import os
import random
import re
import secrets
import shlex
import shutil
import signal
import stat
import subprocess
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path

try:
    import tomllib
except ModuleNotFoundError:  # pragma: no cover - Python < 3.11
    try:
        import tomli as tomllib  # type: ignore[no-redef]
    except ModuleNotFoundError:
        tomllib = None  # type: ignore[assignment]


SCRIPT_DIR = Path(__file__).resolve().parent

FEATURES = (
    "base",
    "gpu.nv",
    "gpu.dri",
    "tmpfs",
    "shm",
    "pwd",
    "net",
    "vtty",
    "wayland",
    "pipewire",
    "x11",
    "vhome",
    "seccomp",
)
FEATURE_SET = set(FEATURES)
# 兼容旧名: home_virtual -> vhome; new_session -> vtty
FEATURE_ALIASES = {"home_virtual": "vhome", "new_session": "vtty"}
# seccomp 是安全过滤开关, 与普通 feature 一样参与全局默认/预设覆盖/--override,
# 但其默认值为 true (在 load_config 初始化 feature_defaults 时处理)。
FEATURE_DEFAULT_TRUE = {"seccomp"}
DBUS_MODES = ("off", "proxy", "direct")
BIND_MODES = ("rw", "rw-try", "create", "ro", "ro-try")


def canonical_feature(name: str) -> str:
    return FEATURE_ALIASES.get(name, name)

# --print 模式下, 运行目录/dbus/vhome 使用 shell 变量占位参数。
# 使用 str 子类作为哨兵, 避免与用户程序参数恰好同名时被误当作 shell 变量。
class _ShellRef(str):
    pass


RUN_DIR_ARG = _ShellRef('"$RUN_SANDBOX_RUN_DIR"')
DBUS_BUS_ARG = _ShellRef('"$RUN_SANDBOX_RUN_DIR/dbus/bus"')
VHOME_DIR_ARG = _ShellRef('"$RUN_SANDBOX_RUN_DIR/vhome"')

# X11: 在高端范围动态分配 display 号, 避免与宿主 X server / 其他实例冲突
X11_DISPLAY_MIN = 200
X11_DISPLAY_MAX = 999


def x11_wrap_script(display: int) -> str:
    return f"""\
mkdir -p /tmp/.X11-unix
xwayland-satellite :{display} >/dev/null 2>&1 &
i=0
while [ "$i" -lt 40 ] && [ ! -S /tmp/.X11-unix/X{display} ]; do
  sleep 0.05
  i=$((i+1))
done
exec "$@"
"""

USAGE = """\
用法:
  run-sandbox [选项] [<预设名|别名>] [程序参数...]
  run-sandbox edit [编辑器参数...]
  run-sandbox ps [--json]                     # 列出正在运行的任务
  run-sandbox stop <run-id>                   # 中断 (SIGINT, 按需升级)
  run-sandbox kill <run-id>                   # 强行停止 (SIGKILL)

ps/stop/kill/edit 为保留命令; 若配置中恰有同名预设/别名, 该名称优先解析为预设。

选项 (只能出现在 <程序> 之前; 程序及其参数永远放在末尾):
  -h, --help                 显示本帮助
  --print                    仅打印拟执行的命令, 不实际运行任何程序
  --override KEY=VALUE       临时覆盖参数, 可重复使用
  --as, --preset PRESET      使用 PRESET(预设名或别名) 的沙箱配置运行另一预设程序或自定义程序

--override 支持的 KEY:
  base gpu.nv gpu.dri tmpfs shm pwd net vtty wayland pipewire x11 vhome seccomp
    (取值: on|off 或 true|false|yes|no|1|0; seccomp 还可取 [seccomp] 配置名)
  dbus        off|proxy|direct
  dbus_whitelist  逗号/空格分隔的 D-Bus 名称, 追加到白名单
  setenv     K=V (可重复, 覆盖同名变量)
  bind       src[:dst][:mode], 追加绑定 (mode: rw|rw-try|create|ro|ro-try)
  security   on|off
  blocklist  路径[:exact], 追加到安全黑名单
  program    绝对路径 (或 PATH 命令), 覆盖本次执行的程序入口

状态目录: [general] state_dir (默认 /tmp/run-sandbox-state), 每个运行任务使用
该目录下唯一的 <预设名>.<随机串>/ 子目录记录运行信息, 退出后自动清理。

seccomp: 配置文件末尾的 [seccomp] 可放多个多行过滤文本; default 为默认档,
其他键为自定义档。preset/--override 中 seccomp=true 用 default,
seccomp="配置名" 选自定义档, seccomp=false 关闭。启用时即时编译并导出 BPF,
通过 --add-seccomp-fd 传给 bwrap。首次编译结果缓存在
<state_dir>/.seccomp-cache/, 文件名含文本 BLAKE2b 哈希, 缓存不自动清理。
X11 display 编号在 200..999 动态分配, 避免与宿主/其他实例冲突。

示例:
  run-sandbox --print splayer file.mp4
  run-sandbox --override pwd=on --override dbus=off opencode
  run-sandbox --as zsh opencode --some-flag
  run-sandbox --as zsh --override net=off /opt/bin/custom --arg
"""


class Abort(Exception):
    """配置或运行错误: 打印 Abort 后以非零状态退出。"""


def abort(message: str) -> "Abort":
    raise Abort(message)


def warn(message: str) -> None:
    print(f"[warn] {message}", file=sys.stderr)


def shlex_split_safe(text: str, where: str) -> list[str]:
    try:
        return shlex.split(text)
    except ValueError as exc:
        abort(f"{where} 无法按 shell 语法解析: {exc}")
    raise AssertionError("unreachable")


def normalize_rc(rc: int) -> int:
    return rc if rc >= 0 else 128 + (-rc)


def run_cmd(argv: list[str]) -> int:
    try:
        return subprocess.run(argv).returncode
    except OSError as exc:
        abort(f"无法执行 {argv[0] if argv else '<空命令>'}: {exc}")
        raise AssertionError("unreachable")


def shell_join_argv(argv: list[str]) -> str:
    """把 argv 渲染为可安全粘贴到 POSIX shell 的单行命令。"""
    parts: list[str] = []
    for arg in argv:
        if isinstance(arg, _ShellRef):
            parts.append(str(arg))  # 保留 shell 变量展开, 不转义
        else:
            parts.append(shlex.quote(arg))
    return " ".join(parts)


# ---------------------------------------------------------------------------
# 命令行解析: 选项只允许出现在程序名之前; 程序名之后的一切原样传给程序。
# ---------------------------------------------------------------------------


@dataclass
class CliOptions:
    print_mode: bool = False
    overrides: list[str] = field(default_factory=list)
    as_preset: str | None = None
    app: str | None = None
    app_args: list[str] = field(default_factory=list)
    help: bool = False


def parse_cli(argv: list[str]) -> CliOptions:
    opts = CliOptions()
    i = 0
    while i < len(argv):
        arg = argv[i]
        if arg in ("-h", "--help"):
            opts.help = True
            return opts

        if arg == "--print":
            opts.print_mode = True
            i += 1
            continue

        if arg in ("--as", "--preset"):
            if i + 1 >= len(argv):
                abort(f"{arg} 需要一个预设名")
            if opts.as_preset is not None:
                abort("--as/--preset 只能出现一次")
            opts.as_preset = argv[i + 1]
            if not opts.as_preset:
                abort(f"{arg} 的预设名不能为空")
            i += 2
            continue
        if arg.startswith("--as=") or arg.startswith("--preset="):
            flag, value = arg.split("=", 1)
            if not value:
                abort(f"{flag} 的预设名不能为空")
            if opts.as_preset is not None:
                abort("--as/--preset 只能出现一次")
            opts.as_preset = value
            i += 1
            continue

        if arg == "--override":
            if i + 1 >= len(argv):
                abort("--override 需要一个 KEY=VALUE 参数")
            spec = argv[i + 1]
            if "=" not in spec:
                abort(f"--override 参数格式须为 KEY=VALUE: {spec}")
            opts.overrides.append(spec)
            i += 2
            continue
        if arg.startswith("--override="):
            spec = arg.split("=", 1)[1]
            if "=" not in spec:
                abort(f"--override 参数格式须为 KEY=VALUE: {spec}")
            opts.overrides.append(spec)
            i += 1
            continue

        if arg == "--":
            if i + 1 >= len(argv):
                abort("-- 之后需要给出程序名")
            opts.app = argv[i + 1]
            opts.app_args = argv[i + 2 :]
            return opts

        if arg.startswith("-") and arg != "-":
            abort(
                f"未知选项 '{arg}'。选项(--print/--override/--as/--preset)只能放在程序名之前, "
                "程序及其参数只放在末尾; 如需向程序传递以 '-' 开头的参数, 请先写程序名。"
            )

        opts.app = arg
        opts.app_args = argv[i + 1 :]
        return opts

    return opts


# ---------------------------------------------------------------------------
# 配置定位与可信边界检查
# ---------------------------------------------------------------------------


def find_config_path() -> Path:
    env = os.environ.get("RUN_SANDBOX_CONF")
    path = Path(os.path.expanduser(env)) if env else SCRIPT_DIR / "run-sandbox.toml"
    if not path.is_file():
        abort(f"找不到配置文件 {path}")
    return path


def open_config_trusted(path: Path):
    """以只读方式打开配置, 并对**同一文件描述符**做信任边界检查。

    先 open 再 fstat, 保证属主/权限检查与后续解析针对同一个 inode,
    避免检查与打开两步之间通过符号链接/文件替换进行 TOCTOU 绕过。
    """
    try:
        fd = os.open(path, os.O_RDONLY)
    except OSError as exc:
        abort(f"无法读取配置文件 {path}: {exc}")
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            abort(f"配置文件不是普通文件: {path}")
        if st.st_uid not in (os.getuid(), 0):
            abort(f"配置文件所有者须为当前用户或 root: {path}")
        if st.st_mode & 0o022:
            abort(
                f"配置文件组/其他可写, 请执行: chmod go-w {shlex.quote(str(path))}"
            )
        return os.fdopen(fd, "rb")
    except BaseException:
        os.close(fd)
        raise


# ---------------------------------------------------------------------------
# 配置数据结构与解析
# ---------------------------------------------------------------------------


@dataclass
class BindSpec:
    src: str
    dst: str | None = None
    mode: str = "rw"


@dataclass
class SeccompRule:
    action: str
    syscalls: list[str]
    errno: str | None = None


@dataclass
class SeccompProfile:
    name: str = "default"
    default_action: str = "allow"
    default_errno: str = "EPERM"
    rules: list[SeccompRule] = field(default_factory=list)
    filter_text: str = ""


@dataclass
class PresetRaw:
    section: str
    program: str | None = None
    extends: str | None = None
    aliases: list[str] = field(default_factory=list)
    feature_overrides: dict[str, bool] = field(default_factory=dict)
    dbus: str | None = None
    dbus_whitelist: list[str] | None = None
    setenv: list[tuple[str, str]] | None = None
    binds: list[BindSpec] | None = None
    seccomp_profile: str | None = None


@dataclass
class EffectivePreset:
    name: str
    program: str = ""
    features: dict[str, bool] = field(default_factory=dict)
    dbus: str = "off"
    dbus_whitelist: list[str] = field(default_factory=list)
    setenv: dict[str, str] = field(default_factory=dict)
    binds: list[BindSpec] = field(default_factory=list)
    seccomp_profile: str = "default"
    chain: list[str] = field(default_factory=list)


@dataclass
class GeneralCfg:
    default: str | None = None
    editor: str | None = None
    security: bool = False
    blocklist: list[tuple[str, str]] = field(default_factory=list)
    dbus: str = "off"
    dbus_whitelist: list[str] = field(default_factory=list)
    state_dir: str = "/tmp/run-sandbox-state"


@dataclass
class Config:
    path: Path
    general: GeneralCfg
    feature_defaults: dict[str, bool]
    aliases: dict[str, str]
    presets: dict[str, PresetRaw]
    effective: dict[str, EffectivePreset] = field(default_factory=dict)
    seccomp_profiles: dict[str, SeccompProfile] = field(default_factory=dict)


def _table(value: object, where: str) -> dict:
    if not isinstance(value, dict):
        abort(f"{where} 须为 TOML 表")
    return value


def ensure_no_empty_tables(node: object, where: str) -> None:
    """拒绝空表, 避免空表在 flatten 时被静默忽略。"""
    if isinstance(node, dict):
        if not node:
            abort(f"{where} 不能为空表")
        for key, value in node.items():
            ensure_no_empty_tables(value, f"{where}.{key}")


def flatten_dotted(table: dict) -> list[tuple[str, object]]:
    """展开 TOML 点号键形成的嵌套表 (如 gpu.nv = true -> ("gpu.nv", true))。"""
    result: list[tuple[str, object]] = []

    def walk(node: dict, prefix: str) -> None:
        for key, value in node.items():
            full = f"{prefix}.{key}" if prefix else str(key)
            if isinstance(value, dict):
                walk(value, full)
            else:
                result.append((full, value))

    walk(table, "")
    return result


def parse_bool(value: object, where: str) -> bool:
    if not isinstance(value, bool):
        abort(f"{where} 须为 true/false")
    return value


def parse_cli_bool(value: str, key: str) -> bool:
    v = value.strip().lower()
    if v in ("on", "true", "yes", "1"):
        return True
    if v in ("off", "false", "no", "0"):
        return False
    abort(f"--override {key} 的值须为 on|off (或 true|false|yes|no|1|0): {value}")
    raise AssertionError("unreachable")


def parse_dbus_mode(value: object, where: str) -> str:
    if not isinstance(value, str):
        abort(f"{where} 须为 off|proxy|direct")
    mode = value.strip().lower()
    if mode not in DBUS_MODES:
        abort(f"{where} 须为 off|proxy|direct (on 已废弃, 请用 proxy): {value}")
    return mode


def split_list_value(value: object, where: str) -> list[str]:
    """把字符串或字符串数组规范化为去空白后的字符串列表。"""
    if isinstance(value, str):
        return [item for item in value.replace(",", " ").split() if item]
    if isinstance(value, list):
        items: list[str] = []
        for item in value:
            if not isinstance(item, str):
                abort(f"{where} 数组元素须为字符串")
            text = item.strip()
            if text:
                items.append(text)
        return items
    abort(f"{where} 须为字符串或字符串数组")


def parse_setenv(value: object, where: str) -> list[tuple[str, str]]:
    result: list[tuple[str, str]] = []

    def add_kv(kv: str) -> None:
        if "=" not in kv:
            abort(f"{where} 的 setenv 条目须为 K=V: {kv}")
        key, val = kv.split("=", 1)
        key = key.strip()
        if not key:
            abort(f"{where} 的 setenv 条目变量名不能为空: {kv}")
        result.append((key, val))

    if isinstance(value, dict):
        for key, val in value.items():
            key = str(key).strip()
            if not key or "=" in key:
                abort(f"{where} 的 setenv 变量名非法: {key!r}")
            if isinstance(val, bool):
                text = "true" if val else "false"
            else:
                text = str(val)
            result.append((key, text))
        return result

    if isinstance(value, str):
        for kv in shlex_split_safe(value, where):
            add_kv(kv)
        return result

    if isinstance(value, list):
        for item in value:
            if not isinstance(item, str):
                abort(f"{where} 的 setenv 数组元素须为 K=V 字符串")
            add_kv(item)
        return result

    abort(f"{where} 的 setenv 须为 K=V 字符串、字符串数组或表 (如 {{ K = \"V\" }})")
    raise AssertionError("unreachable")


def parse_bind_string(item: str, where: str) -> BindSpec:
    if not item.strip():
        abort(f"{where} 的 bind 条目不能为空")
    parts = item.split(":")
    src = parts[0]
    dst: str | None = None
    mode = "rw"

    if len(parts) == 1:
        pass
    elif len(parts) == 2:
        if parts[1] in BIND_MODES:
            mode = parts[1]
        else:
            dst = parts[1]
    else:
        if parts[-1] not in BIND_MODES:
            abort(
                f"{where} 的 bind 条目无法解析 (仅支持 src[:dst][:mode]): {item}"
            )
        mode = parts[-1]
        middle = parts[1:-1]
        if not middle or any(not p for p in middle):
            abort(f"{where} 的 bind 条目目标路径为空: {item}")
        dst = ":".join(middle)

    if not src:
        abort(f"{where} 的 bind 条目源路径为空: {item}")
    if dst == "":
        abort(f"{where} 的 bind 条目目标路径为空: {item}")
    return BindSpec(src=src, dst=dst, mode=mode)


def parse_bind(value: object, where: str) -> list[BindSpec]:
    specs: list[BindSpec] = []

    def add_one(item: object) -> None:
        if isinstance(item, str):
            specs.append(parse_bind_string(item, where))
            return
        if isinstance(item, dict):
            allowed = {"src", "dst", "mode"}
            unknown = set(item) - allowed
            if unknown:
                abort(f"{where} 的 bind 表含未知键: {', '.join(sorted(unknown))}")
            src = item.get("src")
            if not isinstance(src, str) or not src.strip():
                abort(f"{where} 的 bind 表缺少字符串 src")
            dst = item.get("dst")
            mode = item.get("mode", "rw")
            if dst is not None and (not isinstance(dst, str) or not dst.strip()):
                abort(f"{where} 的 bind 表 dst 须为非空字符串")
            if not isinstance(mode, str) or mode not in BIND_MODES:
                abort(f"{where} 的 bind 表 mode 须为 {'|'.join(BIND_MODES)}")
            specs.append(
                BindSpec(
                    src=src.strip(),
                    dst=dst.strip() if isinstance(dst, str) else dst,
                    mode=mode,
                )
            )
            return
        abort(f"{where} 的 bind 数组元素须为字符串或 {{ src=..., dst=..., mode=... }} 表")

    if isinstance(value, (str, dict)):
        add_one(value)
    elif isinstance(value, list):
        for item in value:
            add_one(item)
    else:
        abort(f"{where} 的 bind 须为字符串、表或字符串/表数组")
    return specs


def parse_blocklist_entry(raw: str, where: str) -> tuple[str, str]:
    item = raw.strip()
    if not item:
        abort(f"{where} 的 blocklist 条目不能为空")
    mode = "tree"
    path_text = item
    if item.endswith(":exact"):
        mode = "exact"
        path_text = item[: -len(":exact")]
    elif ":" in item:
        abort(f"{where} 的 blocklist 条目只支持 路径 或 路径:exact: {item}")
    path_text = os.path.expanduser(path_text).strip()
    if not path_text:
        abort(f"{where} 的 blocklist 路径不能为空: {item}")
    normalized = path_text if path_text == "/" else path_text.rstrip("/")
    if not normalized:
        abort(f"{where} 的 blocklist 路径非法: {item}")
    return os.path.realpath(normalized), mode


def parse_general(table: dict) -> GeneralCfg:
    general = GeneralCfg()
    for key, value in table.items():
        if key == "default":
            if not isinstance(value, str) or not value.strip():
                abort("[general] default 须为非空字符串 (预设名或别名)")
            general.default = value.strip()
        elif key == "editor":
            if not isinstance(value, str) or not value.strip():
                abort("[general] editor 须为非空字符串")
            general.editor = value.strip()
        elif key == "security":
            if isinstance(value, str) and value.strip().lower() in ("on", "off"):
                abort(
                    "检测到旧版 security=on|off 写法; 新格式请用 TOML 布尔值: "
                    "security = true|false"
                )
            general.security = parse_bool(value, "[general] security")
        elif key == "blocklist":
            for item in split_list_value(value, "[general] blocklist"):
                general.blocklist.append(parse_blocklist_entry(item, "[general] blocklist"))
        elif key == "state_dir":
            if not isinstance(value, str) or not value.strip():
                abort("[general] state_dir 须为非空绝对路径字符串")
            state_dir = os.path.expanduser(value.strip())
            if not os.path.isabs(state_dir):
                abort(f"[general] state_dir 须为绝对路径: {value}")
            general.state_dir = state_dir
        elif key == "dbus":
            general.dbus = parse_dbus_mode(value, "[general] dbus")
        elif key == "dbus_whitelist":
            general.dbus_whitelist = split_list_value(value, "[general] dbus_whitelist")
        else:
            abort(f"[general] 未知键 '{key}'")
    return general


def parse_preset_aliases(value: object, where: str) -> list[str]:
    """alias 是预设的入口别名字符串或字符串数组; 不参与 extends 继承。"""
    if isinstance(value, str):
        if not value.strip():
            abort(f"{where} alias 须为非空字符串")
        return [value.strip()]
    if isinstance(value, list):
        aliases: list[str] = []
        for item in value:
            if not isinstance(item, str) or not item.strip():
                abort(f"{where} alias 数组元素须为非空字符串")
            aliases.append(item.strip())
        if not aliases:
            abort(f"{where} alias 数组不能为空")
        return aliases
    abort(f"{where} alias 须为字符串或字符串数组")
    raise AssertionError("unreachable")


SECCOMP_DEFAULT_ACTIONS = ("allow", "deny", "errno", "kill", "log")
SECCOMP_ERRNO_ALLOWLIST = {
    "EPERM",
    "EACCES",
    "EINVAL",
    "ENOSYS",
    "ENOENT",
    "ENOTTY",
    "ENETUNREACH",
    "ECONNREFUSED",
}


def parse_seccomp_filter(text: str, where: str = "[seccomp] profile") -> SeccompProfile:
    profile = SeccompProfile(filter_text=text)
    saw_default = False
    for lineno, raw_line in enumerate(text.splitlines(), 1):
        line = raw_line.split("#", 1)[0].strip()
        if not line:
            continue
        tokens = line.split()
        if tokens[0] == "default":
            if len(tokens) < 2 or tokens[1] not in SECCOMP_DEFAULT_ACTIONS:
                abort(f"{where} 第 {lineno} 行: default 须为 allow|deny|errno <CODE>|kill|log")
            if saw_default:
                abort(f"{where} 第 {lineno} 行: default 只能出现一次")
            saw_default = True
            action = tokens[1]
            if action == "deny":
                profile.default_action = "errno"
                profile.default_errno = "EPERM"
            elif action == "errno":
                if len(tokens) != 3:
                    abort(f"{where} 第 {lineno} 行: default errno 需要错误码, 如: default errno EPERM")
                code = tokens[2]
                if code not in SECCOMP_ERRNO_ALLOWLIST:
                    abort(f"{where} 第 {lineno} 行: 不支持的 errno 值 '{code}'")
                profile.default_action = "errno"
                profile.default_errno = code
            else:
                profile.default_action = action
            continue

        action = tokens[0]
        if action == "errno":
            if len(tokens) < 3:
                abort(f"{where} 第 {lineno} 行: errno 需要错误码和至少一个系统调用")
            code = tokens[1]
            if code not in SECCOMP_ERRNO_ALLOWLIST:
                abort(f"{where} 第 {lineno} 行: 不支持的 errno 值 '{code}'")
            syscalls = tokens[2:]
            profile.rules.append(SeccompRule("errno", syscalls, errno=code))
        elif action == "tiocsti":
            if len(tokens) != 1:
                abort(f"{where} 第 {lineno} 行: tiocsti 不接受参数")
            profile.rules.append(SeccompRule("tiocsti", []))
        elif action in ("allow", "kill", "log"):
            if len(tokens) < 2:
                abort(f"{where} 第 {lineno} 行: {action} 需要至少一个系统调用")
            profile.rules.append(SeccompRule(action, tokens[1:]))
        elif action == "deny":
            if len(tokens) < 2:
                abort(f"{where} 第 {lineno} 行: deny 需要至少一个系统调用")
            profile.rules.append(SeccompRule("errno", tokens[1:], errno="EPERM"))
        else:
            abort(
                f"{where} 第 {lineno} 行: 未知动作 '{action}' "
                "(可用: allow|deny|errno <CODE>|kill|log|tiocsti|default ...)"
            )

        for syscall in profile.rules[-1].syscalls:
            if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", syscall):
                abort(f"{where} 第 {lineno} 行: 非法系统调用名 '{syscall}'")
    return profile


def parse_seccomp_table(value: object) -> dict[str, SeccompProfile]:
    """[seccomp] 下每个键都是一段过滤文本; default 为 seccomp=true 的默认档。"""
    table = _table(value, "[seccomp]")
    if not table:
        abort("[seccomp] 至少需要 default = \"\"\"...\"\"\" 过滤文本")
    if "default" not in table:
        if "filter" in table:
            abort("[seccomp] 旧字段 filter 已重命名为 default; 其他自定义档请直接使用新键名")
        abort("[seccomp] 缺少 default 过滤文本 (seccomp=true 时的默认选项)")
    profiles: dict[str, SeccompProfile] = {}
    for name, filter_text in table.items():
        if not re.fullmatch(r"[A-Za-z][A-Za-z0-9_-]*", name):
            abort(f"[seccomp] 配置文件名非法: '{name}' (字母开头, 可含字母/数字/_/-)")
        if not isinstance(filter_text, str) or not filter_text.strip():
            abort(f"[seccomp] {name} 须为非空多行字符串")
        profile = parse_seccomp_filter(filter_text, f"[seccomp] {name}")
        profile.name = name
        profiles[name] = profile
    return profiles


def parse_presets(raw: dict) -> dict[str, PresetRaw]:
    presets_table = _table(raw.get("preset", {}), "[preset]")
    presets: dict[str, PresetRaw] = {}
    for name, table in presets_table.items():
        where = f"[preset.{name}]"
        section = _table(table, where)
        preset = PresetRaw(section=where)
        for key, value in section.items():
            feature_key = canonical_feature(key)
            if key == "program":
                if not isinstance(value, str) or not value.strip():
                    abort(f"{where} program 须为非空绝对路径字符串")
                preset.program = value.strip()
            elif key == "extends":
                if not isinstance(value, str) or not value.strip():
                    abort(f"{where} extends 须为非空预设名字符串")
                preset.extends = value.strip()
            elif key == "alias":
                preset.aliases = parse_preset_aliases(value, where)
            elif key == "seccomp":
                if isinstance(value, bool):
                    preset.feature_overrides["seccomp"] = value
                    if value:
                        # 显式 true 表示选择 default, 覆盖 extends 可能带入的 profile
                        preset.seccomp_profile = "default"
                elif isinstance(value, str):
                    profile_name = value.strip()
                    if not re.fullmatch(r"[A-Za-z][A-Za-z0-9_-]*", profile_name):
                        abort(f"{where} seccomp 配置文件名非法: '{value}'")
                    preset.feature_overrides["seccomp"] = True
                    preset.seccomp_profile = profile_name
                else:
                    abort(f"{where} seccomp 须为 true|false 或 [seccomp] 中的配置文件名")
            elif feature_key in FEATURE_SET:
                preset.feature_overrides[feature_key] = parse_bool(value, f"{where} {key}")
            elif key == "dbus":
                preset.dbus = parse_dbus_mode(value, f"{where} dbus")
            elif key == "dbus_whitelist":
                preset.dbus_whitelist = split_list_value(value, f"{where} dbus_whitelist")
            elif key == "setenv":
                preset.setenv = parse_setenv(value, f"{where} setenv")
            elif key == "bind":
                preset.binds = parse_bind(value, f"{where} bind")
            elif isinstance(value, dict):
                # 支持 TOML 点号键写法: gpu.nv = true 会被解析为嵌套表
                ensure_no_empty_tables(value, f"{where} {key}")
                leaves = flatten_dotted({key: value})
                for full, leaf in leaves:
                    canonical = canonical_feature(full)
                    if canonical not in FEATURE_SET:
                        known = ", ".join(
                            ["program", "alias", "extends", "dbus", "dbus_whitelist", "setenv", "bind", *FEATURES]
                        )
                        abort(f"{where} 未知键 '{full}' (可用: {known})")
                    preset.feature_overrides[canonical] = parse_bool(value=leaf, where=f"{where} {full}")
            else:
                known = ", ".join(
                    ["program", "alias", "extends", "dbus", "dbus_whitelist", "setenv", "bind", *FEATURES]
                )
                abort(f"{where} 未知键 '{key}' (可用: {known})")
        presets[str(name)] = preset
    return presets


def compute_effective(config: Config) -> dict[str, EffectivePreset]:
    """按 默认 < extends 链 < 自身 的优先级合并出每个预设的最终配置。

    - 标量(program/dbus)与 feature: 自身覆盖引用;
    - setenv: 与引用预设按键合并, 同名变量自身覆盖;
    - bind / dbus_whitelist: 自身给出时整体替换引用预设的列表。
    """
    memo: dict[str, EffectivePreset] = {}

    def visit(name: str, stack: list[str]) -> EffectivePreset:
        if name in memo:
            return memo[name]
        raw = config.presets[name]
        if raw.extends is None:
            eff = EffectivePreset(
                name=name,
                program="",
                features=dict(config.feature_defaults),
                dbus=config.general.dbus,
                dbus_whitelist=list(config.general.dbus_whitelist),
                setenv={},
                binds=[],
                chain=[name],
            )
        else:
            base_name = raw.extends
            if base_name not in config.presets:
                abort(f"{raw.section} extends 指向不存在的预设 '{base_name}'")
            if base_name in stack:
                cycle = " -> ".join(stack + [base_name])
                abort(f"预设 extends 循环引用: {cycle}")
            base = visit(base_name, stack + [base_name])
            eff = EffectivePreset(
                name=name,
                program=base.program,
                features=dict(base.features),
                dbus=base.dbus,
                dbus_whitelist=list(base.dbus_whitelist),
                setenv=dict(base.setenv),
                binds=list(base.binds),
                seccomp_profile=base.seccomp_profile,
                chain=base.chain + [name],
            )

        if raw.program is not None:
            eff.program = raw.program
        if raw.seccomp_profile is not None:
            eff.seccomp_profile = raw.seccomp_profile
        eff.features.update(raw.feature_overrides)
        if raw.dbus is not None:
            eff.dbus = raw.dbus
        if raw.dbus_whitelist is not None:
            eff.dbus_whitelist = list(raw.dbus_whitelist)
        if raw.setenv is not None:
            for key, value in raw.setenv:
                eff.setenv[key] = value
        if raw.binds is not None:
            eff.binds = list(raw.binds)

        program = os.path.expanduser(eff.program) if eff.program else ""
        if not program:
            abort(f"{raw.section} 未配置 program, 且 extends 链也未提供 program")
        if not os.path.isabs(program):
            abort(f"{raw.section} program 须为绝对路径 (extends 合并后): {program}")
        eff.program = program
        memo[name] = eff
        return eff

    for name in config.presets:
        visit(name, [name])
    return memo


def load_config(path: Path) -> Config:
    if tomllib is None:
        abort("当前 Python 版本不支持 tomllib, 请使用 Python 3.11+ 或安装 tomli")
    handle = open_config_trusted(path)
    try:
        try:
            raw = tomllib.load(handle)
        except OSError as exc:
            abort(f"无法读取配置文件 {path}: {exc}")
        except tomllib.TOMLDecodeError as exc:
            abort(f"配置文件 TOML 语法错误 ({path}): {exc}")
    finally:
        handle.close()

    allowed_top = {"general", "features", "preset", "seccomp"}
    if "program" in raw:
        abort(
            "检测到旧版配置结构 ([program] 表); 新格式使用 [preset.<名称>] 表, "
            "program 移入预设内, 程序特性段也合并到对应预设中。"
        )
    if "alias" in raw:
        abort(
            "检测到旧版顶级 [alias] 段; alias 现在请写在对应 [preset.<名称>] 内 "
            "(program 的下一行), 且 alias 不参与 extends 继承。"
        )
    unknown_top = sorted(set(raw) - allowed_top)
    if "security" in unknown_top:
        abort(
            "检测到旧版 [security] 段; 新格式中 security 已并入 [general] "
            "(security = true|false, blocklist = [...])。"
        )
    if unknown_top:
        abort(f"配置文件未知顶级段: {', '.join(unknown_top)}")

    general = parse_general(_table(raw.get("general", {}), "[general]"))

    feature_defaults: dict[str, bool] = {
        name: (name in FEATURE_DEFAULT_TRUE) for name in FEATURES
    }
    features_table = _table(raw.get("features", {}), "[features]")
    for key, value in features_table.items():
        if isinstance(value, dict):
            ensure_no_empty_tables(value, f"[features] {key}")
    for key, value in flatten_dotted(features_table):
        if key == "security":
            abort("security 已并入 [general] (security = true|false)")
        if key == "dbus":
            abort("dbus 现为 off|proxy|direct, 请配置在 [general] 或 [preset.*]")
        canonical = canonical_feature(key)
        if canonical not in FEATURE_SET:
            abort(f"[features] 未知键 '{key}' (可用: {', '.join(FEATURES)})")
        feature_defaults[canonical] = parse_bool(value, f"[features] {key}")

    presets = parse_presets(raw)
    if not presets:
        abort("[preset] 未登记任何预设")

    seccomp_profiles: dict[str, SeccompProfile] = {}
    if "seccomp" in raw:
        seccomp_profiles = parse_seccomp_table(raw["seccomp"])

    # 由各预设的 alias 字段构建全局别名表; alias 不被 extends 继承,
    # 但既可作为程序名入口, 也可作为 --as/--preset 的配置来源。
    aliases: dict[str, str] = {}
    for name, preset in presets.items():
        for alias in preset.aliases:
            if alias in presets:
                abort(f"[preset.{name}] alias '{alias}' 与预设名冲突")
            if alias in aliases:
                abort(f"别名 '{alias}' 被多个预设重复使用")
            aliases[alias] = name

    config = Config(
        path=path,
        general=general,
        feature_defaults=feature_defaults,
        aliases=aliases,
        presets=presets,
        seccomp_profiles=seccomp_profiles,
    )
    config.effective = compute_effective(config)

    for preset_name, effective in config.effective.items():
        if effective.features.get("seccomp", False):
            profile_name = effective.seccomp_profile or "default"
            if profile_name not in config.seccomp_profiles:
                abort(
                    f"[preset.{preset_name}] seccomp 指定了不存在的过滤配置 "
                    f"'{profile_name}' (可用: {', '.join(sorted(config.seccomp_profiles)) or '<空>'})"
                )
    if general.default is not None and resolve_preset_name(general.default, config) is None:
        abort(f"[general] default '{general.default}' 不是已登记预设或别名")
    return config


def resolve_preset_name(name: str, config: Config) -> str | None:
    if name in config.presets:
        return name
    target = config.aliases.get(name)
    if target and target in config.presets:
        return target
    return None


# ---------------------------------------------------------------------------
# 运行时覆盖
# ---------------------------------------------------------------------------


def resolve_custom_executable(text: str, where: str = "自定义程序") -> str:
    expanded = os.path.expanduser(text)
    if os.path.isabs(expanded) or "/" in expanded:
        candidate = os.path.abspath(expanded)
    else:
        candidate = shutil.which(expanded)
        if not candidate:
            abort(f"{where} '{text}' 未找到 (不是已登记预设, 也不是 PATH 中的命令)")
    if not os.path.exists(candidate):
        abort(f"{where} 入口不存在: {candidate}")
    if not os.access(candidate, os.X_OK):
        abort(f"{where} 入口不可执行: {candidate}")
    return candidate


def apply_overrides(
    specs: list[str], config: Config, eff: EffectivePreset
) -> tuple[str | None, GeneralCfg]:
    """应用 --override。返回 (program 覆盖, 本次调用专用的 general 副本)。

    传入的 eff 须为调用方拷贝; general 在这里深拷贝, 避免污染 load_config 的缓存。
    """
    program_override: str | None = None
    general = copy.deepcopy(config.general)
    for spec in specs:
        key, value = spec.split("=", 1)
        key = key.strip()
        if not key:
            abort(f"--override 键不能为空: {spec}")

        if key == "seccomp":
            text = value.strip()
            lowered = text.lower()
            if lowered in ("on", "off", "true", "false", "yes", "no", "1", "0"):
                enabled = parse_cli_bool(value, "seccomp")
                eff.features["seccomp"] = enabled
                if enabled:
                    eff.seccomp_profile = "default"
            elif re.fullmatch(r"[A-Za-z][A-Za-z0-9_-]*", text):
                eff.features["seccomp"] = True
                eff.seccomp_profile = text
            else:
                abort(
                    "--override seccomp 须为 on|off/true|false, 或 [seccomp] 中的配置文件名"
                )
            continue

        feature_key = canonical_feature(key)
        if feature_key in FEATURE_SET:
            eff.features[feature_key] = parse_cli_bool(value, key)
        elif key == "dbus":
            eff.dbus = parse_dbus_mode(value, f"--override dbus")
        elif key == "dbus_whitelist":
            items = split_list_value(value, "--override dbus_whitelist")
            if not items:
                abort("--override dbus_whitelist 不能为空")
            eff.dbus_whitelist.extend(items)
        elif key == "setenv":
            if "=" not in value:
                abort(f"--override setenv 须为 K=V: {value}")
            env_key, env_val = value.split("=", 1)
            env_key = env_key.strip()
            if not env_key:
                abort(f"--override setenv 变量名不能为空: {value}")
            eff.setenv[env_key] = env_val
        elif key == "bind":
            for bind in parse_bind(value, "--override bind"):
                eff.binds.append(bind)
        elif key == "security":
            general.security = parse_cli_bool(value, "security")
        elif key == "blocklist":
            entry = parse_blocklist_entry(value, "--override blocklist")
            general.blocklist.append(entry)
        elif key == "program":
            program_override = resolve_custom_executable(value, "--override program")
            eff.program = program_override
        else:
            allowed = ", ".join(
                [*FEATURES, "dbus", "dbus_whitelist", "setenv", "bind", "security", "blocklist", "program"]
            )
            abort(f"--override 未知键 '{key}' (可用: {allowed})")
    return program_override, general


# ---------------------------------------------------------------------------
# 程序解析与安全检查
# ---------------------------------------------------------------------------


def resolve_entry_for_app(app: str, config: Config) -> tuple[str, str]:
    preset_name = resolve_preset_name(app, config)
    if preset_name is not None:
        return config.effective[preset_name].program, preset_name
    candidate = resolve_custom_executable(app, f"程序 '{app}'")
    return candidate, f"custom:{app}"


def resolve_invocation(opts: CliOptions, config: Config) -> tuple[str, EffectivePreset, str, str]:
    """返回 (配置来源预设名, 生效配置, 程序入口, 程序标签)。"""
    if opts.as_preset is not None:
        settings_name = resolve_preset_name(opts.as_preset, config)
        if settings_name is None:
            avail = ", ".join(sorted(config.presets)) or "<空>"
            alias_avail = ", ".join(sorted(config.aliases)) or "<空>"
            abort(
                f"--as/--preset 指定了未登记预设或别名 '{opts.as_preset}'\n"
                f"可用预设: {avail}\n"
                f"可用别名: {alias_avail}"
            )
        settings = config.effective[settings_name]
        if opts.app is None:
            entry = settings.program
            program_label = settings_name
        else:
            entry, program_label = resolve_entry_for_app(opts.app, config)
        return settings_name, settings, entry, program_label

    app = opts.app if opts.app is not None else config.general.default
    if not app:
        abort("未指定程序, 且 [general] default 未配置")
    preset_name = resolve_preset_name(app, config)
    if preset_name is None:
        avail = ", ".join(sorted(config.presets)) or "<空>"
        alias_avail = ", ".join(sorted(config.aliases)) or "<空>"
        abort(
            f"未登记的程序或别名 '{app}'\n"
            f"可用预设: {avail}\n"
            f"可用别名: {alias_avail}\n"
            f"提示: 用 --as <预设名|别名> 才能借预设配置运行自定义可执行程序。"
        )
    return preset_name, config.effective[preset_name], config.effective[preset_name].program, preset_name


def blocklist_matches(project_dir: str, root: str, mode: str) -> bool:
    if root == "/" or mode == "exact":
        return project_dir == root
    return project_dir == root or project_dir.startswith(root + "/")


def run_security_checks(
    general: GeneralCfg,
    eff: EffectivePreset,
    project_dir: str,
    print_mode: bool,
) -> None:
    if not general.security:
        return

    def enforce(message: str) -> None:
        if print_mode:
            warn(f"实际运行将被安全检查拒绝: {message}")
        else:
            abort(message)

    if os.getuid() == 0:
        enforce("security=on 禁止以 root 运行")

    if not eff.features.get("pwd", False):
        return

    for root, mode in general.blocklist:
        if blocklist_matches(project_dir, root, mode):
            enforce(f"security=on 禁止从当前路径运行: {project_dir} (黑名单: {root})")

    if project_dir == "/":
        enforce("security=on 禁止从 / 运行")

    home = os.path.realpath(os.path.expanduser("~"))
    if project_dir == home:
        warn(f"当前目录是 $HOME ({home}), 整个家目录将被 rw 绑定。")
        if not print_mode:
            try:
                answer = input("继续? [y/N] ")
            except EOFError:
                answer = "n"
            if answer.strip().lower() not in ("y", "yes"):
                abort("Aborted.")


# ---------------------------------------------------------------------------
# bwrap 命令构建
# ---------------------------------------------------------------------------


def effective_dbus_mode(eff: EffectivePreset) -> str:
    mode = eff.dbus
    if mode == "proxy" and shutil.which("xdg-dbus-proxy") is None:
        warn("xdg-dbus-proxy 不可用, dbus=proxy 降级为关闭")
        return "off"
    return mode


def runtime_dir() -> str:
    uid = os.getuid()
    return os.environ.get("XDG_RUNTIME_DIR") or f"/run/user/{uid}"


def socket_exists(path: str) -> bool:
    try:
        return stat.S_ISSOCK(os.stat(path).st_mode)
    except OSError:
        return False


def host_x11_displays_in_use() -> set[int]:
    used: set[int] = set()
    socket_dir = Path("/tmp/.X11-unix")
    try:
        children = socket_dir.iterdir()
    except OSError:
        return used
    for child in children:
        name = child.name
        if name.startswith("X"):
            try:
                used.add(int(name[1:]))
            except ValueError:
                pass
    return used


def choose_x11_display() -> int:
    used = host_x11_displays_in_use()
    ordered = list(range(X11_DISPLAY_MIN, X11_DISPLAY_MAX + 1))
    random.shuffle(ordered)
    for display in ordered:
        if display not in used:
            return display
    abort(
        f"无法在 {X11_DISPLAY_MIN}..{X11_DISPLAY_MAX} 范围内找到空闲的 X11 display "
        "(宿主 /tmp/.X11-unix 已占用过多编号)"
    )
    raise AssertionError("unreachable")


def allocate_x11_display(state_dir: Path) -> int:
    """对状态目录本身加 flock, 降低并发实例选中同一编号的概率。"""
    try:
        dir_fd = os.open(state_dir, os.O_RDONLY | os.O_DIRECTORY)
    except OSError as exc:
        abort(f"无法打开状态目录 {state_dir} 进行 X11 display 分配: {exc}")
    try:
        fcntl.flock(dir_fd, fcntl.LOCK_EX)
        return choose_x11_display()
    finally:
        try:
            fcntl.flock(dir_fd, fcntl.LOCK_UN)
        finally:
            os.close(dir_fd)


def dbus_bus_address(rt_dir: str) -> str:
    address = os.environ.get("DBUS_SESSION_BUS_ADDRESS")
    if not address:
        address = f"unix:path={rt_dir}/bus"
    return address


def build_proxy_cmd(eff: EffectivePreset, bus_path: str) -> list[str]:
    proxy = shutil.which("xdg-dbus-proxy") or "xdg-dbus-proxy"
    rt_dir = runtime_dir()
    cmd = [proxy, dbus_bus_address(rt_dir), bus_path]
    for name in eff.dbus_whitelist:
        cmd.append(f"--talk={name}")
    return cmd


def build_bwrap_cmd(
    eff: EffectivePreset,
    entry: str,
    app_args: list[str],
    project_dir: str,
    dbus_mode: str,
    bus_path: str | None = None,
    vhome_path: str | None = None,
    seccomp_fd: int | None = None,
    x11_display: int | None = None,
) -> tuple[list[str], list[str]]:
    """返回 (需要预先执行的 mkdir 列表, bwrap 参数列表, 不含 bwrap 本身)。"""
    args: list[str] = []
    mkdirs: list[str] = []

    def add(*parts: str) -> None:
        args.extend(parts)

    def feat(name: str) -> bool:
        return eff.features.get(name, False)

    if feat("base"):
        add("--ro-bind", "/usr", "/usr")
        add("--ro-bind", "/etc", "/etc")
        add("--symlink", "usr/bin", "/bin")
        add("--symlink", "usr/bin", "/sbin")
        add("--symlink", "usr/lib", "/lib")
        add("--symlink", "usr/lib", "/lib64")
        add("--ro-bind", "/sys", "/sys")
        add("--ro-bind", "/opt", "/opt")
        add("--proc", "/proc")
        add("--dev", "/dev")

    # 防御加固: 清除宿主机代理套接字环境变量
    add("--unsetenv", "SSH_AUTH_SOCK")
    add("--unsetenv", "SSH_AGENT_PID")
    add("--unsetenv", "GPG_TTY")
    add("--unsetenv", "GPG_AGENT_INFO")

    if feat("gpu.nv"):
        for dev in (
            "nvidia0",
            "nvidiactl",
            "nvidia-modeset",
            "nvidia-uvm",
            "nvidia-uvm-tools",
            "nvidia-caps",
        ):
            add("--dev-bind-try", f"/dev/{dev}", f"/dev/{dev}")

    if feat("gpu.dri"):
        add("--dev-bind-try", "/dev/dri", "/dev/dri")

    if feat("tmpfs"):
        add("--tmpfs", "/tmp")
        add("--tmpfs", "/run")

    if feat("shm"):
        add("--tmpfs", "/dev/shm")

    if feat("x11"):
        if x11_display is None:
            abort("内部错误: x11 已启用但未分配 display 编号")
        add("--setenv", "DISPLAY", f":{x11_display}")
        add("--unsetenv", "XAUTHORITY")

    uid = os.getuid()
    rt_dir = runtime_dir()

    if feat("wayland") or dbus_mode != "off" or feat("pipewire"):
        add("--dir", f"/run/user/{uid}")
        add("--setenv", "XDG_RUNTIME_DIR", f"/run/user/{uid}")

    if feat("wayland"):
        display = os.environ.get("WAYLAND_DISPLAY") or "wayland-0"
        src = f"{rt_dir}/{display}"
        add("--bind", src, f"/run/user/{uid}/{display}")
        add("--setenv", "WAYLAND_DISPLAY", display)
        add("--setenv", "XDG_SESSION_TYPE", "wayland")
        add("--setenv", "NO_AT_BRIDGE", "1")
    else:
        add("--unsetenv", "WAYLAND_DISPLAY")

    if dbus_mode == "direct":
        host_bus = f"{rt_dir}/bus"
        if not socket_exists(host_bus):
            warn(f"dbus=direct 但宿主总线套接字不存在: {host_bus}")
        add("--bind-try", host_bus, f"/run/user/{uid}/bus")
        add("--setenv", "DBUS_SESSION_BUS_ADDRESS", f"unix:path=/run/user/{uid}/bus")
    elif dbus_mode == "proxy":
        if bus_path is None:
            abort("内部错误: dbus=proxy 缺少代理套接字路径")
        add("--bind-try", bus_path, f"/run/user/{uid}/bus")
        add("--setenv", "DBUS_SESSION_BUS_ADDRESS", f"unix:path=/run/user/{uid}/bus")
    else:
        add("--unsetenv", "DBUS_SESSION_BUS_ADDRESS")

    if feat("pipewire"):
        add("--bind-try", f"{rt_dir}/pipewire-0", f"/run/user/{uid}/pipewire-0")

    home = os.environ.get("HOME") or str(Path.home())
    if feat("vhome"):
        if vhome_path is None:
            abort("内部错误: vhome 已启用但缺少 vhome 目录路径")
        add("--bind", vhome_path, home)

    # 预设绑定: src[:dst][:mode] 或 { src=..., dst=..., mode=... }
    # 静态绑定先于 pwd 动态绑定, 避免后者遮蔽前者。
    for bind in eff.binds:
        src = os.path.expanduser(bind.src)
        dst = os.path.expanduser(bind.dst) if bind.dst else src
        mode = bind.mode
        if mode == "rw":
            add("--bind", src, dst)
        elif mode == "rw-try":
            add("--bind-try", src, dst)
        elif mode == "create":
            mkdirs.append(src)
            add("--bind", src, dst)
        elif mode == "ro":
            add("--ro-bind", src, dst)
        elif mode == "ro-try":
            add("--ro-bind-try", src, dst)
        else:  # 配置解析时已校验, 这里防御性兜底
            abort(f"未知绑定模式 '{mode}' (条目: {bind.src})")

    if feat("pwd"):
        add("--bind", project_dir, project_dir)

    for key, value in eff.setenv.items():
        add("--setenv", key, value)

    if seccomp_fd is not None:
        add("--add-seccomp-fd", str(seccomp_fd))

    if not feat("net"):
        add("--unshare-net")

    add("--unshare-pid")
    add("--unshare-ipc")
    add("--unshare-uts")
    add("--unshare-cgroup-try")
    if feat("vtty"):
        add("--new-session")
    add("--die-with-parent")

    if feat("x11"):
        add(
            "/usr/bin/bash",
            "-c",
            x11_wrap_script(x11_display or 0),
            "--",
            entry,
            *app_args,
        )
    else:
        add(entry, *app_args)

    return mkdirs, args


def ensure_create_dirs(mkdirs: list[str]) -> None:
    for directory in mkdirs:
        try:
            os.makedirs(directory, exist_ok=True)
        except OSError as exc:
            abort(f"无法创建绑定目录 {directory}: {exc}")
        if not os.path.isdir(directory):
            abort(f"绑定路径非目录: {directory}")


def resolve_bwrap(print_mode: bool) -> str:
    path = shutil.which("bwrap")
    if path:
        return path
    if print_mode:
        return "bwrap"
    abort("找不到 bwrap, 请先安装 bubblewrap")


# ---------------------------------------------------------------------------
# 状态目录 / 运行记录
# ---------------------------------------------------------------------------


_RUN_NAME_RE = re.compile(r"[^A-Za-z0-9._-]+")


def safe_run_prefix(preset_name: str) -> str:
    return _RUN_NAME_RE.sub("_", preset_name).strip("._") or "preset"


def ensure_state_dir(state_dir: str) -> Path:
    path = Path(state_dir)
    try:
        path.mkdir(mode=0o700, parents=True, exist_ok=True)
    except OSError as exc:
        abort(f"无法创建状态目录 {path}: {exc}")
    if path.is_symlink():
        abort(f"状态目录不能是符号链接: {path}")
    try:
        st = path.stat()
    except OSError as exc:
        abort(f"无法检查状态目录 {path}: {exc}")
    if not stat.S_ISDIR(st.st_mode):
        abort(f"状态目录不是目录: {path}")
    if st.st_uid != os.getuid():
        abort(f"状态目录属主须为当前用户: {path}")
    try:
        os.chmod(path, 0o700)
    except OSError as exc:
        warn(f"无法收紧状态目录权限: {exc}")
    return path


def create_run_dir(state_dir: Path, preset_name: str) -> tuple[Path, str]:
    prefix = f"{safe_run_prefix(preset_name)}."
    for _ in range(100):
        run_id = f"{prefix}{secrets.token_hex(3)}"
        run_dir = state_dir / run_id
        try:
            os.mkdir(run_dir, 0o700)
            return run_dir, run_id
        except FileExistsError:
            continue
        except OSError as exc:
            abort(f"无法创建运行状态目录 {run_dir}: {exc}")
    abort(f"无法在 {state_dir} 中分配唯一运行 ID")


def write_run_info(run_dir: Path, data: dict) -> None:
    path = run_dir / "info.json"
    tmp = run_dir / f".info.json.{secrets.token_hex(4)}"
    try:
        tmp.write_text(
            json.dumps(data, ensure_ascii=False, indent=2, sort_keys=True),
            encoding="utf-8",
        )
        os.replace(tmp, path)
    except OSError as exc:
        abort(f"无法写入运行记录 {path}: {exc}")


def read_run_info(run_dir: Path) -> dict | None:
    try:
        with (run_dir / "info.json").open(encoding="utf-8") as handle:
            data = json.load(handle)
    except (OSError, json.JSONDecodeError):
        return None
    return data if isinstance(data, dict) else None


def process_start_time(pid: int) -> int | None:
    """读取 /proc/<pid>/stat 的 starttime, 用于避免 PID 复用误判。"""
    try:
        with open(f"/proc/{pid}/stat", "rb") as handle:
            stat_data = handle.read().decode("utf-8", errors="replace")
    except OSError:
        return None
    tail = stat_data[stat_data.rfind(")") + 2 :].split()
    try:
        return int(tail[19]) if len(tail) > 19 else None
    except (ValueError, IndexError):
        return None


def pid_alive(pid: int | None, start_time: int | None = None) -> bool:
    if not pid or pid <= 0:
        return False
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    if start_time is None:
        return True
    current = process_start_time(pid)
    if current is None:
        # /proc 不可用时退化为普通存活判断
        return True
    return current == start_time


def run_info_alive(info: dict) -> bool:
    return any(
        (
            pid_alive(info.get("pid"), info.get("pid_start")),
            pid_alive(info.get("proxy_pid"), info.get("proxy_start")),
            pid_alive(info.get("launcher_pid"), info.get("launcher_start")),
        )
    )


def scan_state_dir(state_dir: Path, clean_stale: bool = True) -> list[tuple[Path, dict]]:
    """返回 (run_dir, info) 列表; clean_stale 时顺带清理已无存活进程的目录。"""
    entries: list[tuple[Path, dict]] = []
    now = time.time()
    try:
        children = list(state_dir.iterdir())
    except OSError as exc:
        abort(f"无法读取状态目录 {state_dir}: {exc}")
    for child in children:
        if child.name == SECCOMP_CACHE_DIRNAME:
            # seccomp 缓存按设计不做自动清理, ps/stop/kill 必须跳过它
            continue
        if not child.is_dir() or child.is_symlink():
            continue
        info = read_run_info(child)
        if info is None:
            if not clean_stale:
                continue
            try:
                age = now - child.stat().st_mtime
            except OSError:
                age = 0
            # 无 info.json 的新目录可能正处于启动瞬间; 只清理明显陈旧的残留
            if age > 300:
                shutil.rmtree(child, ignore_errors=True)
            continue
        if clean_stale and not run_info_alive(info):
            shutil.rmtree(child, ignore_errors=True)
            continue
        entries.append((child, info))
    entries.sort(key=lambda item: item[1].get("created_at", 0.0))
    return entries


def format_age(seconds: float) -> str:
    seconds = max(0, int(seconds))
    if seconds < 60:
        return f"{seconds}s"
    if seconds < 3600:
        return f"{seconds // 60}m{seconds % 60:02d}s"
    return f"{seconds // 3600}h{(seconds % 3600) // 60:02d}m"


def find_run_dir(state_dir: Path, ref: str) -> tuple[Path, dict]:
    entries = scan_state_dir(state_dir, clean_stale=True)
    matches: list[tuple[Path, dict]] = []
    for run_dir, info in entries:
        run_id = str(info.get("run_id") or run_dir.name)
        if run_id == ref:
            return run_dir, info
        if run_id.startswith(ref):
            matches.append((run_dir, info))
    if len(matches) == 1:
        return matches[0]
    if len(matches) > 1:
        ids = ", ".join(str(item[1].get("run_id") or item[0].name) for item in matches)
        abort(f"运行 ID 前缀 '{ref}' 匹配多个任务: {ids}")
    abort(f"未找到运行中的任务 '{ref}'")


def _signal_group(pid: int, sig: int) -> bool:
    if pid <= 0 or pid == os.getpid():
        return False
    try:
        os.killpg(pid, sig)
        return True
    except (ProcessLookupError, PermissionError):
        # 进程组不存在时退化为单进程信号
        return _signal_pid(pid, sig)


def _signal_pid(pid: int | None, sig: int) -> bool:
    if not pid or pid <= 0 or pid == os.getpid():
        return False
    try:
        os.kill(pid, sig)
        return True
    except (ProcessLookupError, PermissionError):
        return False


def _signal_main(info: dict, sig: int) -> None:
    main_pid = info.get("pid")
    launcher_pid = info.get("launcher_pid")
    if main_pid and main_pid != launcher_pid:
        _signal_group(int(main_pid), sig)
    else:
        _signal_pid(main_pid or launcher_pid, sig)


def _wait_run_dir_gone(run_dir: Path, timeout: float) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if not run_dir.exists():
            return True
        time.sleep(0.1)
    return not run_dir.exists()


def terminate_run_entry(info: dict, force: bool) -> None:
    """stop: SIGINT 后按需升级; kill: 直接 SIGKILL。"""
    proxy_pid = info.get("proxy_pid")
    launcher_pid = info.get("launcher_pid")

    if force:
        _signal_main(info, signal.SIGKILL)
        _signal_pid(proxy_pid, signal.SIGKILL)
        _signal_pid(launcher_pid, signal.SIGKILL)
        return

    _signal_main(info, signal.SIGINT)


# ---------------------------------------------------------------------------
# 运行 / 打印
# ---------------------------------------------------------------------------


def print_banner(settings_label: str, program_label: str, entry: str, project_dir: str) -> None:
    print(f"=== run-sandbox: {settings_label} -> {entry} ===", file=sys.stderr)
    if program_label != settings_label:
        print(f"Settings: {settings_label} | Program: {program_label}", file=sys.stderr)
    print(f"Project: {project_dir}", file=sys.stderr)


def prepare_vhome_dir(run_dir: Path) -> str:
    vhome = run_dir / "vhome"
    try:
        os.makedirs(vhome / ".config", exist_ok=True)
        os.makedirs(vhome / ".cache", exist_ok=True)
    except OSError as exc:
        abort(f"无法准备 vhome 目录 {vhome}: {exc}")
    return str(vhome)


def start_dbus_proxy(proxy_cmd: list[str], bus_path: str) -> subprocess.Popen:
    try:
        proc = subprocess.Popen(proxy_cmd)
    except OSError as exc:
        abort(f"无法启动 xdg-dbus-proxy: {exc}")
    deadline = time.monotonic() + 2.5
    while not socket_exists(bus_path):
        rc = proc.poll()
        if rc is not None:
            proc.wait()
            abort(f"xdg-dbus-proxy 提前退出 (exit code {rc})")
        if time.monotonic() >= deadline:
            proc.terminate()
            try:
                proc.wait(timeout=2)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait()
            abort("等待 xdg-dbus-proxy 创建 socket 超时 (2.5s)")
        time.sleep(0.05)
    return proc


def stop_subprocess(proc: subprocess.Popen | None) -> None:
    if proc is None or proc.poll() is not None:
        return
    proc.terminate()
    try:
        proc.wait(timeout=2)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait()


# ---------------------------------------------------------------------------
# seccomp 过滤: 配置 DSL -> 生成 C -> 即时编译 -> 导出 BPF -> 传递 FD
# 参考 flatpak common/flatpak-run.c: 同样使用 libseccomp 构建规则并
# seccomp_export_bpf() 后, 把 BPF 通过 fd 交给 bwrap --add-seccomp-fd。
# ---------------------------------------------------------------------------


SECCOMP_FD = 9
SECCOMP_CACHE_DIRNAME = ".seccomp-cache"


def seccomp_cache_key(filter_text: str) -> str:
    """用较快的 BLAKE2b 对 [seccomp] 某个配置的文本做摘要, 嵌入缓存文件名。"""
    digest = hashlib.blake2b(filter_text.encode("utf-8"), digest_size=16)
    return digest.hexdigest()


def seccomp_action_macro(action: str, errno_code: str | None = None) -> str:
    if action == "allow":
        return "SCMP_ACT_ALLOW"
    if action == "errno":
        return f"SCMP_ACT_ERRNO({errno_code or 'EPERM'})"
    if action == "kill":
        return "SCMP_ACT_KILL_PROCESS"
    if action == "log":
        return "SCMP_ACT_LOG"
    abort(f"内部错误: 未知 seccomp 动作 '{action}'")
    raise AssertionError("unreachable")


def generate_seccomp_c(profile: SeccompProfile) -> str:
    lines = [
        "/* 由 run-sandbox 依据 [seccomp] 配置文本自动生成, 请勿手改 */",
        "#include <asm/ioctls.h>",
        "#include <errno.h>",
        "#include <seccomp.h>",
        "#include <stdio.h>",
        "#include <string.h>",
        "#include <unistd.h>",
        "",
        "#ifndef TIOCSTI",
        "#define TIOCSTI 0x5412",
        "#endif",
        "",
        "static int add_rule(scmp_filter_ctx ctx, uint32_t action,",
        "                    const char *name, int lineno) {",
        "  int call = seccomp_syscall_resolve_name(name);",
        "  if (call == __NR_SCMP_ERROR) {",
        "    fprintf(stderr, \"seccomp rule %d: unknown syscall '%s'\\n\", lineno, name);",
        "    return -1;",
        "  }",
        "  int rc = seccomp_rule_add(ctx, action, call, 0);",
        "  if (rc < 0) {",
        "    fprintf(stderr, \"seccomp rule %d syscall '%s': %s\\n\", lineno, name, strerror(-rc));",
        "    return -1;",
        "  }",
        "  return 0;",
        "}",
        "",
        "static int add_tiocsti_rule(scmp_filter_ctx ctx, int lineno) {",
        "  int call = seccomp_syscall_resolve_name(\"ioctl\");",
        "  if (call == __NR_SCMP_ERROR) {",
        "    fprintf(stderr, \"seccomp rule %d: unknown syscall 'ioctl'\\n\", lineno);",
        "    return -1;",
        "  }",
        "  int rc = seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), call, 1,",
        "                           SCMP_CMP(1, SCMP_CMP_EQ, TIOCSTI));",
        "  if (rc < 0) {",
        "    fprintf(stderr, \"seccomp rule %d ioctl(TIOCSTI): %s\\n\", lineno, strerror(-rc));",
        "    return -1;",
        "  }",
        "  return 0;",
        "}",
        "",
        "static int lock_native_arch(scmp_filter_ctx ctx) {",
        "#if defined(__x86_64__)",
        "  if (seccomp_arch_remove(ctx, SCMP_ARCH_NATIVE) != 0) return -1;",
        "  return seccomp_arch_add(ctx, SCMP_ARCH_X86_64);",
        "#elif defined(__aarch64__)",
        "  if (seccomp_arch_remove(ctx, SCMP_ARCH_NATIVE) != 0) return -1;",
        "  return seccomp_arch_add(ctx, SCMP_ARCH_AARCH64);",
        "#else",
        "  return 0;",
        "#endif",
        "}",
        "",
        "int main(void) {",
        f"  scmp_filter_ctx ctx = seccomp_init({seccomp_action_macro(profile.default_action, profile.default_errno)});",
        "  if (ctx == NULL) {",
        "    fprintf(stderr, \"seccomp_init failed\\n\");",
        "    return 1;",
        "  }",
        "  if (lock_native_arch(ctx) != 0) {",
        "    fprintf(stderr, \"failed to hard-lock seccomp architecture\\n\");",
        "    seccomp_release(ctx);",
        "    return 1;",
        "  }",
        "",
    ]
    lineno = 1
    for rule in profile.rules:
        if rule.action == "tiocsti":
            lines.append(
                f"  if (add_tiocsti_rule(ctx, {lineno}) != 0) "
                "{ seccomp_release(ctx); return 1; }"
            )
        else:
            macro = seccomp_action_macro(rule.action, rule.errno)
            for syscall in rule.syscalls:
                lines.append(
                    f'  if (add_rule(ctx, {macro}, "{syscall}", {lineno}) != 0) '
                    "{ seccomp_release(ctx); return 1; }"
                )
        lineno += 1
    lines.extend(
        [
            "",
            "  if (seccomp_export_bpf(ctx, STDOUT_FILENO) < 0) {",
            "    fprintf(stderr, \"seccomp_export_bpf failed\\n\");",
            "    seccomp_release(ctx);",
            "    return 1;",
            "  }",
            "  seccomp_release(ctx);",
            "  return 0;",
            "}",
            "",
        ]
    )
    return "\n".join(lines)


def resolve_cc(print_mode: bool = False) -> str:
    for name in ("cc", "gcc", "clang"):
        path = shutil.which(name)
        if path:
            return path
    if print_mode:
        return "cc"
    abort("未找到 C 编译器 (cc/gcc/clang), 无法启用 seccomp 过滤")


def compile_seccomp_filter(profile: SeccompProfile, run_dir: Path) -> str:
    """生成并编译过滤程序, 运行后导出 BPF, 返回 bpf 文件路径。"""
    seccomp_dir = run_dir / "seccomp"
    try:
        seccomp_dir.mkdir(mode=0o700, exist_ok=True)
    except OSError as exc:
        abort(f"无法创建 seccomp 目录 {seccomp_dir}: {exc}")

    c_path = seccomp_dir / "filter.c"
    bin_path = seccomp_dir / "filter-gen"
    bpf_path = seccomp_dir / "filter.bpf"
    try:
        c_path.write_text(generate_seccomp_c(profile), encoding="utf-8")
    except OSError as exc:
        abort(f"无法写入 seccomp 源文件 {c_path}: {exc}")

    cc = resolve_cc(print_mode=False)
    compile_cmd = [cc, "-O2", "-Wall", "-o", str(bin_path), str(c_path), "-lseccomp"]
    try:
        proc = subprocess.run(
            compile_cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
    except OSError as exc:
        abort(f"无法执行 C 编译器 {cc}: {exc}")
    if proc.returncode != 0:
        detail = (proc.stderr or "").strip()
        abort(
            f"seccomp 过滤程序编译失败 ({cc}):\n{detail or '未知编译错误'}"
        )

    try:
        with bpf_path.open("wb") as out:
            gen_proc = subprocess.run(
                [str(bin_path)],
                stdout=out,
                stderr=subprocess.PIPE,
                text=True,
            )
    except OSError as exc:
        abort(f"无法运行 seccomp 生成程序: {exc}")
    if gen_proc.returncode != 0:
        detail = (gen_proc.stderr or "").strip()
        abort(
            f"seccomp 过滤规则无效或导出失败:\n{detail or '未知错误'}"
        )
    try:
        if bpf_path.stat().st_size == 0:
            abort("seccomp BPF 导出结果为空")
    except OSError as exc:
        abort(f"无法检查 seccomp BPF 文件: {exc}")
    return str(bpf_path)


def ensure_seccomp_cache_dir(state_dir: Path) -> Path:
    cache_dir = state_dir / SECCOMP_CACHE_DIRNAME
    try:
        cache_dir.mkdir(mode=0o700, exist_ok=True)
    except OSError as exc:
        abort(f"无法创建 seccomp 缓存目录 {cache_dir}: {exc}")
    if cache_dir.is_symlink():
        abort(f"seccomp 缓存目录不能是符号链接: {cache_dir}")
    if not cache_dir.is_dir():
        abort(f"seccomp 缓存路径不是目录: {cache_dir}")
    return cache_dir


def _copy_atomic(src: Path, dst: Path) -> None:
    tmp = dst.with_name(f"{dst.name}.{secrets.token_hex(4)}.tmp")
    try:
        shutil.copy2(src, tmp)
        os.replace(tmp, dst)
    except OSError as exc:
        try:
            tmp.unlink(missing_ok=True)
        except OSError:
            pass
        abort(f"无法写入 seccomp 缓存文件 {dst}: {exc}")


def obtain_seccomp_bpf(
    profile: SeccompProfile,
    state_dir: Path,
    run_dir: Path,
) -> tuple[str, bool]:
    """命中缓存则直接复用; 未命中则编译并写入带哈希文件名的缓存。

    缓存键由 [seccomp] 中被选配置的文本经 BLAKE2b 生成, 配置内容变化必然
    导致文件名变化, 从而自然失效并重新生成。无自动清理机制。
    """
    key = seccomp_cache_key(profile.filter_text)
    cache_dir = ensure_seccomp_cache_dir(state_dir)
    cache_c = cache_dir / f"seccomp-{key}.c"
    cache_gen = cache_dir / f"seccomp-{key}.gen"
    cache_bpf = cache_dir / f"seccomp-{key}.bpf"

    local_dir = run_dir / "seccomp"
    try:
        local_dir.mkdir(mode=0o700, exist_ok=True)
    except OSError as exc:
        abort(f"无法创建 seccomp 目录 {local_dir}: {exc}")
    local_bpf = local_dir / "filter.bpf"

    try:
        if (
            cache_bpf.exists()
            and not cache_bpf.is_symlink()
            and cache_bpf.is_file()
            and cache_bpf.stat().st_size > 0
        ):
            shutil.copy2(cache_bpf, local_bpf)
            return str(local_bpf), True
    except OSError as exc:
        abort(f"无法读取 seccomp 缓存 {cache_bpf}: {exc}")

    bpf_path = compile_seccomp_filter(profile, run_dir)
    _copy_atomic(local_dir / "filter.c", cache_c)
    _copy_atomic(local_dir / "filter-gen", cache_gen)
    _copy_atomic(Path(bpf_path), cache_bpf)
    return bpf_path, False


def open_seccomp_fd(bpf_path: str) -> int:
    """以固定 FD 9 打开 BPF 文件供 bwrap --add-seccomp-fd 使用。"""
    fd = os.open(bpf_path, os.O_RDONLY)
    try:
        if fd != SECCOMP_FD:
            os.dup2(fd, SECCOMP_FD)
            os.close(fd)
        return SECCOMP_FD
    except OSError:
        for candidate in (fd, SECCOMP_FD):
            try:
                os.close(candidate)
            except OSError:
                pass
        abort(f"无法打开 seccomp BPF 文件: {bpf_path}")
        raise AssertionError("unreachable")


def run_sandbox(
    config: Config,
    settings: EffectivePreset,
    entry: str,
    app_args: list[str],
    project_dir: str,
    settings_label: str,
    program_label: str,
) -> int:
    bwrap = resolve_bwrap(print_mode=False)
    state_dir = ensure_state_dir(config.general.state_dir)
    dbus_mode = effective_dbus_mode(settings)
    run_dir, run_id = create_run_dir(state_dir, settings_label)
    now = time.time()
    launcher_pid = os.getpid()
    info: dict = {
        "version": 1,
        "run_id": run_id,
        "preset": settings_label,
        "program_label": program_label,
        "program": entry,
        "args": app_args,
        "project_dir": project_dir,
        "created_at": now,
        "state": "starting",
        "launcher_pid": launcher_pid,
        "launcher_start": process_start_time(launcher_pid),
        "pid": None,
        "pid_start": None,
        "proxy_pid": None,
        "proxy_start": None,
        "dbus_mode": dbus_mode,
        "dbus_bus": None,
        "vhome": None,
        "x11_display": None,
        "seccomp": settings.features.get("seccomp", False),
        "seccomp_profile": (
            (settings.seccomp_profile or "default")
            if settings.features.get("seccomp", False)
            else None
        ),
        "seccomp_bpf": None,
        "seccomp_cache_hit": None,
    }

    proxy_proc: subprocess.Popen | None = None
    bwrap_proc: subprocess.Popen | None = None
    seccomp_fd: int | None = None
    seccomp_fd_open = False
    try:
        write_run_info(run_dir, info)

        x11_display: int | None = None
        if settings.features.get("x11"):
            x11_display = allocate_x11_display(state_dir)
            info["x11_display"] = x11_display

        vhome_path: str | None = None
        if settings.features.get("vhome"):
            vhome_path = prepare_vhome_dir(run_dir)
            info["vhome"] = vhome_path

        bus_path: str | None = None
        if dbus_mode == "proxy":
            if not settings.dbus_whitelist:
                warn("dbus=proxy 但白名单为空, 沙箱内无任何可访问 dbus 服务")
            bus_dir = run_dir / "dbus"
            try:
                bus_dir.mkdir(mode=0o700, exist_ok=True)
            except OSError as exc:
                abort(f"无法创建 dbus 代理目录 {bus_dir}: {exc}")
            bus_path = str(bus_dir / "bus")
            info["dbus_bus"] = bus_path

        if settings.features.get("seccomp", False):
            profile_name = settings.seccomp_profile or "default"
            profile = config.seccomp_profiles.get(profile_name)
            if profile is None:
                abort(f"seccomp 配置 '{profile_name}' 不存在")
            bpf_path, cache_hit = obtain_seccomp_bpf(profile, state_dir, run_dir)
            seccomp_fd = open_seccomp_fd(bpf_path)
            seccomp_fd_open = True
            info["seccomp_bpf"] = bpf_path
            info["seccomp_cache_hit"] = cache_hit
            info["seccomp_profile"] = profile_name

        write_run_info(run_dir, info)

        mkdirs, bwrap_args = build_bwrap_cmd(
            settings,
            entry,
            app_args,
            project_dir,
            dbus_mode,
            bus_path=bus_path,
            vhome_path=vhome_path,
            seccomp_fd=seccomp_fd,
            x11_display=x11_display,
        )
        ensure_create_dirs(mkdirs)
        print_banner(settings_label, program_label, entry, project_dir)

        if dbus_mode == "proxy":
            assert bus_path is not None
            proxy_cmd = build_proxy_cmd(settings, bus_path)
            proxy_proc = start_dbus_proxy(proxy_cmd, bus_path)
            info["proxy_pid"] = proxy_proc.pid
            info["proxy_start"] = process_start_time(proxy_proc.pid)
            write_run_info(run_dir, info)

        try:
            bwrap_proc = subprocess.Popen(
                [bwrap, *bwrap_args],
                start_new_session=True,
                pass_fds=(SECCOMP_FD,) if seccomp_fd is not None else (),
            )
        except OSError as exc:
            abort(f"无法启动 bwrap: {exc}")
        if seccomp_fd_open:
            try:
                os.close(SECCOMP_FD)
            except OSError:
                pass
            seccomp_fd_open = False
        info.update(
            {
                "state": "running",
                "pid": bwrap_proc.pid,
                "pid_start": process_start_time(bwrap_proc.pid),
                "started_at": time.time(),
            }
        )
        write_run_info(run_dir, info)
        return normalize_rc(bwrap_proc.wait())
    finally:
        if seccomp_fd_open:
            try:
                os.close(SECCOMP_FD)
            except OSError:
                pass
        if bwrap_proc is not None and bwrap_proc.poll() is None:
            bwrap_proc.kill()
            try:
                bwrap_proc.wait(timeout=2)
            except subprocess.TimeoutExpired:
                pass
        stop_subprocess(proxy_proc)
        shutil.rmtree(run_dir, ignore_errors=True)


def print_plan(
    config: Config,
    settings: EffectivePreset,
    entry: str,
    app_args: list[str],
    project_dir: str,
    settings_label: str,
) -> int:
    dbus_mode = effective_dbus_mode(settings)
    bwrap = resolve_bwrap(print_mode=True)

    lines: list[str] = []
    lines.append("RUN_SANDBOX_STATE_DIR=" + shlex.quote(config.general.state_dir))
    lines.append('mkdir -p -- "$RUN_SANDBOX_STATE_DIR"')
    lines.append(
        'RUN_SANDBOX_RUN_DIR="$(mktemp -d -p "$RUN_SANDBOX_STATE_DIR" '
        + shlex.quote(f"{safe_run_prefix(settings_label)}.XXXXXX")
        + ')"'
    )
    lines.append('RUN_SANDBOX_PROXY_PID=""')
    lines.append(
        '_run_sandbox_cleanup() { if [ -n "$RUN_SANDBOX_PROXY_PID" ]; then '
        'kill "$RUN_SANDBOX_PROXY_PID" 2>/dev/null || true; fi; '
        'rm -rf "$RUN_SANDBOX_RUN_DIR"; }'
    )
    lines.append("trap _run_sandbox_cleanup EXIT")

    vhome_path: str | None = None
    if settings.features.get("vhome"):
        vhome_path = VHOME_DIR_ARG
        lines.append(
            'mkdir -p -- "$RUN_SANDBOX_RUN_DIR/vhome/.config" '
            '"$RUN_SANDBOX_RUN_DIR/vhome/.cache"'
        )

    bus_path: str | None = None
    if dbus_mode == "proxy":
        bus_path = DBUS_BUS_ARG
        lines.append('mkdir -p -- "$RUN_SANDBOX_RUN_DIR/dbus"')
        lines.append(shell_join_argv(build_proxy_cmd(settings, DBUS_BUS_ARG)) + " &")
        lines.append("RUN_SANDBOX_PROXY_PID=$!")
        lines.append(
            '_run_sandbox_i=0; while [ "$_run_sandbox_i" -lt 50 ] && '
            '[ ! -S "$RUN_SANDBOX_RUN_DIR/dbus/bus" ]; do sleep 0.05; '
            '_run_sandbox_i=$((_run_sandbox_i+1)); done'
        )
        lines.append(
            'if [ ! -S "$RUN_SANDBOX_RUN_DIR/dbus/bus" ] || '
            '! kill -0 "$RUN_SANDBOX_PROXY_PID" 2>/dev/null; then '
            'echo "xdg-dbus-proxy 启动失败或提前退出" >&2; exit 1; fi'
        )
        if not settings.dbus_whitelist:
            warn("dbus=proxy 但白名单为空, 沙箱内无任何可访问 dbus 服务")

    x11_display: int | None = None
    if settings.features.get("x11"):
        x11_display = choose_x11_display()

    seccomp_fd: int | None = None
    if settings.features.get("seccomp", False):
        profile_name = settings.seccomp_profile or "default"
        profile = config.seccomp_profiles.get(profile_name)
        if profile is None:
            abort(f"seccomp 配置 '{profile_name}' 不存在")
        seccomp_fd = SECCOMP_FD
        cc = resolve_cc(print_mode=True)
        key = seccomp_cache_key(profile.filter_text)
        lines.append(
            'RUN_SANDBOX_SECCOMP_CACHE="$RUN_SANDBOX_STATE_DIR/'
            f'{SECCOMP_CACHE_DIRNAME}"'
        )
        lines.append("RUN_SANDBOX_SECCOMP_KEY=" + shlex.quote(key))
        lines.append(
            'RUN_SANDBOX_SECCOMP_BPF="$RUN_SANDBOX_SECCOMP_CACHE/'
            'seccomp-$RUN_SANDBOX_SECCOMP_KEY.bpf"'
        )
        lines.append(
            'mkdir -p -- "$RUN_SANDBOX_SECCOMP_CACHE" '
            '"$RUN_SANDBOX_RUN_DIR/seccomp"'
        )
        lines.append('if [ ! -s "$RUN_SANDBOX_SECCOMP_BPF" ]; then')
        lines.append(
            "  cat > \"$RUN_SANDBOX_RUN_DIR/seccomp/filter.c\" "
            "<<'RUN_SANDBOX_SECCOMP_EOF'"
        )
        lines.extend("  " + line for line in generate_seccomp_c(profile).rstrip().splitlines())
        lines.append("RUN_SANDBOX_SECCOMP_EOF")
        lines.append(
            "  " + shlex.quote(cc)
            + ' -O2 -Wall -o "$RUN_SANDBOX_RUN_DIR/seccomp/filter-gen" '
            '"$RUN_SANDBOX_RUN_DIR/seccomp/filter.c" -lseccomp'
        )
        lines.append(
            '  "$RUN_SANDBOX_RUN_DIR/seccomp/filter-gen" '
            '> "$RUN_SANDBOX_RUN_DIR/seccomp/filter.bpf"'
        )
        lines.append(
            '  cp -- "$RUN_SANDBOX_RUN_DIR/seccomp/filter.bpf" '
            '"$RUN_SANDBOX_SECCOMP_BPF.tmp.$$"'
        )
        lines.append(
            '  mv -- "$RUN_SANDBOX_SECCOMP_BPF.tmp.$$" '
            '"$RUN_SANDBOX_SECCOMP_BPF"'
        )
        lines.append("fi")
        lines.append(
            'cp -- "$RUN_SANDBOX_SECCOMP_BPF" '
            '"$RUN_SANDBOX_RUN_DIR/seccomp/filter.bpf"'
        )
        lines.append('exec 9<"$RUN_SANDBOX_SECCOMP_BPF"')

    mkdirs, bwrap_args = build_bwrap_cmd(
        settings,
        entry,
        app_args,
        project_dir,
        dbus_mode,
        bus_path=bus_path,
        vhome_path=vhome_path,
        seccomp_fd=seccomp_fd,
        x11_display=x11_display,
    )

    for directory in mkdirs:
        lines.append("mkdir -p -- " + shlex.quote(directory))
    lines.append(shell_join_argv([bwrap, *bwrap_args]))
    print("\n".join(lines))
    return 0


def do_edit(opts: CliOptions, config: Config, conf_path: Path) -> int:
    if opts.as_preset is not None or opts.overrides:
        abort("edit 命令不接受 --as/--preset / --override")
    editor = config.general.editor
    if not editor:
        abort("未配置编辑器 ([general] editor)")
    parts = shlex_split_safe(editor, "[general] editor")
    if not parts:
        abort("[general] editor 配置为空命令")
    if parts[0].startswith("~"):
        parts[0] = os.path.expanduser(parts[0])
    argv = [*parts, *opts.app_args, str(conf_path)]
    if opts.print_mode:
        print(shell_join_argv(argv))
        return 0
    return normalize_rc(run_cmd(argv))


def do_ps(config: Config, json_mode: bool = False) -> int:
    state_dir = ensure_state_dir(config.general.state_dir)
    entries = scan_state_dir(state_dir, clean_stale=True)
    now = time.time()
    if json_mode:
        rows = []
        for run_dir, info in entries:
            rows.append(
                {
                    "run_id": info.get("run_id") or run_dir.name,
                    "preset": info.get("preset"),
                    "program": info.get("program"),
                    "args": info.get("args", []),
                    "state": info.get("state"),
                    "pid": info.get("pid"),
                    "proxy_pid": info.get("proxy_pid"),
                    "launcher_pid": info.get("launcher_pid"),
                    "dbus_mode": info.get("dbus_mode"),
                    "dbus_bus": info.get("dbus_bus"),
                    "vhome": info.get("vhome"),
                    "seccomp": info.get("seccomp"),
                    "seccomp_profile": info.get("seccomp_profile"),
                    "seccomp_bpf": info.get("seccomp_bpf"),
                    "seccomp_cache_hit": info.get("seccomp_cache_hit"),
                    "x11_display": info.get("x11_display"),
                    "project_dir": info.get("project_dir"),
                    "age_seconds": int(now - float(info.get("created_at") or now)),
                }
            )
        print(json.dumps(rows, ensure_ascii=False, indent=2))
        return 0

    if not entries:
        print("没有正在运行的任务。")
        return 0
    print(
        f"{'RUN ID':<26} {'PRESET':<16} {'STATE':<9} {'PID':>7} {'AGE':>8}  PROGRAM"
    )
    for run_dir, info in entries:
        run_id = str(info.get("run_id") or run_dir.name)
        preset = str(info.get("preset") or "?")
        state = str(info.get("state") or "?")
        pid = info.get("pid") or "-"
        age = format_age(now - float(info.get("created_at") or now))
        program = str(info.get("program") or "")
        print(f"{run_id:<26} {preset:<16} {state:<9} {pid:>7} {age:>8}  {program}")
    return 0


def do_control(config: Config, ref: str, force: bool) -> int:
    state_dir = ensure_state_dir(config.general.state_dir)
    run_dir, info = find_run_dir(state_dir, ref)
    run_id = str(info.get("run_id") or run_dir.name)
    main_pid = info.get("pid") or info.get("launcher_pid")
    proxy_pid = info.get("proxy_pid")
    launcher_pid = info.get("launcher_pid")

    if not run_info_alive(info):
        shutil.rmtree(run_dir, ignore_errors=True)
        print(f"任务 {run_id} 已经结束。")
        return 0

    if force:
        print(f"强制停止 {run_id} (SIGKILL -> {main_pid or '-'})")
        terminate_run_entry(info, force=True)
        if _wait_run_dir_gone(run_dir, 2.0):
            print(f"已停止并清理: {run_id}")
            return 0
    else:
        print(f"中断 {run_id} (SIGINT -> {main_pid or '-'})")
        terminate_run_entry(info, force=False)
        if _wait_run_dir_gone(run_dir, 4.0):
            print(f"已停止并清理: {run_id}")
            return 0
        print("SIGINT 未能在 4s 内结束任务, 升级为 SIGTERM...")
        _signal_main(info, signal.SIGTERM)
        _signal_pid(proxy_pid, signal.SIGTERM)
        if _wait_run_dir_gone(run_dir, 2.0):
            print(f"已停止并清理: {run_id}")
            return 0

    # 最后兜底: 对残留进程 SIGKILL; 若全部死亡则由本控制器直接清理状态目录
    _signal_main(info, signal.SIGKILL)
    _signal_pid(proxy_pid, signal.SIGKILL)
    _signal_pid(launcher_pid, signal.SIGKILL)
    if _wait_run_dir_gone(run_dir, 1.0):
        print(f"已停止并清理: {run_id}")
        return 0
    if not run_info_alive(info):
        shutil.rmtree(run_dir, ignore_errors=True)
        print(f"已强制清理: {run_id}")
        return 0
    abort(f"无法停止任务 {run_id} (主进程 {main_pid} 仍存活)")


def dispatch_control(opts: CliOptions, config: Config) -> int:
    if opts.print_mode:
        abort("--print 不适用于 ps/stop/kill 控制命令")
    if opts.as_preset is not None or opts.overrides:
        abort("ps/stop/kill 不接受 --as/--preset/--override")

    command = opts.app
    assert command is not None
    if command == "ps":
        if not opts.app_args:
            return do_ps(config)
        if opts.app_args == ["--json"]:
            return do_ps(config, json_mode=True)
        abort("ps 仅支持可选参数 --json")
    if command in ("stop", "kill"):
        if len(opts.app_args) != 1 or not opts.app_args[0].strip():
            abort(f"{command} 需要一个非空运行 ID (来自 run-sandbox ps)")
        return do_control(config, opts.app_args[0], force=(command == "kill"))
    abort(f"未知控制命令 '{command}'")


def dispatch(opts: CliOptions, config: Config, conf_path: Path) -> int:
    if (
        opts.app in ("ps", "stop", "kill")
        and opts.as_preset is None
        and resolve_preset_name(opts.app, config) is None
    ):
        return dispatch_control(opts, config)

    if (
        opts.app == "edit"
        and opts.as_preset is None
        and resolve_preset_name("edit", config) is None
    ):
        return do_edit(opts, config, conf_path)

    settings_name, settings, entry, program_label = resolve_invocation(opts, config)
    settings = copy.deepcopy(settings)
    program_override, general = apply_overrides(opts.overrides, config, settings)
    if program_override is not None:
        entry = program_override
        program_label = "--override program"

    if settings.features.get("seccomp", False):
        profile_name = settings.seccomp_profile or "default"
        if profile_name not in config.seccomp_profiles:
            avail = ", ".join(sorted(config.seccomp_profiles)) or "<空>"
            abort(
                f"seccomp 指定了不存在的过滤配置 '{profile_name}' "
                f"(可用: {avail})"
            )

    if not os.path.exists(entry):
        abort(f"入口不存在: {entry}")
    if not os.access(entry, os.X_OK):
        abort(f"入口不可执行: {entry}")

    try:
        project_dir = os.path.realpath(os.getcwd())
    except OSError as exc:
        abort(f"无法确定当前工作目录: {exc}")
    if not project_dir:
        abort("无法确定当前工作目录")

    run_security_checks(general, settings, project_dir, opts.print_mode)

    if opts.print_mode:
        return print_plan(
            config,
            settings,
            entry,
            opts.app_args,
            project_dir,
            settings_name,
        )
    return run_sandbox(
        config,
        settings,
        entry,
        opts.app_args,
        project_dir,
        settings_name,
        program_label,
    )


def main(argv: list[str] | None = None) -> int:
    args = sys.argv[1:] if argv is None else argv
    try:
        opts = parse_cli(args)
        if opts.help:
            print(USAGE, end="")
            return 0
        conf_path = find_config_path()
        config = load_config(conf_path)
        return dispatch(opts, config, conf_path)
    except Abort as exc:
        print(f"Abort: {exc}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        return 130


if __name__ == "__main__":
    sys.exit(main())
