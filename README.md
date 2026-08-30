# EasyBwrap

个人自用项目，在ArchLinux调试，不做通用承诺，也不保证非Arch环境可用。
README下方剩余内容为LLM生成，大概不准确；但是暂时懒得调了。有空再写，也可能不写。

EasyBwrap 是一个用 Python 写的沙盒启动脚本（`easy-bwrap.py`），用来以配置文件的方式使用 [bubblewrap](https://github.com/containers/bubblewrap)（bwrap）。预设化配置与指定运行程序；支持高级安全特性配置；支持通过此工具运行的程序的状态管理。

## 功能

- **预设机制**：在 TOML 定义 `[preset.名称]`，每个预设指定要运行的程序和沙箱参数；预设可以 `extends` 另一个预设，在其基础上增改（基于预设Override）。
- **目录绑定**：`bind` 列表声明哪些宿主目录暴露给沙盒，支持 `ro`（只读）、`create`（自动建目录）、`rw-try` / `ro-try`（目录不存在就跳过）等模式。
- **特性开关**：GPU 直通（NVIDIA / dri）、tmpfs、网络隔离、独立终端会话、Wayland、X11（自动分配 display 号）、PipeWire 音频、虚拟 `$HOME` 等，按预设逐项开关。
- **默认拒绝**：未在配置里列出的文件系统路径、特性和程序不生效；另有黑名单（`blocklist`）兜底挡住 `/etc`、`~/.ssh` 之类的敏感路径。
- **DBus 控制**：`off`（不开放）/ `proxy`（经 xdg-dbus-proxy 按白名单过滤）/ `direct`（直通宿主总线）三种模式。
- **seccomp 过滤**：在配置里用简单的每行 DSL 写规则，运行时生成 C 源码、调用系统 C 编译器编译（依赖 libseccomp），导出 BPF 后通过 `--add-seccomp-fd` 交给 bwrap，编译结果按内容哈希缓存。
- **运行管理**：`ps` 列出正在运行的沙盒任务，`stop` / `kill` 分别温和中断和强杀；每个任务在状态目录下有独立子目录，退出后自动清理。
- **辅助选项**：`--print` 只打印将要执行的命令不实际运行；`--override KEY=VALUE` 临时覆盖配置；`--as PRESET` 借用某个预设的沙箱配置去运行别的程序。

## 依赖

- Python 3.11+（更低版本需另装 `tomli`）
- bubblewrap（`bwrap`）
- xdg-dbus-proxy（仅 `dbus = "proxy"` 时需要）
- C 编译器（cc / gcc / clang）和 libseccomp（仅启用 seccomp 过滤时需要）

## 配置与使用

仓库里的 `easy-bwrap.toml` 是一份示例配置。脚本默认读取与自己同目录的 `run-sandbox.toml`，所以要么把配置文件改名为 `run-sandbox.toml` 放在脚本旁边，要么用环境变量指定路径：

```sh
export RUN_SANDBOX_CONF=/path/to/easy-bwrap.toml
```

常用方式：

```sh
./easy-bwrap.py                     # 运行 [general] 里的 default 预设
./easy-bwrap.py zsh -l              # 运行指定预设
./easy-bwrap.py --print splayer a.mp4   # 只打印命令，不运行
./easy-bwrap.py --override net=off opencode
./easy-bwrap.py ps                  # 查看运行中的任务
```

详细语法直接看脚本开头的 docstring 和 `easy-bwrap.toml` 里的注释，配置文件能用的写法都在注释里。

## 许可

GPL-3.0，见 `LICENSE`。
