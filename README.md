# herdr.tailcat — 把本地 herdr socket 暴露到 tailcat 隧道

一个 [herdr](https://herdr.dev) 插件：把本机的 herdr API socket（默认
`~/.config/herdr/herdr.sock`）通过 [tailcat](https://github.com/tailscale/tailcat)
的内网穿透隧道暴露出去 —— WireGuard 端到端加密、DERP 中继打洞、无控制面、无需 root、
不在本机开任何监听端口。

适合的场景：在另一台机器上用 herdr 客户端（如 [herdrm](https://github.com/missuo/herdrm)、
`herdr api`、脚本）驱动这台机器上的 herdr，而不需要 SSH 端口转发。

## 工作原理

```
┌─ 远端客户端 ─┐   WireGuard/DERP   ┌─ herdr-tailcatd（本插件）─┐
│ tailcat CLI  │ ══════════════════▶ │ tailcat.Server            │
│ 或 socat 桥接 │ ◂═════════════════ │   OnTCP :6464 ──dial──▶ herdr.sock │
└──────────────┘   加密 + NAT 穿透   └────────────────────────────┘
```

- 守护进程 `herdr-tailcatd`（Go，基于 tailcat 库）在隧道内只监听一个虚拟端口 **6464**，
  并把每条连接原样转发到本地 herdr Unix socket（herdr 协议是换行分隔的 JSON-RPC，
  按字节透传即可）。
- tailcat 的包过滤被收紧到仅 6464 端口，隧道到不了本机任何其他端口。
- 首次启动生成服务器密钥并把最近的 DERP 区域固化进去
  （等价于 `tailcat genkey --fixed-region`），所以 **token 在重启后保持稳定**。

### Key 与 token 的稳定性

token 由服务器私钥派生：key 不变，token 就不变。守护进程保证这一点的机制：

- key 只生成一次，存放在插件 state 目录的 `server.private.json`（0600），
  之后每次启动（herdr 重启、live handoff、守护进程崩溃后被重新拉起）都加载同一个文件。
- DERP 区域在首次运行时探测一次并固化进 key 文件，重启不再重新探测
  （否则换区域 = 换 token）。
- **想彻底钉死身份**（跨插件重装、state 目录被清也能保住 token）：
  把 `server.private.json` 复制到插件 config 目录
  （`herdr plugin config-dir herdr.tailcat`）。config 目录里的 key 优先于
  state 目录，且永远不会被覆盖。也可以直接放一个 `tailcat genkey`
  生成的 key 文件进去（缺 Region 的会自动补全并回写）。
- 想让 token 失效换新身份：删掉两处 key 文件后 restart。
- 短 token 引用的是 tailcat 公共 DERP map 里的区域 ID；万一上游 map 变动导致
  短 token 无法解析，用 `token.full`（内嵌中继信息，不受影响），或删 key 重新生成。

## 安装

```sh
# 本地开发
herdr plugin link /path/to/herdr_tc        # 本仓库
sh scripts/build.sh                        # link 不会自动跑 build

# 或从 GitHub 安装（发布时把 go.mod 里的 replace 换成正式版本号）
herdr plugin install <owner>/<repo>
```

启用后，herdr 每次启动（以及 live handoff 后）都会通过 `[[startup]]` 钩子
自动拉起守护进程；已有实例在跑时是幂等的。

## 使用

```sh
herdr plugin action invoke herdr.tailcat.token     # 查看 token 和客户端用法
herdr plugin action invoke herdr.tailcat.restart   # 重启暴露
herdr plugin action invoke herdr.tailcat.stop      # 停止暴露（token 立即失效）
herdr plugin log list --plugin herdr.tailcat       # 查看钩子执行日志
```

### 客户端

一次性会话（stdin/stdout 就是 herdr socket 的字节流）：

```sh
printf '{"id":"1","method":"plugin.list","params":{}}\n' | tailcat <token> 6464
```

给 herdrm 这类期望 Unix socket 的客户端用的常驻桥接：

```sh
socat UNIX-LISTEN:/tmp/herdr-remote.sock,fork EXEC:'tailcat <token> 6464'
# 然后让客户端连 /tmp/herdr-remote.sock
```

## 安全（务必阅读）

herdr 的插件模型**没有沙箱**；同样，这个插件暴露的 herdr socket 拥有对 herdr
服务器的**完全控制权**（往任意 pane 发按键、启动 agent、调用全部 API）。
请把它当作"把 shell 暴露到网络上"来对待：

- **token 即凭据**。任何拿到 token 的人都能连接。token 文件以 0600 存放在
  插件 state 目录；不要在公开场合粘贴。
- **建议配置客户端白名单**。在 `herdr plugin config-dir herdr.tailcat`
  指向的目录里创建 `allow.list`，每行一个客户端 nodekey（客户端用
  `tailcat genkey --client` 生成），然后 restart。未匹配的客户端在
  WireGuard 握手阶段就会被静默忽略，甚至无法得知服务存在。
- 不需要时及时 `stop`；卸载插件（`herdr plugin unlink herdr.tailcat`）
  后记得确认守护进程已停止。
- 传输本身始终是 WireGuard 端到端加密；DERP 中继只看得到密文。

## 文件说明

```
herdr-plugin.toml          插件清单（startup 钩子 + token/stop/restart 三个 action）
cmd/herdr-tailcatd/        守护进程（Go + tailcat 库）
scripts/build.sh           go build → bin/herdr-tailcatd
scripts/start.sh           幂等启动（startup 钩子）
scripts/stop.sh            停止
scripts/restart.sh         重启
scripts/token.sh           打印 token 与客户端用法
```

## 开发

本仓库的 `go.mod` 用 `replace github.com/tailscale/tailcat => ../tailcat`
指向旁边的 tailcat 源码树。发布前请去掉 replace 并 require 一个正式版本。

```sh
sh scripts/build.sh                                  # 构建
HERDR_SOCKET_PATH=~/.config/herdr/herdr.sock \
HERDR_PLUGIN_STATE_DIR=.state \
  ./bin/herdr-tailcatd                               # 前台手动跑（调试用）
```
