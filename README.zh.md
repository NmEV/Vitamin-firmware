# USBNet

在树莓派 Pico（RP2040）/ Pico 2（RP2350）上实现的 **USB 以太网**，内置一个
**加密的 flash 持久化 Web 服务**。

板子以 USB 网卡形式出现（默认 CDC-NCM；`tusb_config.h` 里把 `USE_ECM` 改为 `1`
可切换 ECM/RNDIS），给自己分配 `192.168.7.1`，运行 DHCP 服务器给主机分配
`192.168.7.16`，并通过 mDNS 响应 `demo.local`。80 端口上运行一个微型 HTTP 服务，
暴露三个接口；写入的载荷在持久化到 flash 前会被加密。

## 快速开始

1. 构建（或直接下载 CI 产物，见[构建](#构建)）并烧录固件：按住 BOOTSEL 键，
   插入 USB 线，把 `.uf2` 文件拖到 `RPI-RP2` 磁盘上。
2. 主机会从 Pico 的 DHCP 服务器拿到地址（`192.168.7.16`）。`ping 192.168.7.1`
   和 `ping demo.local` 都应该能通。
3. **升级固件后无需手动清数据** —— 存储头部带格式版本号（见[存储与加密](#存储与加密)），
   固件与旧记录格式不兼容时旧数据会自动按空处理（`/print` 返回
   `{"status":"empty"}`），下一次 `/write` 直接覆盖。只有想主动清空数据时才需要：
   ```sh
   curl http://192.168.7.1/clear
   ```

## Web 服务 API

服务端：lwIP 原始 TCP 协议栈监听 80 端口，由现有 `NO_SYS` 主循环驱动（无 RTOS、
无额外线程）。响应使用 `Connection: close`；请求必须携带 `Content-Length` 头。

| 方法 | 路径 | 行为 |
|------|------|------|
| POST | `/write` | 发送 JSON 表单，如 `{"name":"alice","value":"hello"}`。提取配置字段（`web_server.c` 中的 `WRITE_FIELDS`，默认 `name`、`value`），**加密**后持久化到 flash。成功返回 `{"status":"ok","bytes":N}`；无效/空 body 返回 `400`；存储数据超过 2 KiB 返回 `413`。 |
| GET  | `/print` | 以 `application/json` 返回已存储的数据（读取时实时解密）；无有效数据时返回 `{"status":"empty"}`。 |
| GET  | `/clear` | 擦除已存储的数据。返回 `{"status":"ok"}`。 |
| 任意 | 其它路径 | `404`。 |

示例：

```sh
curl -X POST http://192.168.7.1/write -d '{"name":"alice","value":"hello"}'
#   -> {"status":"ok","bytes":37}
curl http://192.168.7.1/print
#   -> {"name":"alice","value":"hello"}
curl http://192.168.7.1/clear
```

**2 KiB 限制**针对的是*存储后的 JSON*（包含字段名、引号和花括号），而不是单纯的
value。对固定 9 字符 `name` 的载荷，固定开销为 31 字节，因此可接受的 value 上限是
`2048 - 31 = 2017` 个字符；更大值会被 `413` 拒绝（`stress_test.py` 会自动探测该
边界）。

**JSON 转义**：值中的常见转义（`\"`、`\\`、`\/`、`\b`、`\f`、`\n`、`\r`、`\t`）
会被正确解码并在读取时重新转义，往返一致；不支持的转义（如 `\uXXXX`）或非法
JSON 会返回 `400`，不会静默改写数据。**Content-Length**：值畸形（空、非数字、
溢出）返回 `400`；声明长度超过接收缓冲（约 3.1 KB）会立即返回 `413` 并关闭连接，
而不是挂起到超时。

## 存储与加密

`storage.c` 遵循官方 Pico `flash_program` 模式
（`flash_safe_execute` + `flash_range_erase/program`），位置在
`XIP_BASE + 256 KB`。固件从 flash 起始处链接，因此该槽位要求**整个固件体积低于
256 KB**——CI 会检查 `arm-none-eabi-size` 结果并上传 `usbnet.map`，防止代码增长
侵入存储区。**载荷永不以明文落盘**：

- 每次写入生成一批**全新的 `crypto_box` 密钥对**（X25519）和**全新的 24 字节
  nonce**（tweetnacl；本固件用 `get_rand_32()` 提供 `randombytes()`）。
- 载荷按 **256 字节一节**进行 box 加密（XSalsa20-Poly1305，自盒模式）；每节的
  nonce 是基 nonce 的后 8 字节 XOR 上节序号，因此每节拥有独立密钥流并且各自
  独立认证。
- 头部含**格式版本字节**：固件升级后若布局不兼容，旧记录会立刻被识别为
  "非本版本格式"并自动按空处理（无需升级后手动 `/clear`；下一次 `/write` 直接
  覆盖旧扇区）。头部之后是加密分节。flash 布局（占用一个 4 KB 扇区）：

  ```
  [0..3]    magic 'USBN'              （被擦除时缺失 == 空/损坏）
  [4]       格式版本（当前为 1；擦除后为 0xFF）
  [5..7]    保留（0xFF）
  [8..11]   uint32 小端 明文长度
  [12..35]  基 nonce（24 字节）
  [36..67]  公钥（32 字节）
  [68..99]  私钥（32 字节）
  [100..]   box 分节：每节 poly1305 MAC（16 字节）+ 密文
  ```

- `/print` 读回 nonce 与两把密钥，逐节打开（每节先解到一小段栈缓冲，再拼接到
  调用方缓冲区）；认证失败（数据损坏/不匹配）按空数据处理。

私钥与载荷一并存储（本功能的目标是*载荷*不以明文落盘，而非密钥保密），因此
防护对象是"随手读 flash 转储"的人，而不是能同时拿到 flash 内容与固件的定向攻击者。

## 内存配置（`pico_config.h`）

通过 SDK 的 `PICO_CONFIG_HEADER_FILES` 机制注入（见 `CMakeLists.txt`）：

- **`PICO_STACK_SIZE = 0x1000`（4 KiB）** —— 默认 2 KiB 对运行在 lwIP/Web 回调链
  深处的 `crypto_scalarmult`（约 1.5 KiB）来说太紧。4 KiB 是上限：默认 memmap 把
  core-0 栈放在 4 KiB 的 `SCRATCH_Y` 区域（再大链接会失败）。
- **`PICO_USE_STACK_GUARDS = 1`** —— 硬件级栈溢出保护：RP2350-ARM 上 SDK 会把
  Armv8-M 的 `MSPLIM` 寄存器设为栈底（RP2040 用 Armv6-M MPU，RISC-V 用 PMP），
  栈溢出会立即触发故障，而不是静默破坏 SRAM。

## 压力测试

`stress_test.py`（Python 3.8+，仅标准库）对接口进行压测并输出延迟
（avg/min/max/p50/p95）、吞吐与失败统计：

```sh
python stress_test.py                    # 100 轮：write -> print -> 校验
python stress_test.py -n 500 -s 512      # 500 轮，value 512 字节
python stress_test.py -w 4 --mode write  # 4 并发 worker，纯写吞吐
python stress_test.py --help             # 查看全部选项
```

预检会校验契约（`/clear` 后 `/print` 返回 `{"status":"empty"}`；超限 `/write`
被 `413` 拒绝且响应必须是完整可解析的 JSON——防止响应体长度类回归；单 worker
下还会做一次 JSON 转义往返校验），并二分探测真实可接受的最大 value 长度（预期
约 `2017`）。`-s` 超过上限会在启动时直接拒绝，避免注定失败配置刷出成片
`413`。注意：对写入数据的逐字节校验只在 `--workers 1` 下有意义。

## 构建

**GitHub Actions**（`.github/workflows/main.yml`）在 `ubuntu-latest` 上用
ARM GCC 14.2.rel1 + Pico SDK 2.3.0（与本地 VS Code 环境一致；工具链与 SDK 有
缓存）同时构建 `pico`（RP2040）与 `pico2`（RP2350）Release，push/PR 到
`main`/`master` 或手动触发。产物 `usbnet-firmware-pico` /
`usbnet-firmware-pico2` 各是一个 zip，内含 `build/usbnet.uf2`（烧这个）、
`build/usbnet.elf`、`build/usbnet.bin` 与 `build/usbnet.map`。若固件体积长到
侵入 256 KB 存储槽位，CI 会直接失败。

本地开发：使用树莓派 Pico VS Code 扩展（`CMakeLists.txt` 已配置，SDK 2.3.0 +
GCC 14.2），或手动构建：

```sh
mkdir build && cd build
cmake -DPICO_BOARD=pico2 -DCMAKE_BUILD_TYPE=Release ..
make -j$(nproc)
```

**别忘了把板卡类型换成你实际使用的板卡**（VS Code 窗口右下角，或
`CMakeLists.txt` 里的 `PICO_BOARD` 变量）——CI 会覆盖为 `pico2`。

## 配置与注意事项

- 协议切换：`tusb_config.h` 的 `USE_ECM`（0 = CDC-NCM，适合 iOS / Windows 11；
  1 = ECM + RNDIS，适合 Windows / macOS）。
- 字段配置：`web_server.c` 中的 `WRITE_FIELDS`（默认为 `name`、`value`）。
- `flash_program.c` 是官方 flash 读写示例，仅作参考，**不参与编译**（它自带
  `main`）。
- `tweetnacl.c` / `tweetnacl.h` 是内置的单文件 TweetNaCl 实现，用于
  `crypto_box`、`crypto_box_open` 与 `randombytes`。
- Pico W / Pico 2 W 若需使用 CYW43 功能：先调用 `cyw43_arch_init()`，再以
  `usb_network_init(..., false)` 启动（避免重复初始化 lwIP）；若使用
  `pico_cyw43_arch_lwip_poll` 库，可以去掉 `pico_lwip*` 系列库。
- stdio 输出走 UART；发送字符 `'s'` 可演示一次干净的关机流程。
- 仅支持 HTTP 的一个小子集（GET/POST、`Content-Length`、`Connection: close`
  响应）；curl、浏览器、Postman 等常见客户端均可正常使用。

## 致谢

- 原始项目：[mattmyne/usbnet](https://github.com/mattmyne/usbnet)
  （其本身基于 TinyUSB 的 `net_lwip_webserver` 示例）。
- 加密采用 [TweetNaCl](https://tweetnacl.cr.yp.to/)。
