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
   `{"status":"empty"}`），下一次 `/write` 直接覆盖。只有想主动清空数据时才需要——
   `/clear` 只接受 POST，并且必须携带上一次 `/write` 返回的完全相同的密钥对：
   ```sh
   curl -X POST http://192.168.7.1/clear \
        -d '{"pk":"<上一次 /write 返回的 pk>","sk":"<上一次 /write 返回的 sk>"}'
   ```

## Web 服务 API

服务端：lwIP 原始 TCP 协议栈监听 80 端口，由现有 `NO_SYS` 主循环驱动（无 RTOS、
无额外线程）。响应使用 `Connection: close`；请求必须携带 `Content-Length` 头。

| 方法 | 路径 | 行为 |
|------|------|------|
| POST | `/write` | 发送 JSON 表单，如 `{"name":"alice","value":"hello"}`。提取配置字段（`web_server.c` 中的 `WRITE_FIELDS`，默认 `name`、`value`），**加密**后持久化到 flash。成功返回 `{"status":"ok","bytes":N,"pk":"<64位hex>","sk":"<64位hex>"}`：`pk`/`sk` 是本次写入记录的**清除回执**，请妥善保存。无效/空 body 返回 `400`；存储数据超过 2 KiB 返回 `413`。该端点带宽松 CORS 头（`Access-Control-Allow-Origin: *`）并支持 OPTIONS 预检，主机侧网页可跨域 POST 并读取响应。 |
| GET  | `/print` | 以 `application/json` 返回已存储的数据（读取时实时解密）；无有效数据时返回 `{"status":"empty"}`。该端点仅在 `DEBUG=1`（`tusb_config.h`）时编译进固件，默认固件下返回 `404`。 |
| GET  | `/sign` | 端点描述：`{"endpoint":"/sign","method":"POST","fields":["challenge","context","timestamp"]}`。 |
| POST | `/sign` | 用固件内置的 Ed25519 密钥对消息 `<challenge>:<context>:<timestamp>:device_001` 签名（自旧版固件迁移）。返回 `{"signature":"<base64>","timestamp":"<原样回显>","device_id":"device_001"}`；空 body/缺字段/格式错误返回 `400`。 |
| POST | `/clear` | 擦除已存储的数据，但**只有 body 携带当前记录那次 `/write` 返回的完全相同的 `pk`/`sk`**（hex）时才会执行，如 `{"pk":"...","sk":"..."}`。完全一致 → `{"status":"ok"}`；不一致 → `403` 且数据保持不动；缺失/格式错误 → `400`；无有效记录 → `200`（幂等空操作）。该端点同样带宽松 CORS 头（`Access-Control-Allow-Origin: *`）并支持 OPTIONS 预检（须携带正确回执才会真正擦除）。 |
| 任意 | 其它路径 | `404`。`GET /clear` 返回 `405`：擦除仅限 POST，浏览器链接或 `<img>` 永远无法触发擦除。 |

示例：

```sh
curl -X POST http://192.168.7.1/write -d '{"name":"alice","value":"hello"}'
#   -> {"status":"ok","bytes":32,"pk":"<64 位 hex>","sk":"<64 位 hex>"}
curl http://192.168.7.1/print
#   -> {"name":"alice","value":"hello"}
curl -X POST http://192.168.7.1/clear \
     -d '{"pk":"<上一次 /write 返回的 pk>","sk":"<上一次 /write 返回的 sk>"}'
#   -> {"status":"ok"}
```

**清除回执**：每次 `/write` 都会生成全新的密钥对，成功响应会把它以 hex 形式
（`pk`/`sk`）一并返回；设备端同样把这 64 字节存在记录头（偏移 36..99，见下文
布局）。`POST /clear` 把提交的密钥对与记录头逐字节比对，完全一致才执行擦除：

- 只有**最近一次 `/write`** 返回的回执有效：记录被再次写入后密钥轮换，旧回执
  会得到 `403`。
- 密钥不符时数据分毫不动；`GET /clear` 一律返回 `405`。
- 回执丢失后，有效记录无法再通过 `/clear` 擦除，但 `/write` 可以直接覆盖
  （写入不需要回执）。

**签名端点（`/sign`）** —— 自旧版固件迁移而来：POST 一个包含
`challenge`、`context`、`timestamp` 三个字段的 JSON 表单；固件用
TweetNaCl `crypto_sign`（Ed25519）对 UTF-8 消息
`<challenge>:<context>:<timestamp>:device_001` 签名，返回 base64 编码的
64 字节原始签名、原样回显的时间戳和设备 ID：

```sh
curl -X POST http://192.168.7.1/sign \
     -d '{"challenge":"abc","context":"login","timestamp":"2024-06-01T12:00:00Z"}'
# -> {"signature":"<64 字节签名的 base64>","timestamp":"2024-06-01T12:00:00Z","device_id":"device_001"}
```

签名密钥固定在固件镜像中（与旧版固件使用相同常量，已有验签方无需改动）：
设备 ID 为 `device_001`，Ed25519 公钥（base64）为
`f/LmPWawjJ9QjK6GniT26UdCcgIEd2tcoy3lbvCThNQ=`。可用仓库自带的纯标准库验签
工具（RFC 8032 实现，无第三方依赖）验证：

```sh
python sign_verify.py 'abc:login:2024-06-01T12:00:00Z:device_001' '<sign 返回的 signature>'
# OK: signature is valid for this message and key
```

`/write`、`/clear`、`/sign` 的响应带宽松 CORS 头（`Access-Control-Allow-Origin: *`）
并接受 OPTIONS 预检，主机上的网页可以跨域写入、清除与签名；`/print` 刻意不加
CORS，随机网页无法跨域读取存储数据。清除有效记录仍必须携带其完全一致的
`pk`/`sk` 回执（否则 `403`），空槽上的 `/clear` 也只是无害的 `200` 空操作——
放开 CORS 无法抹掉网页本不知晓其回执的数据。

**2 KiB 限制**针对的是*存储后的 JSON*（包含字段名、引号和花括号），而不是单纯的
value。对固定 9 字符 `name` 的载荷，固定开销为 31 字节，因此可接受的 value 上限是
`2048 - 31 = 2017` 个字符；更大值会被 `413` 拒绝（`stress_test.py` 会自动探测该
边界）。

**JSON 转义**：值中的常见转义（`\"`、`\\`、`\/`、`\b`、`\f`、`\n`、`\r`、`\t`）
会被正确解码并在读取时重新转义，往返一致；不支持的转义（如 `\uXXXX`）或非法
JSON 会返回 `400`，不会静默改写数据。**Content-Length**：空或非数字的值返回
`400`；溢出的值会饱和并返回 `413`，声明长度超过接收缓冲（约 3.1 KB）也同样立即
返回 `413` 并关闭连接，而不是挂起到超时。

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
记录头里这对密钥同时充当 `/clear` 的回执：只有提交的密钥对与头部逐字节一致时，
`POST /clear` 才会擦除——这能挡住误触链接、网页 `<img>` 之类的意外请求；但正如
上文所述，能直接 dump flash 的人同样拿得到密钥，因此它不对抗这类攻击者。

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
python stress_test.py --mode clear       # 用最近一次 /write 的回执擦除数据
python stress_test.py --help             # 查看全部选项
```

预检会校验带密钥保护的清除契约（`GET /clear` 必须返回 `405`；探测 `/write`
必须返回 `pk`/`sk` 回执；错误密钥的 `/clear` 必须 `403` 且数据原封不动；
正确回执能擦除记录，随后对空槽重复 `/clear` 仍是 `200` 空操作），超限
`/write` 被 `413` 干净拒绝，每个错误响应都必须是完整可解析的 JSON（防止响应体
长度类回归），单 worker 下做 JSON 转义往返校验，并二分探测真实最大 value 长度
（预期约 `2017`）。工具会自动记住每次成功 `/write` 的回执，因此
`--mode clear` 能擦除本次运行写入的数据；要清除早期会话写入的记录请传
`--pk`/`--sk`（预检无法清除的旧记录会被探测写入覆盖）。`-s` 超过上限会在
启动时直接拒绝，避免注定失败配置刷出成片 `413`。注意：对写入数据的逐字节校验
只在 `--workers 1` 下有意义。工具通过 `GET /print` 校验写入，而该端点只在
`DEBUG=1`（`tusb_config.h`）的固件中存在；默认 `DEBUG=0` 固件下预检会以明确
提示中止。

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
- 调试读回：`tusb_config.h` 中的 `DEBUG`（默认 0）。HTTP `GET /print`
  端点（读回已存储记录）仅在 `DEBUG=1` 时编译进固件；`DEBUG=0` 时该路径返回
  `404`。需要读回数据时请以 `DEBUG=1` 构建固件。
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
