# MachOExplorer CLI 使用手册

本文档介绍 MachOExplorer 的命令行工具 `moex`。

## 总览
`moex` 是一个二进制，包含五个子命令：

| 子命令 | 用途 |
| --- | --- |
| `moex dump` | 以文本或 JSON 导出完整分析树 |
| `moex parse` | 检查文件能否解析 |
| `moex diff` | 对比两个 Mach-O 文件 |
| `moex cache-list` | 列出 dyld shared cache 中的镜像 |
| `moex cache-extract` | 从 dyld shared cache 提取镜像 |

它由 `crates/moex-cli` 构建，与桌面应用共用同一套解析器和分析树
（`crates/moex-core`），运行时不需要图形环境。

```bash
moex --help
moex --version
moex <subcommand> --help
```

### 获取二进制
- 自行构建：`cargo build --release -p moex-cli`，产物为 `target/release/moex`。
- macOS 应用包内自带：`MachOExplorer.app/Contents/MacOS/moex`。

下面的示例假设 `moex` 在 `PATH` 中；在源码目录下请使用 `./target/release/moex`。

## 从 2.x 迁移
MachOExplorer 2.x 的图形程序带有 `--cli` 模式，另有若干独立的 `moex-*` 工具。
在 3.x 中它们都是子命令：

| 2.x | 3.x |
| --- | --- |
| `MachOExplorer --cli [options] <file>` | `moex dump [options] <file>` |
| `moex-parse <file>...` | `moex parse <file>...` |
| `moex-diff <fileA> <fileB>` | `moex diff <fileA> <fileB>` |
| `moex-cache-list [options] <cache> [filter]` | `moex cache-list [options] <cache> [filter]` |
| `moex-cache-extract [options] <cache> <image> <out>` | `moex cache-extract [options] <cache> <image> <out>` |

保持不变的部分：
- `moex dump` 接受 `--cli` 模式原有的参数（`--format`、`--output`、`--max-rows`、`--max-depth`、`--root-path`、`--name-filter`、`--table-mode`、`--include-empty`），退出码也相同。
- `moex diff`、`moex cache-list`、`moex cache-extract` 沿用旧工具的参数语法：选项在前，写成 `--flag` 或 `--key=value`，位置参数在后。错误信息保留原有前缀（`moex-diff failed:`、`moex-cache-list failed:`、`moex-cache-extract failed:`）。
- JSON 输出格式不变（`schemaVersion` 为 `1.1`）。测试会把 Rust 版对测试语料中每个文件的输出与最后一个 C++ 版本的输出逐项比对。

已移除的部分：
- `MachOExplorer` 二进制不再接受 `--cli`，它只是图形界面。`moex dump` 也不接受 `--cli` 这个参数。
- 不再有 `moex-parse`、`moex-diff`、`moex-cache-list`、`moex-cache-extract` 这些二进制。

行为上有意为之的差异（例如 `--limit=` 的值不是数字时，现在是参数错误而不是崩溃）列在
[docs/rust-port-quirks.md](docs/rust-port-quirks.md)。

## `moex dump`

```bash
moex dump [options] <file>
```

对一个文件执行完整分析，并输出分析树。

### 参数说明

- `--format text|json`
  输出格式，默认 `text`。
- `--output <path>`
  输出到文件（不指定则输出到 stdout）。
- `--max-rows <N>`
  每个表最多输出 N 行，`0` 表示不限制（默认）。
- `--max-depth <N>`
  限制分析树深度，`0` 表示不限制（默认）。
- `--root-path <path>`
  只导出匹配路径的分析子树，例如 `File/Mach Header (x86_64)`。
- `--name-filter <text>`
  仅保留名称匹配指定文本的节点。
- `--table-mode full|headers|summary`
  控制表格导出粒度：完整行、仅表头、或仅行数摘要。默认 `full`。
- `--include-empty`
  包含无表格/无二进制载荷的空节点。
- `-h` / `--help`
  显示帮助信息。

参数可以写成 `--name value` 或 `--name=value`，可以放在文件之前或之后。

### 输出行为

- 默认输出到 `stdout`。
- 参数错误或分析失败输出到 `stderr`。
- JSON 输出为可读缩进格式。
- JSON 顶层包含 `schemaVersion`、`generator`、`format`、`file`、`options`、`summary` 和 `analysis`。
- 节点包含 `name`、`path`、`depth`、`kind`、`childIndex`、`children`，以及存在时的 `table` 和/或 `binary`。表格行包含 `rowIndex`、`cells`（按表头）与 `values`（按位置）。
- 所有字符串都会被净化为合法 UTF-8。
- 输出先缓冲：分析失败时不会写出任何内容。
- 时间戳按本地时区格式化。设置 `MOEX_TZ=UTC` 可得到可复现的输出。

### 退出码

- `0`：执行成功
- `1`：分析或运行失败（例如解析失败、无法写输出文件）
- `2`：命令行参数错误

### 导出范围

`moex dump` 会递归遍历完整分析树，导出桌面应用中显示的所有分析节点。例如：

- 文件类型总览（Mach-O / Fat / Archive / dyld shared cache）
- Mach Header、Load Commands
- Sections 及派生视图（含反汇编）
- Symbol/String 相关视图
- Dynamic Loader Info（含 dyld exports trie 与 chained fixups 视图）
- Objective-C 与 Swift 相关视图
- 代码签名、Integrity Report、Xref Report
- dyld shared cache 顶层视图（mappings/images）

GUI 专属交互行为（筛选、复制、CSV 导出）不属于导出内容，但其底层分析数据会导出。

### 示例

#### 终端文本输出

```bash
moex dump sample/simple
```

#### 终端 JSON 输出

```bash
moex dump --format json sample/simple
```

#### 写入 JSON 文件

```bash
moex dump --format json --output simple-analysis.json sample/simple
```

#### 大文件限制输出量

```bash
moex dump --max-rows 100 --max-depth 4 sample/complex
```

#### 包含空节点（便于结构遍历）

```bash
moex dump --format json --include-empty sample/simple
```

#### 仅导出某个子树

```bash
moex dump --format json --root-path "File/Mach Header (x86_64)" sample/simple
```

#### 仅关注指定节点并输出表格摘要

```bash
moex dump --format json --name-filter Xref --table-mode summary sample/simple
```

#### 与 jq 联用

```bash
moex dump --format json sample/simple | jq '.analysis.name'
```

## `moex parse`

```bash
moex parse <file> [file...]
```

用途：

- 快速验证解析可用性
- 回归脚本依赖该命令

每个文件在 stdout 输出一行 `[ok] <file> headers=<N>`，失败时在 stderr 输出
`[fail] <file> error=<message>`。只要有文件失败，退出码即为 `1`。

## `moex diff`

```bash
moex diff <fileA> <fileB>
```

用途：

- 对比首个 Mach-O Header 关键信息（架构、load command 数量与大小）
- 对比 section/symbol 集合差异（仅 A、仅 B、共有）

退出码：`0` 成功；`1` 文件无法解析或不含 Mach-O header；`2` 参数个数错误。

## `moex cache-list`

```bash
moex cache-list [--json] [--exact] [--limit=N] [--output=file] <dyld_shared_cache_file> [path-filter]
```

- `--json`：输出 JSON
- `--exact`：路径精确匹配（默认子串匹配）
- `--limit=N`：匹配 N 个后停止（`0` 表示不限制）
- `--output=file`：输出到文件而不是 stdout

用途：

- 列出 dyld shared cache 中的镜像
- 支持精确/子串过滤

选项必须放在 cache 路径之前，并使用 `--key=value` 形式。
退出码：`0` 成功；`1` 输入不是 dyld shared cache 或无法打开输出文件；`2` 用法错误。

## `moex cache-extract`

```bash
moex cache-extract [--compact] [--all] [--exact] [--dry-run] [--json] [--max=N] <dyld_shared_cache_file> <image-path-or-substr> <output-macho-or-dir>
```

- `--compact`：重写 segment file offset，输出紧凑文件
- `--all`：把所有匹配的镜像提取到输出目录
- `--exact`：路径精确匹配（默认子串匹配）
- `--dry-run`：只打印提取计划，不写文件
- `--json`：输出机器可读的 JSON 行
- `--max=N`：`--all` 模式下最多处理的镜像数（`0` 表示不限制）

用途：

- 从 dyld shared cache 提取单个或多个镜像
- 可选 compact 模式重写 segment file offset

选项必须放在 cache 路径之前。不带 `--all` 时最后一个参数是输出文件；带 `--all` 时是目录，
每个镜像写为 `<镜像文件名>.macho`。退出码：`0` 成功；`1` 没有匹配的镜像或提取失败
（`--all` 模式下其余镜像仍会继续处理）；`2` 用法错误。

分片 cache 的镜像位于子 cache 文件中（`<cache>.01`、`<cache>.25.dylddata` 等）。
传入主 cache 文件即可：提取器会从同一目录读取其头部列出的子 cache 文件，
并从实际存放各 segment 的文件中复制数据。缺失或属于其他 cache（UUID 不同）的
子 cache 文件会被跳过，依赖它的镜像以退出码 `1` 失败。分片 cache 建议使用 `--compact`：
否则每个 segment 保留它在各自子 cache 文件中的文件偏移，来自不同文件的 segment
在输出中可能重叠。

## 自动化示例

### CLI 冒烟测试

```bash
tests/regression/run_cli_smoke.sh
```

### 全量回归

```bash
tests/regression/run_all.sh
```

两者都使用 `target/release/moex`；设置 `MOEX_BIN` 可测试其他二进制。

### 批量分析示例

```bash
for f in sample/simple sample/complex; do
  moex dump --format json --output "$(basename "$f").json" "$f"
done
```

## 构建提示

```bash
cargo build --release -p moex-cli
```

## 常见问题

- 报错：`the following required arguments were not provided: <FILE>` 或 `unexpected argument '...' found`
  原因：`moex dump` 需要且只接受一个输入文件。
- 报错：`invalid value '...' for '--format <FORMAT>'`
  原因：当前仅支持 `text` 和 `json`。
- 报错：`analysis failed: ...`
  原因：文件解析失败或输入样本异常。目录（包括 `.app` 包）会被拒绝，请传入包内的可执行文件。
- 报错：`cannot open output file: ...`
  原因：输出路径不可写或目录不存在。
- 报错：`input is not a dyld shared cache file`
  原因：传给 `cache-list` / `cache-extract` 的文件可以解析，但不是 dyld shared cache。
