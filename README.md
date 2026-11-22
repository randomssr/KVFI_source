# KVFI 发布材料

```
source/                      KVFI 工具源码及配置模板
source/ground_truth.json     69 个设备的 key-value source 标注
firmware/                    69 个设备的原始固件镜像目录（按厂商/型号）

```

## 使用说明

### 1. 安装环境

需要 Python 3.10 或更高版本，以及带有对应架构反编译器和 IDAPython 的 IDA Pro。固件解包可使用 Binwalk、SquashFS 等工具。

在发布材料目录中执行：

```bash
cd source
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
python -m pip install esprima
```

### 2. 配置路径和模型

修改 `source/settings.toml`，将以下路径替换为本机的实际绝对路径：

```toml
ida_path = "/absolute/path/to/ida/idat"
script_path = "/absolute/path/to/KVFI-release-materials/source"
result_path = "/absolute/path/to/KVFI-release-materials/source/res"
```

在 `source/` 目录创建 `.env`，为语义分析配置支持 Anthropic Messages API 的模型服务：

```dotenv
ANTHROPIC_API_KEY=your_api_key
ANTHROPIC_BASE_URL=https://your-provider.example
ANTHROPIC_MODEL=your_model_name
```

使用默认 Anthropic 服务时，可省略 `ANTHROPIC_BASE_URL`。模型服务必须支持该 API 协议；只有 OpenAI-compatible 接口的服务不能直接使用这条入口。

### 3. 解包并分析固件

先将 `firmware/厂商/型号/` 下的固件解包，得到完整文件系统目录，例如 `/absolute/path/to/squashfs-root`。分析程序接收解包目录或 ELF 二进制，不直接接收刷机镜像。

从 `source/` 目录运行完整分析，`--device` 用于指定本次结果目录名称：

```bash
python run_unified.py \
  --rootfs /absolute/path/to/squashfs-root \
  --device example_device \
  --with-agent
```

这条命令执行结构分析、候选构建和模型语义分析。模型调用会产生 API 费用。运行结束后，主要输出位于配置的 `result_path/example_device/`：

- `deepin_result_path.json`：合并后的 source 结果。
- `agent_possible.json`：语义分析识别的 key-value sources。
- `recv_param_result.json`：结构分析结果。

仅运行结构分析时，省略 `--with-agent`：

```bash
python run_unified.py \
  --rootfs /absolute/path/to/squashfs-root \
  --device example_structural
```

也可以对已知候选函数单独进行语义分析：

```bash
python agent_analyze.py \
  --binary /absolute/path/to/httpd \
  --funcs sub_A26C \
  --out ./example_sources.json
```

其中函数名应与对应二进制在 IDA 中的名称一致；该命令只检查指定候选。




