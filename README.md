# KVFI

```text
source/                     Tool source code and configuration templates
source/ground_truth.json    Key-value source annotations for 69 devices
firmware/                   Firmware files organized by vendor and device
```

## Usage

### 1. Set up the environment

Install Python 3.10 or later and IDA Pro with IDAPython and decompiler support for the target architectures. Firmware extraction may require tools such as Binwalk and SquashFS utilities.

From the release directory, run:

```bash
cd source
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
python -m pip install esprima
```

### 2. Configure paths and the model

Edit `source/settings.toml` and replace the following paths with absolute paths on your machine:

```toml
ida_path = "/absolute/path/to/ida/idat"
script_path = "/absolute/path/to/KVFI-release-materials/source"
result_path = "/absolute/path/to/KVFI-release-materials/source/res"
```

Create a `.env` file in `source/` to configure a model service that supports the Anthropic Messages API:

```dotenv
ANTHROPIC_API_KEY=your_api_key
ANTHROPIC_BASE_URL=https://your-provider.example
ANTHROPIC_MODEL=your_model_name
```

Omit `ANTHROPIC_BASE_URL` when using the default Anthropic service. This entry point requires the Anthropic Messages API; a service that only supports the OpenAI-compatible API cannot be used directly.

### 3. Extract and analyze firmware

Extract the firmware from `firmware/<vendor>/<device>/` into a complete filesystem directory, such as `/absolute/path/to/squashfs-root`. The analyzer accepts an extracted filesystem directory or an ELF binary, rather than a firmware update image.

Run the complete analysis from `source/`. The `--device` argument specifies the name of the output directory for this run:

```bash
python run_unified.py \
  --rootfs /absolute/path/to/squashfs-root \
  --device example_device \
  --with-agent
```

This command runs structural analysis, candidate construction, and model-based semantic analysis. Model calls incur API charges. The main outputs are written to `result_path/example_device/`:

- `deepin_result_path.json`: merged source-identification results.
- `agent_possible.json`: key-value sources identified through semantic analysis.
- `recv_param_result.json`: structural analysis results.

To run structural analysis only, omit `--with-agent`:

```bash
python run_unified.py \
  --rootfs /absolute/path/to/squashfs-root \
  --device example_structural
```

To perform semantic analysis on a known candidate function:

```bash
python agent_analyze.py \
  --binary /absolute/path/to/httpd \
  --funcs sub_A26C \
  --out ./example_sources.json
```

Use the function name shown by IDA for the corresponding binary. This command checks only the specified candidate.
