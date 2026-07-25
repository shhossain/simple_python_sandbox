# Safe Code Executor

Sandboxed Python code execution service. Run untrusted-ish Python (AST-validated, restricted builtins/imports) inside hardened Docker container, call it over HTTP.

## What it does

- FastAPI service (`executor_service.py`) executes Python code in restricted `exec` environment
- AST validation blocks dunders, class defs, forbidden names/attrs/methods, disallowed imports
- Per-request timeout via `SIGALRM`
- Contexts (DataFrames, arrays, etc) passed in via cloudpickle, base64-encoded — client-serialized only, never untrusted pickle
- Result returned as string repr + optional cloudpickle for deserialization
- Docker hardening: read-only rootfs, dropped caps, seccomp profile, resource limits, non-root user

## Quick start

```bash
docker compose up -d --build
```

Service listens on `http://localhost:4323`.

Check health:
```bash
curl http://localhost:4323/health
```

## Usage (Python client)

```python
from client import DockerCodeExecutor
import pandas as pd

executor = DockerCodeExecutor(service_url="http://localhost:4323")

df = pd.DataFrame({"sales": [100, 200, 150]})

result = executor.execute(
    "result = df['sales'].sum()",
    df=df,
    timeout=5,
)

print(result["result"])       # "450" (string)
print(result["output"])       # captured stdout
print(result["success"])      # True/False
```

Pass `deserialize_result=True` to get a real Python object back instead of string repr:

```python
result = executor.execute("result = df.describe()", df=df, deserialize_result=True)
print(result["result"])  # DataFrame object
```

`execute()` accepts arbitrary `**contexts` kwargs — any cloudpickle-serializable object (DataFrame, ndarray, dict, list, ...) gets injected into the sandbox under that name.

## Raw HTTP API

`POST /execute`

```json
{
  "code": "result = 1 + 1",
  "contexts": {"x": "<base64 cloudpickle>"},
  "timeout": 5
}
```

Response:
```json
{
  "success": true,
  "result": "2",
  "result_pickle": "<base64 cloudpickle or null>",
  "output": "",
  "error": null,
  "auto_printed": false,
  "execution_time": 0.001
}
```

`GET /health` → `{"status": "healthy", "timestamp": ...}`

## What's allowed in sandboxed code

- Modules: `math`, `statistics`, `decimal`, `fractions`, `collections`, `itertools`, `functools`, `operator`, `re`, `string`, `datetime`, `time`, `calendar`, `json`, `typing`, `random`, `numpy`/`pandas` (pre-loaded as `np`/`pd`)
- Builtins: common type conversions, collections, iteration, aggregation, math, string ops — see `config.py: ALLOWED_BUILTINS`
- Blocked: `eval`, `exec`, `open`, `__import__` overrides, dunder access, class definitions, `globals`/`locals`/`vars`/`dir`, private/protected attribute access (`_foo`)

Set `result = <value>` in your code to return it, or just end with an expression (Jupyter-style auto-print).

## Configuration

All via env vars, see `config.py` for defaults:

| Var | Default | Purpose |
|---|---|---|
| `RATE_LIMIT_MAX_REQUESTS` | 20 | Requests per window per IP |
| `RATE_LIMIT_WINDOW_SECONDS` | 60 | Rate limit window |
| `MAX_TIMEOUT_SECONDS` | 10 | Hard cap on requested timeout |
| `DEFAULT_TIMEOUT_SECONDS` | 5 | Default if not specified |
| `MAX_OUTPUT_SIZE` | 10000 | Max stdout chars before truncation |
| `MAX_CODE_LENGTH` | 50000 | Max code string length |
| `MAX_RESULT_ROWS` | 1000 | Max DataFrame/Series rows serialized |
| `MAX_ARRAY_SIZE` | 10000 | Max ndarray size before truncation |
| `ALLOWED_MODULES` | see above | Comma-separated whitelist |
| `ALLOWED_BUILTINS` | see above | Comma-separated whitelist |
| `FORBIDDEN_NAMES` | see above | Comma-separated blacklist |

## Security notes

- Contexts must be serialized by trusted client code only — service never deserializes untrusted pickle data from outside its own client
- AST validation is defense-in-depth, not a full sandbox by itself — Docker isolation (seccomp, dropped caps, read-only fs, resource limits) is the real boundary
- Don't expose port 4323 directly to untrusted networks without additional auth in front

## Requirements

Python 3.12+, deps in `pyproject.toml` (managed via `uv`).
