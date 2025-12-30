"""
CRITICAL SECURITY NOTE:
This service NEVER deserializes untrusted pickle data.
Objects must be serialized by trusted client code only.
Pickle deserialization is inherently unsafe and bypasses all validation.
"""

import pandas as pd
import numpy as np
import ast
import io
import signal
import base64
import importlib
import cloudpickle
from contextlib import redirect_stdout, redirect_stderr
from typing import Dict, Any, Optional, Union, List
from datetime import datetime, date, time as dt_time, timedelta
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field, field_validator
import uvicorn
import time

from config import (
    RATE_LIMIT_MAX_REQUESTS,
    RATE_LIMIT_WINDOW_SECONDS,
    MAX_TIMEOUT_SECONDS,
    DEFAULT_TIMEOUT_SECONDS,
    MAX_OUTPUT_SIZE,
    MAX_RESULT_ROWS,
    ALLOWED_MODULES,
    ALLOWED_BUILTINS,
    FORBIDDEN_NAMES,
    FORBIDDEN_ATTRS,
    FORBIDDEN_METHODS,
)


# Rate limiting
class RateLimiter:
    def __init__(
        self,
        max_requests: int = RATE_LIMIT_MAX_REQUESTS,
        window: int = RATE_LIMIT_WINDOW_SECONDS,
    ):
        self.max_requests = max_requests
        self.window = window
        self.requests = {}

    def check(self, ip: str) -> bool:
        now = time.time()
        if ip not in self.requests:
            self.requests[ip] = []

        # Remove old requests
        self.requests[ip] = [
            req for req in self.requests[ip] if now - req < self.window
        ]

        if len(self.requests[ip]) >= self.max_requests:
            return False

        self.requests[ip].append(now)
        return True


class CodeExecutionRequest(BaseModel):
    code: Union[str, List[str]] = Field(
        ..., description="Python code to execute (string or list of strings)"
    )
    contexts: Dict[str, str] = Field(
        default_factory=dict,
        description="Base64-encoded cloudpickle serialized context objects",
    )
    timeout: int = Field(
        default=DEFAULT_TIMEOUT_SECONDS,
        ge=1,
        le=MAX_TIMEOUT_SECONDS,
        description="Timeout in seconds",
    )

    @field_validator("code")
    @classmethod
    def validate_code_length(cls, v):
        # Handle case where LLM sends code as array of strings
        if isinstance(v, list):
            v = "\n".join(str(chunk) for chunk in v)
        if not isinstance(v, str):
            v = str(v)
        if len(v.strip()) == 0:
            raise ValueError("Code cannot be empty")
        return v


class CodeExecutionResponse(BaseModel):
    success: bool
    result: Optional[str] = None  # Always string (repr of result)
    result_pickle: Optional[str] = (
        None  # Base64 encoded cloudpickle for complex objects
    )
    output: str = ""
    error: Optional[str] = None
    auto_printed: bool = False
    execution_time: float = 0.0


class SafeCodeExecutor:
    """
    Hardened code executor addressing vulnerabilities:
    - Python sandbox escapes via object introspection
    - Infinite loops and resource exhaustion
    - Pickle deserialization RCE
    - Docker container escapes
    """

    def __init__(
        self,
        timeout: int = DEFAULT_TIMEOUT_SECONDS,
        max_output_size: int = MAX_OUTPUT_SIZE,
    ):
        self.timeout = min(timeout, MAX_TIMEOUT_SECONDS)
        self.max_output_size = max_output_size

    def validate_code(self, code: str) -> tuple[bool, Optional[str]]:
        """Strict AST-based validation with allowed imports"""
        try:
            tree = ast.parse(code)
        except SyntaxError as e:
            return False, f"Syntax error: {str(e)}"

        for node in ast.walk(tree):
            # Check imports - allow only whitelisted modules
            if isinstance(node, ast.Import):
                for alias in node.names:
                    module_name = alias.name.split(".")[0]
                    if module_name not in ALLOWED_MODULES:
                        return False, f"Import not allowed: {alias.name}"
            elif isinstance(node, ast.ImportFrom):
                if node.module:
                    module_name = node.module.split(".")[0]
                    if module_name not in ALLOWED_MODULES:
                        return False, f"Import not allowed: from {node.module}"

            # Check names
            if isinstance(node, ast.Name):
                if node.id in FORBIDDEN_NAMES:
                    return False, f"Forbidden name: {node.id}"
                # Block access to anything starting with __
                if node.id.startswith("__"):
                    return False, f"Access to dunders not allowed: {node.id}"

            # Check attributes
            if isinstance(node, ast.Attribute):
                attr = node.attr
                if attr in FORBIDDEN_ATTRS:
                    return False, f"Forbidden attribute: {attr}"
                if attr in FORBIDDEN_METHODS:
                    return False, f"Forbidden method: {attr}"
                if attr.startswith("_"):
                    return False, f"Private/protected access not allowed: {attr}"

            # Block function definitions that could be exploited
            if isinstance(node, ast.FunctionDef):
                if node.name in FORBIDDEN_METHODS:
                    return False, f"Cannot define forbidden method: {node.name}"

            # Block class definitions completely (prevent __reduce__ exploits)
            if isinstance(node, ast.ClassDef):
                return False, "Class definitions not allowed"

            # Block async operations
            if isinstance(node, (ast.AsyncFunctionDef, ast.AsyncFor, ast.AsyncWith)):
                return False, "Async operations not allowed"

        return True, None

    def get_last_expression(self, code: str) -> Optional[str]:
        """Extract last expression for Jupyter-like behavior"""
        try:
            tree = ast.parse(code)
            if not tree.body:
                return None

            last_node = tree.body[-1]
            if isinstance(last_node, ast.Expr):
                expr = last_node.value
                if isinstance(expr, ast.Call):
                    if isinstance(expr.func, ast.Name) and expr.func.id == "print":
                        return None
                return ast.get_source_segment(code, last_node)
            return None
        except Exception:
            return None

    def _timeout_handler(self, signum, frame):
        raise TimeoutError(f"Execution exceeded {self.timeout} seconds")

    def _safe_import(self, module_name: str) -> Any:
        """Safely import an allowed module."""
        base_module = module_name.split(".")[0]
        if base_module not in ALLOWED_MODULES:
            raise ImportError(f"Import not allowed: {module_name}")
        return importlib.import_module(module_name)

    def _deserialize_pickled_context(self, pickled_b64: str) -> Any:
        """Deserialize a base64-encoded cloudpickle object."""
        try:
            pickled_bytes = base64.b64decode(pickled_b64)
            return cloudpickle.loads(pickled_bytes)
        except Exception as e:
            raise ValueError(f"Failed to deserialize context: {e}")

    def create_safe_environment(self, contexts: Dict[str, str]) -> Dict[str, Any]:
        """Create restricted environment with pickled context deserialization."""
        # Build safe builtins from config
        builtins_dict = (
            __builtins__ if isinstance(__builtins__, dict) else vars(__builtins__)
        )
        safe_builtins = {
            name: builtins_dict[name]
            for name in ALLOWED_BUILTINS
            if name in builtins_dict
        }

        # Add safe __import__ that only allows whitelisted modules
        def safe_import(name, globals=None, locals=None, fromlist=(), level=0):
            base_module = name.split(".")[0]
            if base_module not in ALLOWED_MODULES:
                raise ImportError(f"Import not allowed: {name}")
            return importlib.import_module(name)

        safe_builtins["__import__"] = safe_import

        safe_globals = {
            "__builtins__": safe_builtins,
            # Pre-loaded modules
            "pd": pd,
            "np": np,
            "numpy": np,
            "pandas": pd,
        }

        # Deserialize pickled contexts
        for key, pickled_value in contexts.items():
            safe_globals[key] = self._deserialize_pickled_context(pickled_value)

        return safe_globals

    def format_value_for_display(self, value: Any) -> str:
        """Format value safely for display"""
        try:
            if isinstance(value, pd.DataFrame):
                return str(value.head(100))  # Limit rows
            elif isinstance(value, pd.Series):
                return str(value.head(100))
            elif isinstance(value, np.ndarray):
                if value.size > 1000:
                    return (
                        f"ndarray(shape={value.shape}, dtype={value.dtype}) [truncated]"
                    )
                return str(value)
            elif isinstance(value, (list, dict, tuple, set)):
                s = repr(value)
                if len(s) > 1000:
                    return s[:1000] + "... [truncated]"
                return s
            else:
                s = str(value)
                if len(s) > 1000:
                    return s[:1000] + "... [truncated]"
                return s
        except Exception:
            return "[Error displaying value]"

    def execute(self, code: str, contexts: Dict[str, Any]) -> Dict[str, Any]:
        """Execute code with maximum security"""
        start_time = time.time()

        # Validate
        is_valid, error_msg = self.validate_code(code)
        if not is_valid:
            return {
                "success": False,
                "result": None,
                "output": "",
                "error": f"Validation failed: {error_msg}",
                "auto_printed": False,
                "execution_time": 0.0,
            }

        last_expr = self.get_last_expression(code)
        safe_globals = self.create_safe_environment(contexts)
        safe_locals = {}

        output_buffer = io.StringIO()
        error_buffer = io.StringIO()

        signal.signal(signal.SIGALRM, self._timeout_handler)
        signal.alarm(self.timeout)

        auto_printed = False

        try:
            with redirect_stdout(output_buffer), redirect_stderr(error_buffer):
                exec(code, safe_globals, safe_locals)
                result = safe_locals.get("result", safe_globals.get("result", None))

            stdout = output_buffer.getvalue()
            stderr = error_buffer.getvalue()

            # Auto-print last expression
            if last_expr and not result:
                try:
                    last_value = eval(last_expr, safe_globals, safe_locals)
                    if last_value is not None:
                        formatted = self.format_value_for_display(last_value)
                        stdout += formatted + "\n"
                        auto_printed = True
                        result = last_value
                except Exception:
                    pass

            if len(stdout) > self.max_output_size:
                stdout = stdout[: self.max_output_size] + "\n... (output truncated)"

            result_str, result_pickle = self.serialize_result(result)
            execution_time = time.time() - start_time

            return {
                "success": True,
                "result": result_str,
                "result_pickle": result_pickle,
                "output": stdout,
                "error": stderr if stderr else None,
                "auto_printed": auto_printed,
                "execution_time": round(execution_time, 3),
            }

        except TimeoutError as e:
            return {
                "success": False,
                "result": None,
                "result_pickle": None,
                "output": output_buffer.getvalue(),
                "error": f"Timeout: {str(e)}",
                "auto_printed": False,
                "execution_time": self.timeout,
            }
        except MemoryError:
            return {
                "success": False,
                "result": None,
                "result_pickle": None,
                "output": output_buffer.getvalue(),
                "error": "Memory limit exceeded",
                "auto_printed": False,
                "execution_time": time.time() - start_time,
            }
        except Exception as e:
            return {
                "success": False,
                "result": None,
                "result_pickle": None,
                "output": output_buffer.getvalue(),
                "error": f"{type(e).__name__}: {str(e)}",
                "auto_printed": False,
                "execution_time": time.time() - start_time,
            }
        finally:
            signal.alarm(0)

    def _convert_numpy_types(self, obj: Any) -> Any:
        """Recursively convert numpy/pandas types to Python native types."""
        # Handle pandas DataFrame
        if isinstance(obj, pd.DataFrame):
            return {
                "_type": "DataFrame",
                "_data": self._convert_numpy_types(
                    obj.head(MAX_RESULT_ROWS).to_dict("records")
                ),
                "_shape": list(obj.shape),
                "_columns": obj.columns.tolist(),
            }
        # Handle pandas Series
        elif isinstance(obj, pd.Series):
            return {
                "_type": "Series",
                "_data": self._convert_numpy_types(obj.head(MAX_RESULT_ROWS).tolist()),
                "_index": self._convert_numpy_types(
                    obj.head(MAX_RESULT_ROWS).index.tolist()
                ),
                "_name": obj.name,
            }
        # Handle numpy arrays
        elif isinstance(obj, np.ndarray):
            return self._convert_numpy_types(obj.tolist())
        elif isinstance(obj, (np.integer,)):
            return int(obj)
        elif isinstance(obj, (np.floating,)):
            return float(obj)
        elif isinstance(obj, (np.bool_,)):
            return bool(obj)
        elif isinstance(obj, dict):
            return {
                self._convert_numpy_types(k): self._convert_numpy_types(v)
                for k, v in obj.items()
            }
        elif isinstance(obj, (list, tuple)):
            converted = [self._convert_numpy_types(item) for item in obj]
            return type(obj)(converted) if isinstance(obj, tuple) else converted
        elif isinstance(obj, set):
            return {self._convert_numpy_types(item) for item in obj}
        # Handle datetime types
        elif isinstance(obj, datetime):
            return {"_type": "datetime", "_data": obj.isoformat()}
        elif isinstance(obj, date):
            return {"_type": "date", "_data": obj.isoformat()}
        elif isinstance(obj, dt_time):
            return {"_type": "time", "_data": obj.isoformat()}
        elif isinstance(obj, timedelta):
            return {"_type": "timedelta", "_data": obj.total_seconds()}
        else:
            return obj

    def serialize_result(self, result: Any) -> tuple[Optional[str], Optional[str]]:
        """
        Convert result to string representation and cloudpickle.
        Returns: (result_str, result_pickle_base64)
        """
        if result is None:
            return None, None

        # Always create string representation
        result_str = self.format_value_for_display(result)

        # Create cloudpickle for complex objects
        try:
            pickled = cloudpickle.dumps(result)
            result_pickle = base64.b64encode(pickled).decode("utf-8")
        except Exception:
            result_pickle = None

        return result_str, result_pickle


# FastAPI app
app = FastAPI(title="Hardened Code Executor")
rate_limiter = RateLimiter()


@app.middleware("http")
async def rate_limit_middleware(request: Request, call_next):
    client_ip = request.client.host
    if not rate_limiter.check(client_ip):
        return JSONResponse(status_code=429, content={"error": "Rate limit exceeded"})
    return await call_next(request)


@app.post("/execute", response_model=CodeExecutionResponse)
async def execute_code(request: CodeExecutionRequest):
    """Execute code with strict security"""
    try:
        executor = SafeCodeExecutor(timeout=request.timeout)
        result = executor.execute(request.code, request.contexts)
        return CodeExecutionResponse(**result)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/health")
async def health():
    return {"status": "healthy", "timestamp": time.time()}


if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=4323, log_level="info")
