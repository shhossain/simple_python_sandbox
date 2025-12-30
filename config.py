"""
Configuration for the Safe Code Executor service.
Values can be overridden via environment variables.
"""

import os
from typing import Set


def get_env_set(key: str, default: Set[str]) -> Set[str]:
    """Get a set from comma-separated env var or return default."""
    value = os.getenv(key)
    if value:
        return {item.strip() for item in value.split(",") if item.strip()}
    return default


def get_env_int(key: str, default: int) -> int:
    """Get int from env var or return default."""
    value = os.getenv(key)
    if value:
        try:
            return int(value)
        except ValueError:
            return default
    return default


def get_env_float(key: str, default: float) -> float:
    """Get float from env var or return default."""
    value = os.getenv(key)
    if value:
        try:
            return float(value)
        except ValueError:
            return default
    return default


# =============================================================================
# Rate Limiting Configuration
# =============================================================================
RATE_LIMIT_MAX_REQUESTS = get_env_int("RATE_LIMIT_MAX_REQUESTS", 20)
RATE_LIMIT_WINDOW_SECONDS = get_env_int("RATE_LIMIT_WINDOW_SECONDS", 60)

# =============================================================================
# Execution Limits
# =============================================================================
MAX_TIMEOUT_SECONDS = get_env_int("MAX_TIMEOUT_SECONDS", 10)
DEFAULT_TIMEOUT_SECONDS = get_env_int("DEFAULT_TIMEOUT_SECONDS", 5)
MAX_OUTPUT_SIZE = get_env_int("MAX_OUTPUT_SIZE", 10000)
MAX_CODE_LENGTH = get_env_int("MAX_CODE_LENGTH", 50000)
MAX_RESULT_ROWS = get_env_int("MAX_RESULT_ROWS", 1000)
MAX_ARRAY_SIZE = get_env_int("MAX_ARRAY_SIZE", 10000)

# =============================================================================
# Allowed Modules for Import
# Safe modules that don't allow file/network/system access
# =============================================================================
ALLOWED_MODULES: Set[str] = get_env_set(
    "ALLOWED_MODULES",
    {
        # Math and statistics
        "math",
        "statistics",
        "decimal",
        "fractions",
        # Data structures
        "collections",
        "itertools",
        "functools",
        "operator",
        # String and regex
        "re",
        "string",
        # Date and time
        "datetime",
        "time",
        "calendar",
        # JSON (safe serialization)
        "json",
        # Typing
        "typing",
        # Random (deterministic if seeded)
        "random",
        # Data processing (already in globals)
        "numpy",
        "pandas",
    },
)

# =============================================================================
# Allowed Builtins
# Safe built-in functions
# =============================================================================
ALLOWED_BUILTINS: Set[str] = get_env_set(
    "ALLOWED_BUILTINS",
    {
        # Type conversions
        "abs",
        "bool",
        "float",
        "int",
        "str",
        # Collections
        "dict",
        "list",
        "set",
        "tuple",
        "frozenset",
        # Iteration
        "enumerate",
        "range",
        "zip",
        "map",
        "filter",
        "reversed",
        "iter",
        "next",
        # Aggregation
        "all",
        "any",
        "len",
        "max",
        "min",
        "sum",
        "sorted",
        # Math
        "round",
        "pow",
        "divmod",
        # Object/type checking
        "isinstance",
        "issubclass",
        "type",
        "callable",
        "hasattr",
        "getattr",
        # String
        "repr",
        "ascii",
        "chr",
        "ord",
        "format",
        # Other safe operations
        "hash",
        "id",
        "slice",
        "print",
    },
)

# =============================================================================
# Forbidden Names (blacklist)
# =============================================================================
FORBIDDEN_NAMES: Set[str] = get_env_set(
    "FORBIDDEN_NAMES",
    {
        # Code execution
        "eval",
        "exec",
        "compile",
        "__import__",
        "breakpoint",
        # File I/O
        "open",
        "file",
        "input",
        "raw_input",
        # System
        "exit",
        "quit",
        "help",
        "copyright",
        "credits",
        "license",
        # Introspection that can be abused
        "globals",
        "locals",
        "vars",
        "dir",
        # Built-in access
        "__builtins__",
        "__loader__",
        "__spec__",
        # Memory/object manipulation
        "memoryview",
        "bytearray",
        # Dangerous
        "delattr",
        "setattr",
    },
)

# =============================================================================
# Forbidden Attributes (cannot access these on any object)
# =============================================================================
FORBIDDEN_ATTRS: Set[str] = get_env_set(
    "FORBIDDEN_ATTRS",
    {
        "__class__",
        "__bases__",
        "__subclasses__",
        "__code__",
        "__globals__",
        "__dict__",
        "__module__",
        "__import__",
        "__builtins__",
        "__loader__",
        "__spec__",
        "__name__",
        "__qualname__",
        "__self__",
        "__func__",
        "__closure__",
        "func_globals",
        "func_code",
        "gi_frame",
        "gi_code",
    },
)

# =============================================================================
# Forbidden Methods
# =============================================================================
FORBIDDEN_METHODS: Set[str] = get_env_set(
    "FORBIDDEN_METHODS",
    {
        "__reduce__",
        "__reduce_ex__",
        "__setstate__",
        "__getattribute__",
        "__getattr__",
        "__setattr__",
        "__delattr__",
        "__call__",
    },
)
