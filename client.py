"""
Safe Code Executor Client

Simple client that pickles contexts and sends to executor.
Results are returned as strings (with optional cloudpickle deserialization).
"""

import requests
import base64
import cloudpickle
from typing import Dict, Any


class DockerCodeExecutor:
    """
    Client for hardened code executor.

    Contexts are serialized via cloudpickle.
    Results are returned as strings by default.
    Use `deserialize_result=True` to get Python objects via cloudpickle.
    """

    def __init__(self, service_url: str = "http://localhost:4323"):
        self.service_url = service_url
        self._check_service()

    def _check_service(self):
        try:
            response = requests.get(f"{self.service_url}/health", timeout=5)
            response.raise_for_status()
        except Exception as e:
            raise ConnectionError(f"Service unavailable: {e}")

    def _serialize_context(self, obj: Any) -> str:
        """Serialize object using cloudpickle and base64 encode."""
        pickled = cloudpickle.dumps(obj)
        return base64.b64encode(pickled).decode("utf-8")

    def execute(
        self, code: str, timeout: int = 5, deserialize_result: bool = False, **contexts
    ) -> Dict[str, Any]:
        """
        Execute code with contexts.

        Args:
            code: Python code to execute
            timeout: Max execution time in seconds
            deserialize_result: If True, deserialize result via cloudpickle
            **contexts: Variables to inject (DataFrames, arrays, dicts, etc.)

        Returns:
            dict with keys:
                - success: bool
                - result: str (string representation) or deserialized object
                - output: str (stdout)
                - error: str or None
                - execution_time: float

        Example:
            result = executor.execute(
                "result = df['sales'].sum()",
                df=my_dataframe,
            )
            print(result['result'])  # "450" (string)
        """
        # Pickle all contexts
        pickled_contexts = {
            name: self._serialize_context(obj) for name, obj in contexts.items()
        }

        payload = {
            "code": code,
            "contexts": pickled_contexts,
            "timeout": timeout,
        }

        try:
            response = requests.post(
                f"{self.service_url}/execute",
                json=payload,
                timeout=timeout + 5,
            )
            response.raise_for_status()
            result = response.json()

            # Optionally deserialize via cloudpickle
            if deserialize_result and result.get("result_pickle"):
                try:
                    pickled_bytes = base64.b64decode(result["result_pickle"])
                    result["result"] = cloudpickle.loads(pickled_bytes)
                except Exception:
                    pass  # Fall back to string result

            return result

        except requests.exceptions.Timeout:
            return {
                "success": False,
                "error": "Request timeout",
                "output": "",
                "result": None,
            }
        except Exception as e:
            return {
                "success": False,
                "error": f"Request failed: {str(e)}",
                "output": "",
                "result": None,
            }
