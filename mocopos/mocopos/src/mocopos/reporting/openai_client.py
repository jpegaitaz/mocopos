import os
import time
from typing import Dict, Any, Optional
from openai import OpenAI
from httpx import HTTPError

_DEFAULT_MODEL = os.getenv("OPENAI_MODEL", "gpt-4o")
_MAX_RETRIES = int(os.getenv("OPENAI_MAX_RETRIES", "5"))

_client: Optional[OpenAI] = None

def get_client() -> OpenAI:
    global _client
    if _client is None:
        # Uses OPENAI_API_KEY from the environment
        _client = OpenAI()
    return _client

def _prune_none(d: Dict[str, Any]) -> Dict[str, Any]:
    return {k: v for k, v in d.items() if v is not None}

def call_openai_responses(
    model: str,
    instructions: str,
    input_obj: Any,
    *,
    response_format: Optional[Dict[str, Any]] = None,
    temperature: float = 0.2,
    seed: Optional[int] = None,
    max_output_tokens: Optional[int] = None,
) -> str:
    """
    Wraps Responses API with retries and compatibility fallbacks.
    Some SDK versions don't support 'seed' or use 'max_tokens' instead of 'max_output_tokens'.
    We try the most modern signature first, then progressively fall back.
    """
    client = get_client()
    delay = 1.0

    # Build the most up-to-date parameter set
    base_params: Dict[str, Any] = {
        "model": model or _DEFAULT_MODEL,
        "instructions": instructions,
        "input": input_obj,
        "temperature": temperature,
        "response_format": response_format,
        "seed": seed,
        "max_output_tokens": max_output_tokens,
    }
    base_params = _prune_none(base_params)

    for attempt in range(_MAX_RETRIES):
        try:
            # Attempt 1: modern signature
            try:
                resp = client.responses.create(**base_params)
                return getattr(resp, "output_text", None) or str(resp)
            except TypeError as te:
                # Fallback path: remove 'seed' if unsupported; then try swapping token field name.
                fallback_params = dict(base_params)
                if "seed" in str(te) and "seed" in fallback_params:
                    fallback_params.pop("seed", None)

                try:
                    resp = client.responses.create(**fallback_params)
                    return getattr(resp, "output_text", None) or str(resp)
                except TypeError as te2:
                    # Last resort: rename max_output_tokens -> max_tokens
                    if ("max_output_tokens" in str(te2)) and ("max_output_tokens" in fallback_params):
                        fallback_params["max_tokens"] = fallback_params.pop("max_output_tokens")
                    resp = client.responses.create(**fallback_params)
                    return getattr(resp, "output_text", None) or str(resp)
        except HTTPError:
            if attempt == _MAX_RETRIES - 1:
                raise
            time.sleep(delay)
            delay = min(delay * 2, 20.0)
        except Exception:
            if attempt == _MAX_RETRIES - 1:
                raise
            time.sleep(delay)
            delay = min(delay * 2, 20.0)

    # Should never get here due to raises on last attempt
    raise RuntimeError("Failed to obtain response from OpenAI after retries.")
