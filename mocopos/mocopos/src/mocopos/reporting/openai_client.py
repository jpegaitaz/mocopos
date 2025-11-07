import os
import time
from pathlib import Path
from typing import Dict, Any, Optional

from httpx import HTTPError
from openai import OpenAI
from dotenv import load_dotenv, find_dotenv

# -------------------- Environment helpers --------------------

def _load_env_once() -> None:
    # Load .env from the nearest parent; do not overwrite real env vars
    load_dotenv(find_dotenv(), override=False)

def _resolve_api_key() -> Optional[str]:
    api_key = os.getenv("OPENAI_API_KEY")
    if api_key:
        return api_key

    # Optional: read from a file path if provided
    key_file = os.getenv("OPENAI_API_KEY_FILE")
    if key_file and Path(key_file).exists():
        return Path(key_file).read_text(encoding="utf-8").strip()

    return None

def _default_model() -> str:
    # Read dynamically so .env changes are respected without restart
    return os.getenv("OPENAI_MODEL", "gpt-4o")

_MAX_RETRIES = int(os.getenv("OPENAI_MAX_RETRIES", "5"))

_client: Optional[OpenAI] = None

# -------------------- Client factory --------------------

def get_client() -> OpenAI:
    global _client
    if _client is None:
        _load_env_once()

        api_key = _resolve_api_key()
        if not api_key:
            raise RuntimeError(
                "Missing OPENAI_API_KEY. Set it in your environment or provide OPENAI_API_KEY_FILE."
            )

        base_url = os.getenv("OPENAI_BASE_URL")
        _client = OpenAI(api_key=api_key, base_url=base_url) if base_url else OpenAI(api_key=api_key)
    return _client

# -------------------- Utils --------------------

def _prune_none(d: Dict[str, Any]) -> Dict[str, Any]:
    return {k: v for k, v in d.items() if v is not None}

# -------------------- Responses wrapper --------------------

def call_openai_responses(
    model: Optional[str],
    instructions: str,
    input_obj: Any,
    *,
    response_format: Optional[Dict[str, Any]] = None,
    temperature: float = 0.2,
    seed: Optional[int] = None,
    max_output_tokens: Optional[int] = None,
) -> str:
    """
    Wraps the Responses API with retries and compatibility fallbacks.
    - Tries modern signature first.
    - If TypeError mentions unsupported fields, falls back by removing them
      or swapping 'max_output_tokens' -> 'max_tokens'.
    """
    client = get_client()
    delay = 1.0

    # Build the most up-to-date parameter set
    base_params: Dict[str, Any] = {
        "model": model or _default_model(),
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
            # Network/HTTP transport error from httpx
            if attempt == _MAX_RETRIES - 1:
                raise
            time.sleep(delay)
            delay = min(delay * 2, 20.0)

        except Exception:
            # Any other SDK/runtime error; backoff and retry
            if attempt == _MAX_RETRIES - 1:
                raise
            time.sleep(delay)
            delay = min(delay * 2, 20.0)

    # Should never reach here because we raise on the last attempt
    raise RuntimeError("Failed to obtain response from OpenAI after retries.")
