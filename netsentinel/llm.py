"""Claude via the server's keyless login (the same pattern as Resumate's src/lib/ai/client.ts).

Guard rails:
- no static credentials: refuses to run if an API key is in the environment, or if the runtime
  reports one was used
- all built-in Claude Code tools disabled; only the SDK's StructuredOutput is allowed
- no user/project settings, CLAUDE.md or skills; an isolated, empty working directory
- a minimal subprocess environment, so the database socket path and other settings never reach it
"""

import asyncio
import logging
import os
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path

log = logging.getLogger(__name__)

FORBIDDEN_KEYS = ("ANTHROPIC_API_KEY", "ANTHROPIC_AUTH_TOKEN", "AWS_BEARER_TOKEN_BEDROCK",
                  "ANTHROPIC_FOUNDRY_API_KEY", "ANTHROPIC_FOUNDRY_AUTH_TOKEN")
BASE_ENV = ("PATH", "HOME", "USER", "LANG", "TMPDIR", "CLAUDE_CONFIG_DIR", "HTTPS_PROXY", "HTTP_PROXY", "NO_PROXY")
DEFAULT_MODEL = "claude-sonnet-5"


class LLMUnavailable(RuntimeError):
    pass


class LLMInvalidOutput(RuntimeError):
    pass


@dataclass(frozen=True)
class LLMResult:
    output: dict
    model: str
    duration_ms: int


def config_problems() -> list[str]:
    problems = [f"{k} is set; static API keys are not allowed (keyless login only)"
                for k in FORBIDDEN_KEYS if os.environ.get(k, "").strip()]
    if os.environ.get("NETSENTINEL_AI_MODE", "local") != "local":
        problems.append("only NETSENTINEL_AI_MODE=local (the server's `claude login`) is supported")
    return problems


def _env() -> dict[str, str]:
    env = {k: v for k, v in os.environ.items() if k in BASE_ENV}
    env.setdefault("HOME", str(Path.home()))
    env["CLAUDE_AGENT_SDK_CLIENT_APP"] = "netsentinel/1.0"
    env["CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC"] = "1"
    return env


def _cwd() -> Path:
    p = Path(tempfile.gettempdir()) / "netsentinel-agents"
    p.mkdir(mode=0o700, exist_ok=True)
    return p


class ClaudeClient:
    """Structured, tool-less, one-shot calls. Implements the `complete` interface agents depend on."""

    def __init__(self, model: str | None = None, timeout_s: float = 180):
        self.model = model or os.environ.get("NETSENTINEL_CLAUDE_MODEL", DEFAULT_MODEL)
        self.timeout_s = timeout_s

    def complete(self, *, system: str, prompt: str, schema: dict) -> LLMResult:
        problems = config_problems()
        if problems:
            raise LLMUnavailable("; ".join(problems))
        started = time.monotonic()
        try:
            output = asyncio.run(asyncio.wait_for(self._run(system, prompt, schema), self.timeout_s))
        except asyncio.TimeoutError:
            raise LLMUnavailable(f"no response within {self.timeout_s:.0f}s") from None
        return LLMResult(output, self.model, int((time.monotonic() - started) * 1000))

    async def _run(self, system: str, prompt: str, schema: dict) -> dict:
        from claude_agent_sdk import ClaudeAgentOptions, ClaudeSDKError, ResultMessage, SystemMessage, query

        options = ClaudeAgentOptions(
            system_prompt=system, tools=[], allowed_tools=[], permission_mode="dontAsk", setting_sources=[],
            cwd=str(_cwd()), env=_env(), model=self.model, max_turns=8, effort="medium",
            output_format={"type": "json_schema", "schema": schema},
        )
        result = None
        try:
            async for message in query(prompt=prompt, options=options):
                if isinstance(message, SystemMessage) and message.subtype == "init":
                    tools = set(message.data.get("tools") or []) - {"StructuredOutput"}
                    if tools:
                        raise LLMUnavailable(f"agent started with unexpected tools {sorted(tools)}; refusing to run")
                    if message.data.get("apiKeySource") in ("ANTHROPIC_API_KEY", "apiKeyHelper"):
                        raise LLMUnavailable("agent attempted to use a static API key; refusing to run")
                elif isinstance(message, ResultMessage):
                    result = message
        except ClaudeSDKError as e:
            raise LLMUnavailable(f"Claude runtime error: {type(e).__name__}: {str(e)[:200]}") from None
        if result is None:
            raise LLMUnavailable("Claude ended without a result")
        if result.subtype == "error_max_structured_output_retries":
            raise LLMInvalidOutput("Claude could not produce output matching the schema")
        if result.is_error or result.subtype != "success" or not isinstance(result.structured_output, dict):
            raise LLMUnavailable(f"Claude returned {result.subtype}")
        log.info("claude ok in %sms, turns=%s", result.duration_ms, result.num_turns)
        return result.structured_output
