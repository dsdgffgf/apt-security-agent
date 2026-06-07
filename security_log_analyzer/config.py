from __future__ import annotations

import os
from pathlib import Path

# 自动加载项目根目录 .env 文件（不提交到 git）
_dotenv_path = Path(__file__).resolve().parent.parent / ".env"
if _dotenv_path.exists():
    try:
        from dotenv import load_dotenv
        load_dotenv(_dotenv_path)
    except ImportError:
        pass


# DeepSeek configuration (primary)
DEEPSEEK_DEFAULT_MODEL = "deepseek-v4-pro"
DEEPSEEK_FLASH_MODEL = "deepseek-v4-flash"
DEEPSEEK_DEFAULT_BASE_URL = "https://api.deepseek.com/v1"
DEEPSEEK_API_KEY_ENV_VARS = ("DEEPSEEK_API_KEY",)
DEEPSEEK_MODEL_ENV_VARS = ("DEEPSEEK_MODEL",)
DEEPSEEK_BASE_URL_ENV_VARS = ("DEEPSEEK_BASE_URL",)

# 按 mode 自动选择模型: 复杂推理用 Pro，工具驱动用 Flash
MODE_MODEL_MAP: dict[str, str] = {
    "apt": DEEPSEEK_DEFAULT_MODEL,       # APT 多阶段编排 → Pro
    "attack": DEEPSEEK_FLASH_MODEL,       # payload 生成 → Flash
    "pentest": DEEPSEEK_FLASH_MODEL,      # 端口扫描+简单分析 → Flash
    "defense": DEEPSEEK_FLASH_MODEL,      # 日志分析 → Flash
}

# ── C2 监听器配置（社工钓鱼）────────────────────────────
C2_HOST = os.getenv("C2_HOST", "0.0.0.0")
C2_PORT = int(os.getenv("C2_PORT", "8080"))
C2_ENABLED = os.getenv("C2_ENABLED", "true").lower() in ("1", "true", "yes")
C2_CAPTURE_ENDPOINT = os.getenv("C2_CAPTURE_ENDPOINT", "/capture")
C2_PAYLOAD_ENDPOINT = os.getenv("C2_PAYLOAD_ENDPOINT", "/payload.ps1")


# MiMo configuration (legacy fallback)
MIMO_DEFAULT_MODEL = "mimo-v2.5-pro"
MIMO_PAYG_BASE_URL = "https://api.xiaomimimo.com/anthropic"
MIMO_TOKEN_PLAN_BASE_URL = "https://token-plan-cn.xiaomimimo.com/anthropic"
MIMO_DEFAULT_BASE_URL = MIMO_PAYG_BASE_URL
MIMO_API_KEY_ENV_VARS = ("MIMO_API_KEY", "XIAOMI_API_KEY", "XIAOMI_MIMO_API_KEY")
MIMO_MODEL_ENV_VARS = ("MIMO_MODEL", "XIAOMI_MIMO_MODEL", "XIAOMI_MODEL")
MIMO_BASE_URL_ENV_VARS = ("MIMO_BASE_URL", "XIAOMI_MIMO_BASE_URL", "XIAOMI_BASE_URL")


def load_qwen_model_config(
    *,
    model: str | None = None,
    api_key: str | None = None,
    model_server: str | None = None,
    mode: str = "defense",
) -> dict[str, object]:
    # 优先使用 DeepSeek
    if _first_env(DEEPSEEK_API_KEY_ENV_VARS) or api_key:
        return load_deepseek_model_config(model=model, api_key=api_key, model_server=model_server, mode=mode)
    if _first_env(MIMO_API_KEY_ENV_VARS):
        return load_mimo_model_config(model=model, api_key=api_key, model_server=model_server)
    # 默认尝试 DeepSeek（会在缺少 API key 时报清晰错误）
    return load_deepseek_model_config(model=model, api_key=api_key, model_server=model_server, mode=mode)


def load_deepseek_model_config(
    *,
    model: str | None = None,
    api_key: str | None = None,
    model_server: str | None = None,
    mode: str = "defense",
) -> dict[str, object]:
    resolved_key = api_key or _first_env(DEEPSEEK_API_KEY_ENV_VARS)
    if not resolved_key:
        raise ValueError(
            "DeepSeek API credential is not configured. "
            "Set the DEEPSEEK_API_KEY environment variable."
        )

    # 自动选择模型：用户显式设了 DEEPSEEK_MODEL 则优先，否则按 mode 选
    resolved_model = model or _first_env(DEEPSEEK_MODEL_ENV_VARS)
    if not resolved_model:
        resolved_model = MODE_MODEL_MAP.get(mode, DEEPSEEK_FLASH_MODEL)

    generate_cfg = {"top_p": 0.95, "temperature": 0, "max_tokens": 4096}
    if mode == "apt":
        generate_cfg["timeout"] = 600  # APT 模式工具调用需要更长推理时间
        generate_cfg["extra_body"] = {"thinking": {"type": "disabled"}}
    return {
        "model": resolved_model,
        "model_server": model_server or _first_env(DEEPSEEK_BASE_URL_ENV_VARS) or DEEPSEEK_DEFAULT_BASE_URL,
        "api_key": resolved_key,
        "model_type": "deepseek",
        "generate_cfg": generate_cfg,
    }


def load_mimo_model_config(
    *,
    model: str | None = None,
    api_key: str | None = None,
    model_server: str | None = None,
) -> dict[str, object]:
    resolved_key = api_key or _first_env(MIMO_API_KEY_ENV_VARS)
    if not resolved_key:
        raise ValueError("Xiaomi MiMo API credential is not configured in the local backend environment.")

    return {
        "model": model or _first_env(MIMO_MODEL_ENV_VARS) or MIMO_DEFAULT_MODEL,
        "model_server": resolve_mimo_base_url(
            api_key=resolved_key,
            model_server=model_server or _first_env(MIMO_BASE_URL_ENV_VARS),
        ),
        "api_key": resolved_key,
        "model_type": "mimo_anthropic",
        "generate_cfg": {"top_p": 0.95, "temperature": 0, "max_tokens": 4096},
    }


def resolve_mimo_base_url(*, api_key: str | None = None, model_server: str | None = None) -> str:
    if model_server:
        return model_server.strip().rstrip("/")

    if (api_key or "").strip().startswith("tp-"):
        return MIMO_TOKEN_PLAN_BASE_URL

    return MIMO_PAYG_BASE_URL


def _first_env(names: tuple[str, ...]) -> str | None:
    for name in names:
        value = os.getenv(name)
        if value:
            return value
    return None
