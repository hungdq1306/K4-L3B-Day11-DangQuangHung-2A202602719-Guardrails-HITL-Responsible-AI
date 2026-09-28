"""
Lab 11 — Helper Utilities
"""
from core.config import get_llm_provider, PROVIDER_OPENROUTER  # noqa: F401
from core.openai_runtime import OpenAIRunner


async def chat_with_agent(agent, runner, user_message: str, session_id=None):
    """Send a message to the agent and get the response.

    Works with OpenAIRunner (OpenAI Red / OpenRouter Blue) and Google ADK (Gemini Red).
    """
    import os
    provider = getattr(runner, "provider", None)
    if isinstance(runner, OpenAIRunner) or provider in ("openrouter", "openai"):
        text = await runner.chat(agent, user_message)
        return text, None

    from google import genai
    from google.genai import types

    class _MockCtx:
        user_id: str = "student"

    ctx = _MockCtx()
    user_content = types.Content(
        role="user",
        parts=[types.Part.from_text(text=user_message)],
    )

    # 1. Run input plugins
    plugins = getattr(runner, "plugins", None) or getattr(agent, "plugins", None) or []
    for plugin in plugins:
        cb = getattr(plugin, "on_user_message_callback", None)
        if cb:
            res = await cb(invocation_context=ctx, user_message=user_content)
            if res is not None:
                blocked_text = ""
                if hasattr(res, "parts") and res.parts:
                    blocked_text = "".join(
                        p.text for p in res.parts if getattr(p, "text", None)
                    )
                return blocked_text, None

    # 2. Call LLM with retry for rate limits
    client = genai.Client(api_key=os.environ.get("GOOGLE_API_KEY"))
    config = types.GenerateContentConfig(
        system_instruction=getattr(agent, "instruction", None),
        temperature=0.7,
    )
    model_name = getattr(agent, "model", "gemini-3.5-flash-lite")
    final_text = ""
    for attempt in range(4):
        try:
            resp = await client.aio.models.generate_content(
                model=model_name,
                contents=user_message,
                config=config,
            )
            final_text = resp.text or ""
            break
        except Exception as e:
            if "429" in str(e) or "RESOURCE_EXHAUSTED" in str(e):
                import asyncio
                await asyncio.sleep(4.0 * (attempt + 1))
            else:
                raise e

    # 3. Run output plugins
    for plugin in plugins:
        cb = getattr(plugin, "after_model_callback", None)
        if cb:
            class MockResp:
                def __init__(self, t: str):
                    self.content = types.Content(
                        role="model", parts=[types.Part.from_text(text=t)]
                    )

            m_resp = MockResp(final_text)
            out_res = await cb(callback_context=ctx, llm_response=m_resp)
            if hasattr(out_res, "content") and out_res.content and out_res.content.parts:
                final_text = "".join(
                    p.text for p in out_res.content.parts if getattr(p, "text", None)
                )

    return final_text, None
