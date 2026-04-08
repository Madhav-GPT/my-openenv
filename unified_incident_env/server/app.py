"""FastAPI app and challenge routes for the unified incident environment."""

from __future__ import annotations

import argparse
import os
from typing import Any

import gradio as gr
from fastapi import Body
from fastapi import HTTPException
from fastapi.responses import HTMLResponse
from fastapi.responses import RedirectResponse
from fastapi import WebSocket, WebSocketDisconnect
from openenv.core.env_server.http_server import create_fastapi_app
from openenv.core.env_server.web_interface import (
    OPENENV_GRADIO_CSS,
    OPENENV_GRADIO_THEME,
    WebInterfaceManager,
    _extract_action_fields,
    _is_chat_env,
    build_gradio_app,
    get_gradio_display_title,
    get_quick_start_markdown,
    load_environment_metadata,
)

from ..models import (
    BaselineCatalog,
    GraderReport,
    RuntimeStatus,
    ScenarioCatalog,
    UnifiedIncidentAction,
    UnifiedIncidentObservation,
    UnifiedIncidentState,
)
from .challenge import (
    current_runtime_progress,
    grade_episode,
    list_baselines,
    list_scenarios,
    set_runtime_progress,
)
from .environment import UnifiedIncidentEnvironment

_BOOTSTRAP_ENV = UnifiedIncidentEnvironment()
set_runtime_progress(_BOOTSTRAP_ENV.state.model_dump())


_SIMPLE_CONSOLE_HTML = """<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>Unified Incident Env - Simple Console</title>
  <style>
    :root {
      color-scheme: dark;
      --bg: #0b1220;
      --panel: #111a2b;
      --line: #2b3b57;
      --text: #e9efff;
      --muted: #9aa7c2;
      --accent: #4ade80;
      --accent-2: #60a5fa;
      --danger: #f87171;
    }
    * { box-sizing: border-box; }
    body {
      margin: 0;
      background: radial-gradient(circle at 15% 10%, #1c2942 0%, #0b1220 50%, #070c16 100%);
      color: var(--text);
      font-family: "JetBrains Mono", "Fira Code", ui-monospace, SFMono-Regular, Menlo, monospace;
      min-height: 100vh;
    }
    .shell {
      max-width: 980px;
      margin: 24px auto;
      padding: 16px;
      border: 1px solid var(--line);
      border-radius: 14px;
      background: rgba(17, 26, 43, 0.88);
      backdrop-filter: blur(4px);
    }
    h1 {
      margin: 0 0 8px;
      font-size: 20px;
      letter-spacing: .2px;
    }
    p {
      margin: 0 0 12px;
      color: var(--muted);
      line-height: 1.45;
    }
    a { color: var(--accent-2); text-decoration: none; }
    a:hover { text-decoration: underline; }
    .grid {
      display: grid;
      grid-template-columns: 1fr 1fr;
      gap: 10px;
      margin-bottom: 10px;
    }
    .grid .full { grid-column: 1 / -1; }
    label {
      display: block;
      font-size: 12px;
      color: var(--muted);
      margin-bottom: 6px;
      text-transform: uppercase;
      letter-spacing: .08em;
    }
    input, select, textarea {
      width: 100%;
      border-radius: 10px;
      border: 1px solid var(--line);
      background: #0a1323;
      color: var(--text);
      padding: 10px 12px;
      font: inherit;
    }
    textarea { min-height: 110px; resize: vertical; }
    .btns {
      display: flex;
      flex-wrap: wrap;
      gap: 8px;
      margin: 10px 0 12px;
    }
    button {
      border: 1px solid var(--line);
      background: #13203a;
      color: var(--text);
      padding: 9px 12px;
      border-radius: 10px;
      cursor: pointer;
      font: inherit;
    }
    button:hover { border-color: var(--accent-2); }
    .primary { background: #16304f; border-color: #2c4f79; }
    .success { background: #143728; border-color: #256648; }
    .danger { background: #401d22; border-color: #7a2d35; }
    #terminal {
      margin: 0;
      min-height: 290px;
      max-height: 520px;
      overflow: auto;
      border: 1px solid var(--line);
      border-radius: 10px;
      padding: 12px;
      background: #060b14;
      line-height: 1.5;
      white-space: pre-wrap;
      word-break: break-word;
    }
    .hint { font-size: 12px; color: var(--muted); margin-top: 8px; }
  </style>
</head>
<body>
  <div class="shell">
    <h1>Unified Incident Env - Simple Console</h1>
    <p>
      Minimal UI for judges and demos. Use this for <code>reset</code>, <code>step</code>, and <code>state</code>.
      Keep the advanced interface at <a href="/web/">/web/</a>.
    </p>

    <div class="grid">
      <div>
        <label for="hfToken">HF Token (saved in this browser only)</label>
        <input id="hfToken" type="password" placeholder="hf_xxx..." />
      </div>
      <div>
        <label for="scenarioId">Scenario ID (optional on reset)</label>
        <select id="scenarioId">
          <option value="">default</option>
          <option value="database_sqli_outage">database_sqli_outage (easy)</option>
          <option value="cache_abuse_broken_access_control">cache_abuse_broken_access_control (medium)</option>
          <option value="worker_bad_deploy_command_injection">worker_bad_deploy_command_injection (hard)</option>
        </select>
      </div>
      <div class="full">
        <label for="actionInput">Step Action JSON (body for /step action)</label>
        <textarea id="actionInput">{ "action_type": "query_logs" }</textarea>
      </div>
    </div>

    <div class="btns">
      <button class="success" onclick="saveToken()">Save Token</button>
      <button class="primary" onclick="startSession()">Start Session</button>
      <button onclick="doReset()">Reset</button>
      <button onclick="doStep()">Step</button>
      <button onclick="doState()">Get state</button>
      <button class="danger" onclick="clearTerminal()">Clear</button>
      <a href="/web/" style="margin-left:auto;align-self:center;">Open advanced UI</a>
    </div>

    <pre id="terminal"></pre>
    <div class="hint">
      Start Session triggers reset and writes a START line; Step prints STEP-style lines; State prints the current workflow snapshot.
    </div>
  </div>

  <script>
    const tokenKey = "my_openenv_hf_token";
    const terminal = document.getElementById("terminal");

    function ts() {
      return new Date().toISOString().replace("T", " ").slice(0, 19);
    }

    function append(line) {
      terminal.textContent += "[" + ts() + "] " + line + "\\n";
      terminal.scrollTop = terminal.scrollHeight;
    }

    function safeJson(value) {
      try {
        return JSON.stringify(value, null, 2);
      } catch {
        return String(value);
      }
    }

    function readToken() {
      return document.getElementById("hfToken").value.trim();
    }

    function readScenario() {
      return document.getElementById("scenarioId").value.trim();
    }

    function saveToken() {
      const token = readToken();
      if (!token) {
        append("No HF token entered.");
        return;
      }
      localStorage.setItem(tokenKey, token);
      append("HF token saved in local browser storage.");
    }

    function loadToken() {
      const stored = localStorage.getItem(tokenKey);
      if (!stored) {
        append("No saved HF token found (optional).");
        return;
      }
      document.getElementById("hfToken").value = stored;
      append("Loaded saved HF token.");
    }

    async function requestJson(path, payload, method = "POST") {
      const init = {
        method,
        headers: { "Content-Type": "application/json" },
      };
      if (payload !== null) {
        init.body = JSON.stringify(payload);
      }
      const response = await fetch(path, init);
      const raw = await response.text();
      let json = null;
      try {
        json = raw ? JSON.parse(raw) : null;
      } catch {
        json = raw;
      }
      return { ok: response.ok, status: response.status, data: json };
    }

    function summarizeObservation(observation) {
      if (!observation || typeof observation !== "object") {
        return "observation=none";
      }
      const tick = observation.tick_count;
      const stage = observation.workflow_stage;
      const score = observation.final_score;
      const done = observation.done;
      return "tick=" + tick + " stage=" + stage + " final_score=" + score + " done=" + done;
    }

    async function startSession() {
      const token = readToken();
      if (!token) {
        append("HF token is empty. Add it first, then Start Session.");
        return;
      }
      saveToken();
      await doReset();
    }

    async function doReset() {
      const scenario = readScenario();
      const payload = scenario ? { scenario_id: scenario } : {};
      append("[START] reset request => " + safeJson(payload));
      try {
        const result = await requestJson("/reset", payload, "POST");
        if (!result.ok) {
          append("[ERROR] reset failed status=" + result.status + " body=" + safeJson(result.data));
          return;
        }
        append("[RESET] status=200 " + summarizeObservation(result.data?.observation));
      } catch (error) {
        append("[ERROR] reset exception=" + String(error));
      }
    }

    async function doStep() {
      const raw = document.getElementById("actionInput").value.trim();
      if (!raw) {
        append("[ERROR] action JSON is empty");
        return;
      }

      let action;
      try {
        action = JSON.parse(raw);
      } catch (error) {
        append("[ERROR] invalid JSON for action: " + String(error));
        return;
      }

      const payload = (action && typeof action === "object" && "action" in action)
        ? action
        : { action: action };
      append("[STEP] request action=" + safeJson(payload.action));

      try {
        const result = await requestJson("/step", payload, "POST");
        if (!result.ok) {
          append("[ERROR] step failed status=" + result.status + " body=" + safeJson(result.data));
          return;
        }
        const reward = result.data?.reward;
        const done = result.data?.done;
        const errorText = result.data?.observation?.why_failed || "null";
        append("[STEP] reward=" + reward + " done=" + done + " error=" + errorText);
        append("[STATE] " + summarizeObservation(result.data?.observation));
      } catch (error) {
        append("[ERROR] step exception=" + String(error));
      }
    }

    async function doState() {
      append("[STATE] request /state");
      try {
        const result = await requestJson("/state", null, "GET");
        if (!result.ok) {
          append("[ERROR] state failed status=" + result.status + " body=" + safeJson(result.data));
          return;
        }
        append("[STATE] step_count=" + result.data?.step_count + " workflow_stage=" + result.data?.workflow_stage + " scenario=" + result.data?.scenario_id);
        append(safeJson(result.data));
      } catch (error) {
        append("[ERROR] state exception=" + String(error));
      }
    }

    function clearTerminal() {
      terminal.textContent = "";
    }

    loadToken();
    append("Simple console ready.");
  </script>
</body>
</html>
"""


def create_compatible_app():
    env_factory = lambda: UnifiedIncidentEnvironment()
    enable_web = os.getenv("ENABLE_WEB_INTERFACE", "false").lower() in ("true", "1", "yes")
    if not enable_web:
        return create_fastapi_app(
            env_factory,
            UnifiedIncidentAction,
            UnifiedIncidentObservation,
            max_concurrent_envs=1,
        )

    app = create_fastapi_app(
        env_factory,
        UnifiedIncidentAction,
        UnifiedIncidentObservation,
        max_concurrent_envs=1,
    )
    metadata = load_environment_metadata(env_factory, "unified_incident_env")
    web_manager = WebInterfaceManager(
        env_factory,
        UnifiedIncidentAction,
        UnifiedIncidentObservation,
        metadata,
    )

    @app.get("/", include_in_schema=False)
    async def web_root():
        return RedirectResponse(url="/simple")

    @app.get("/web", include_in_schema=False)
    async def web_root_no_slash():
        return RedirectResponse(url="/web/")

    @app.get("/simple", include_in_schema=False)
    async def simple_console():
        return HTMLResponse(_SIMPLE_CONSOLE_HTML)

    @app.get("/web/metadata")
    async def web_metadata():
        return web_manager.metadata.model_dump()

    @app.websocket("/ws/ui")
    async def websocket_ui_endpoint(websocket: WebSocket):
        await web_manager.connect_websocket(websocket)
        try:
            while True:
                await websocket.receive_text()
        except WebSocketDisconnect:
            await web_manager.disconnect_websocket(websocket)

    @app.post("/web/reset")
    async def web_reset(request: dict[str, Any] | None = Body(default=None)):
        return await web_manager.reset_environment(request)

    @app.post("/web/step")
    async def web_step(request: dict[str, Any]):
        def _autofill_action_fields(action_data: dict[str, Any]) -> dict[str, Any]:
            action_type = action_data.get("action_type")
            if not isinstance(action_type, str):
                return action_data

            current_observation = web_manager.episode_state.current_observation or {}
            required_fields_by_action = current_observation.get("required_fields_by_action")
            if not isinstance(required_fields_by_action, dict):
                return action_data
            required_fields = required_fields_by_action.get(action_type)
            if not isinstance(required_fields, list):
                return action_data

            valid_action_example = current_observation.get("valid_action_example")
            if not isinstance(valid_action_example, dict):
                return action_data
            if valid_action_example.get("action_type") != action_type:
                return action_data

            filled_action = dict(action_data)
            for field in required_fields:
                if filled_action.get(field) in (None, "") and valid_action_example.get(field) not in (None, ""):
                    filled_action[field] = valid_action_example[field]
            return filled_action

        if "message" in request:
            message = request["message"]
            if hasattr(web_manager.env, "message_to_action"):
                action = web_manager.env.message_to_action(message)
                if hasattr(action, "tokens"):
                    action_data = {"tokens": action.tokens.tolist()}
                else:
                    action_data = action.model_dump(exclude={"metadata"})
            else:
                action_data = {"message": message}
        elif isinstance(request.get("action"), dict):
            action_data = request["action"]
        else:
            action_data = request

        if isinstance(action_data, dict):
            action_data = _autofill_action_fields(action_data)

        return await web_manager.step_environment(action_data)

    @app.get("/web/state")
    async def web_state():
        return web_manager.get_state()

    action_fields = _extract_action_fields(UnifiedIncidentAction)
    is_chat_env = _is_chat_env(UnifiedIncidentAction)
    quick_start_md = get_quick_start_markdown(
        metadata,
        UnifiedIncidentAction,
        UnifiedIncidentObservation,
    )
    gradio_blocks = build_gradio_app(
        web_manager,
        action_fields,
        metadata,
        is_chat_env,
        title=metadata.name,
        quick_start_md=quick_start_md,
    )
    return gr.mount_gradio_app(
        app,
        gradio_blocks,
        path="/web",
        theme=OPENENV_GRADIO_THEME,
        css=OPENENV_GRADIO_CSS,
    )


app = create_compatible_app()
app.router.routes = [
    route
    for route in app.router.routes
    if not (getattr(route, "path", None) == "/health")
]


@app.get("/tasks", response_model=ScenarioCatalog, tags=["challenge"])
def tasks(difficulty: str | None = None) -> ScenarioCatalog:
    try:
        return list_scenarios(difficulty=difficulty)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@app.get("/baseline", response_model=BaselineCatalog, tags=["challenge"])
def baseline(scenario_id: str | None = None) -> BaselineCatalog:
    try:
        return list_baselines(scenario_id=scenario_id)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@app.get("/grader", response_model=GraderReport, tags=["challenge"])
def grader(scenario_id: str | None = None) -> GraderReport:
    progress = current_runtime_progress()
    if scenario_id is not None:
        progress["scenario_id"] = scenario_id
    try:
        return grade_episode(progress)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@app.get("/status", response_model=RuntimeStatus, tags=["challenge"])
def status() -> RuntimeStatus:
    progress = current_runtime_progress()
    return RuntimeStatus(
        progress=UnifiedIncidentState(**progress),
        grader=grade_episode(progress),
    )


@app.get("/health", tags=["challenge"])
def health() -> dict[str, object]:
    return {
        "status": "ok",
        "environment": "unified_incident_env",
        "version": "1.0.0",
        "stages": [
            "diagnosis",
            "root_cause_analysis",
            "security_subquest",
            "remediation",
            "verification",
            "postmortem",
            "done",
        ],
    }


def serve(host: str = "0.0.0.0", port: int = 8000) -> None:
    import uvicorn

    uvicorn.run(app, host=host, port=port)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=8000)
    args = parser.parse_args()
    serve(host=args.host, port=args.port)


if __name__ == "__main__":
    main()
