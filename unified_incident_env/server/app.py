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
    .summary-panel {
      margin-top: 12px;
      padding: 12px;
      border: 1px solid var(--line);
      border-radius: 10px;
      background: #081124;
    }
    .summary-title {
      margin: 0 0 10px;
      font-size: 16px;
    }
    .summary-meta {
      margin: 0 0 10px;
      color: var(--muted);
      font-size: 12px;
    }
    .bar-row {
      display: grid;
      grid-template-columns: 260px 1fr 64px;
      align-items: center;
      gap: 10px;
      margin: 8px 0;
    }
    .bar-label {
      font-size: 12px;
      color: var(--text);
      overflow: hidden;
      text-overflow: ellipsis;
      white-space: nowrap;
    }
    .bar-track {
      height: 12px;
      border-radius: 999px;
      background: #1a2742;
      overflow: hidden;
      border: 1px solid #2b3b57;
    }
    .bar-fill {
      height: 100%;
      border-radius: 999px;
      background: linear-gradient(90deg, #34d399 0%, #60a5fa 100%);
    }
    .bar-fill.steps {
      background: linear-gradient(90deg, #f59e0b 0%, #fb7185 100%);
    }
    .bar-value {
      text-align: right;
      font-size: 12px;
      color: var(--muted);
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
        <label for="hfToken">HF Token (never stored by this UI)</label>
        <input id="hfToken" type="password" placeholder="hf_xxx..." />
      </div>
      <div>
        <label for="modelLabel">MODEL_NAME (required for Start Session)</label>
        <input id="modelLabel" type="text" value="Qwen/Qwen2.5-72B-Instruct:novita" />
      </div>
      <div>
        <label for="scenarioId">Scenario ID (optional on reset)</label>
        <select id="scenarioId">
          <option value="all" selected>all (easy + medium + hard)</option>
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
      <button class="primary" onclick="startSession()">Start Session</button>
      <button onclick="doReset()">Reset</button>
      <button onclick="doStep()">Step</button>
      <button onclick="doState()">Get state</button>
      <button class="danger" onclick="clearTerminal()">Clear</button>
      <a href="/web/" style="margin-left:auto;align-self:center;">Open advanced UI</a>
    </div>

    <pre id="terminal"></pre>
    <div id="summaryPanel" class="summary-panel" style="display:none;">
      <h2 class="summary-title">Performance Summary</h2>
      <p id="summaryMeta" class="summary-meta"></p>
      <div id="scoreBars"></div>
      <div id="stepBars" style="margin-top:12px;"></div>
    </div>
    <div class="hint">
      Start Session runs selected scenario(s) end-to-end against live `/web/reset` + `/web/step` and emits START/STEP/END logs.
    </div>
  </div>

  <script>
    const terminal = document.getElementById("terminal");
    const summaryPanel = document.getElementById("summaryPanel");
    const summaryMeta = document.getElementById("summaryMeta");
    const scoreBars = document.getElementById("scoreBars");
    const stepBars = document.getElementById("stepBars");
    let lastObservation = null;
    let lastDone = false;
    let stepCounter = 0;
    let rewardHistory = [];
    let autoRunning = false;
    let actionHistory = [];
    let runResults = [];

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

    function readModelLabel() {
      return document.getElementById("modelLabel").value.trim();
    }

    function actionToLog(action) {
      try {
        return JSON.stringify(action);
      } catch {
        return String(action);
      }
    }

    function benchmarkScenarios(selection) {
      const all = [
        "database_sqli_outage",
        "cache_abuse_broken_access_control",
        "worker_bad_deploy_command_injection",
      ];
      if (!selection || selection === "all") {
        return all;
      }
      if (selection === "default") {
        return ["database_sqli_outage"];
      }
      return [selection];
    }

    function formatBool(value) {
      return value ? "true" : "false";
    }

    function rewardSum(values) {
      return values.reduce((total, value) => total + Number(value || 0), 0);
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

    function summarizeObservation(observation, doneOverride = null) {
      if (!observation || typeof observation !== "object") {
        return "observation=none";
      }
      const tick = observation.tick_count;
      const stage = observation.workflow_stage;
      const score = observation.final_score;
      const done = (typeof doneOverride === "boolean")
        ? doneOverride
        : (typeof observation.done === "boolean" ? observation.done : false);
      return "tick=" + tick + " stage=" + stage + " final_score=" + score + " done=" + done;
    }

    function toStepAction(rawAction) {
      if (rawAction && typeof rawAction === "object" && rawAction.action_type === "submit_postmortem" && !rawAction.postmortem) {
        return {
          action_type: "submit_postmortem",
          postmortem: {
            root_cause: "incident documented",
            attack_vector: "documented in run",
            timeline: ["reset", "security subquest", "remediation", "verification"],
            remediation_steps: ["restart affected services", "apply approved patch"],
            prevention_steps: ["increase monitoring", "harden input validation"],
          },
        };
      }
      return rawAction;
    }

    function pickAutoAction(observation, scenarioId) {
      if (!observation || typeof observation !== "object") {
        return null;
      }
      const stage = observation.workflow_stage || "";
      const allowed = Array.isArray(observation.allowed_actions) ? observation.allowed_actions : [];
      const repeatedAction = actionHistory.length >= 2
        && actionHistory[actionHistory.length - 1] === actionHistory[actionHistory.length - 2]
        ? actionHistory[actionHistory.length - 1]
        : null;
      const repeatingError = typeof observation.why_failed === "string"
        && observation.why_failed.toLowerCase().includes("same ineffective action");

      if (scenarioId === "cache_abuse_broken_access_control" && stage === "root_cause_analysis") {
        if (allowed.includes("query_dependencies")) {
          return { action_type: "query_dependencies", service: "api-gateway" };
        }
        if (allowed.includes("query_logs")) {
          return { action_type: "query_logs", service: "cache" };
        }
      }

      if (repeatingError && repeatedAction && allowed.length > 1) {
        const alternative = allowed.find((actionType) => actionType !== repeatedAction);
        if (alternative) {
          if (alternative === "query_dependencies") {
            return { action_type: "query_dependencies", service: "api-gateway" };
          }
          if (alternative === "query_logs") {
            return { action_type: "query_logs", service: scenarioId === "worker_bad_deploy_command_injection" ? "worker" : "database" };
          }
          return { action_type: alternative };
        }
      }

      const validExample = observation.valid_action_example;
      if (validExample && typeof validExample === "object" && validExample.action_type) {
        return toStepAction(validExample);
      }
      if (allowed.length === 0) {
        return null;
      }
      if (allowed.includes("query_logs")) {
        return { action_type: "query_logs" };
      }
      return toStepAction({ action_type: allowed[0] });
    }

    async function doReset(silentStart = false, scenarioOverride = null, emitResetLog = true) {
      const selectedScenario = scenarioOverride ?? readScenario();
      const scenario = selectedScenario === "all" ? "" : selectedScenario;
      const payload = scenario ? { scenario_id: scenario } : {};
      if (!silentStart) {
        append("[RESET] request => " + safeJson(payload));
      }
      try {
        const result = await requestJson("/web/reset", payload, "POST");
        if (!result.ok) {
          append("[ERROR] reset failed status=" + result.status + " body=" + safeJson(result.data));
          return null;
        }
        const reward = typeof result.data?.reward === "number" ? result.data.reward : 0;
        const done = typeof result.data?.done === "boolean" ? result.data.done : false;
        if (emitResetLog) {
          append("[RESET] status=200 reward=" + reward + " done=" + done + " " + summarizeObservation(result.data?.observation, done));
        }
        lastObservation = result.data?.observation || null;
        lastDone = done;
        stepCounter = 0;
        rewardHistory = [];
        actionHistory = [];
        return result.data;
      } catch (error) {
        append("[ERROR] reset exception=" + String(error));
        return null;
      }
    }

    async function executeStep(action, emitRequestLog = true) {
      const stepAction = toStepAction(action);
      if (!stepAction || typeof stepAction !== "object" || !stepAction.action_type) {
        append("[ERROR] invalid action object");
        return null;
      }

      if (emitRequestLog) {
        append("[STEP] request action=" + actionToLog(stepAction));
      }

      try {
        const result = await requestJson("/web/step", stepAction, "POST");
        if (!result.ok) {
          append("[ERROR] step failed status=" + result.status + " body=" + safeJson(result.data));
          return null;
        }
        const reward = typeof result.data?.reward === "number" ? result.data.reward : 0;
        const done = typeof result.data?.done === "boolean" ? result.data.done : false;
        const observation = result.data?.observation || {};
        const errorText = result.data?.observation?.why_failed || "null";
        stepCounter += 1;
        rewardHistory.push(reward);
        actionHistory.push(stepAction.action_type);
        lastObservation = observation;
        lastDone = done;
        append("[STEP] step=" + stepCounter + " action=" + actionToLog(stepAction) + " reward=" + reward.toFixed(2) + " done=" + String(done).toLowerCase() + " error=" + errorText);
        append("[STATE] " + summarizeObservation(observation, done));
        return result.data;
      } catch (error) {
        append("[ERROR] step exception=" + String(error));
        return null;
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

      await executeStep(action, true);
    }

    async function runAutoSession(scenarioId) {
      autoRunning = true;
      const maxSteps = Math.max(1, (lastObservation?.max_ticks || 8) + 6);
      while (!lastDone && stepCounter < maxSteps) {
        const autoAction = pickAutoAction(lastObservation, scenarioId);
        if (!autoAction) {
          append("[ERROR] no valid next action available");
          break;
        }
        document.getElementById("actionInput").value = safeJson(autoAction);
        const stepResult = await executeStep(autoAction, false);
        if (!stepResult) {
          break;
        }
      }
      const finalScore = Number(lastObservation?.final_score ?? 0);
      const success = Boolean(
        lastDone
        && lastObservation?.incident_resolved
        && lastObservation?.security_subquest_status === "completed"
      );
      const rewardsStr = rewardHistory.map((r) => Number(r).toFixed(2)).join(",");
      append("[END] success=" + formatBool(success) + " steps=" + stepCounter + " score=" + finalScore.toFixed(2) + " rewards=" + rewardsStr);
      autoRunning = false;
      return {
        success,
        steps: stepCounter,
        score: finalScore,
        rewards: rewardHistory.slice(),
      };
    }

    function renderBarRows(container, rows, maxValue, fillClass = "") {
      const safeMax = maxValue > 0 ? maxValue : 1;
      container.innerHTML = rows.map((row) => {
        const width = Math.max(0, Math.min(100, (row.value / safeMax) * 100));
        const fillClassName = fillClass ? "bar-fill " + fillClass : "bar-fill";
        return (
          '<div class="bar-row">' +
            '<div class="bar-label">' + row.label + "</div>" +
            '<div class="bar-track"><div class="' + fillClassName + '" style="width:' + width.toFixed(1) + '%"></div></div>' +
            '<div class="bar-value">' + row.text + "</div>" +
          "</div>"
        );
      }).join("");
    }

    function renderSummary(results, modelName) {
      if (!Array.isArray(results) || results.length === 0) {
        summaryPanel.style.display = "none";
        return;
      }
      summaryPanel.style.display = "block";
      const meanScore = results.reduce((total, item) => total + item.score, 0) / results.length;
      const successCount = results.filter((item) => item.success).length;
      summaryMeta.textContent = "Model: " + modelName + " | Mean score: " + meanScore.toFixed(2) + " | Success: " + successCount + "/" + results.length;

      renderBarRows(
        scoreBars,
        results.map((item) => ({
          label: item.scenario + " (score)",
          value: item.score,
          text: item.score.toFixed(2),
        })),
        1.0,
        ""
      );

      const maxSteps = Math.max(...results.map((item) => item.steps), 1);
      renderBarRows(
        stepBars,
        results.map((item) => ({
          label: item.scenario + " (steps)",
          value: item.steps,
          text: String(item.steps),
        })),
        maxSteps,
        "steps"
      );
    }

    async function startSession() {
      if (autoRunning) {
        append("[ERROR] session already running");
        return;
      }

      const token = readToken();
      const modelLabel = readModelLabel();
      if (!token || !modelLabel) {
        append("[ERROR] Start Session requires both HF token and MODEL_NAME. Fill both fields first.");
        return;
      }

      const selected = readScenario();
      const scenarioIds = benchmarkScenarios(selected);
      runResults = [];
      summaryPanel.style.display = "none";
      append("[RUN] live_env=true endpoints=/web/reset,/web/step,/web/state");

      for (const scenarioId of scenarioIds) {
        append("[START] task=" + scenarioId + " env=unified-incident-env model=" + modelLabel);
        const resetPayload = await doReset(true, scenarioId, false);
        if (!resetPayload) {
          append("[END] success=false steps=0 score=0.00 rewards=");
          runResults.push({
            scenario: scenarioId,
            success: false,
            steps: 0,
            score: 0,
            reward_sum: 0,
          });
          continue;
        }
        const outcome = await runAutoSession(scenarioId);
        runResults.push({
          scenario: scenarioId,
          success: Boolean(outcome?.success),
          steps: Number(outcome?.steps || 0),
          score: Number(outcome?.score || 0),
          reward_sum: rewardSum(outcome?.rewards || []),
        });
      }
      renderSummary(runResults, modelLabel);
    }

    async function doState() {
      append("[STATE] request /web/state");
      try {
        const result = await requestJson("/web/state", null, "GET");
        if (!result.ok) {
          append("[ERROR] /web/state failed status=" + result.status + " body=" + safeJson(result.data));
          const fallback = await requestJson("/state", null, "GET");
          if (!fallback.ok) {
            append("[ERROR] /state fallback failed status=" + fallback.status + " body=" + safeJson(fallback.data));
            return;
          }
          append("[STATE] fallback step_count=" + fallback.data?.step_count);
          append(safeJson(fallback.data));
          return;
        }
        append(
          "[STATE] step_count=" + result.data?.step_count +
          " workflow_stage=" + result.data?.workflow_stage +
          " scenario=" + result.data?.scenario_id +
          " difficulty=" + result.data?.difficulty
        );
        append(safeJson(result.data));
      } catch (error) {
        append("[ERROR] state exception=" + String(error));
      }
    }

    function clearTerminal() {
      terminal.textContent = "";
    }

    append("Simple console ready. Provide HF token + MODEL_NAME, then click Start Session.");
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
