"""FastAPI app and challenge routes for the unified incident environment."""

from __future__ import annotations

import argparse
import os
from typing import Any

import gradio as gr
from fastapi import Body
from fastapi import HTTPException
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
        return RedirectResponse(url="/web/")

    @app.get("/web", include_in_schema=False)
    async def web_root_no_slash():
        return RedirectResponse(url="/web/")

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
