"""Flask API endpoints for Garmin Connect authentication, stats, and workout upload."""

import json
import logging
import os
from datetime import date

from flask import Flask, jsonify, request
from flask_cors import CORS

from dotenv import load_dotenv

from garminconnect import GarminConnectTooManyRequestsError

import metrics
from garmin_service import (
    create_session,
    get_activity_detail,
    get_client_for_session,
    revoke_session,
)

# INFO keeps our own operational logs (inbound, token cache hits/misses, cold logins, counts)
# and garminconnect's WARNING-level login-strategy 429 summaries, while dropping the very chatty
# urllib3 / garminconnect per-request DEBUG output. Flip to DEBUG when diagnosing a login issue.
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

load_dotenv()
INTERNAL_API_KEY = os.getenv("INTERNAL_API_KEY")

app = Flask(__name__)
CORS(
    app,
    origins=[
        "http://localhost:5173",
        "https://gymcraft.damianwroblewski.com",
    ],
)


@app.before_request
def check_api_key():
    # Inbound marker for every request that actually reaches Flask. Pair the reqId with the
    # proxy's "[garmin-activities][#N] -> POST" line: if the proxy logs a 429 for #N but no
    # "inbound ... reqId=N" line appears here, the request was throttled upstream (Render's
    # Cloudflare edge) and never hit the app — i.e. NOT a Garmin rate limit.
    logger.info(
        "inbound %s %s reqId=%s", request.method, request.path, request.headers.get("X-Request-Id", "-")
    )
    # /health is intentionally unauthenticated: it is the wake + readiness probe the proxy polls
    # when Render has spun this free instance down. It touches no Garmin state and leaks nothing,
    # so it stays outside the API-key gate (and is usable by an external keep-warm pinger too).
    if request.path == "/health":
        return
    if not INTERNAL_API_KEY:
        return
    provided = request.headers.get("X-API-Key")
    if not provided:
        logger.warning("Rejected %s %s: missing X-API-Key header", request.method, request.path)
        return jsonify({
            "status": "error",
            "code": "MISSING_API_KEY",
            "message": "Missing X-API-Key header — the internal API key was not sent by the caller.",
        }), 401
    if provided != INTERNAL_API_KEY:
        logger.warning("Rejected %s %s: X-API-Key does not match configured key", request.method, request.path)
        return jsonify({
            "status": "error",
            "code": "INVALID_API_KEY",
            "message": "Invalid X-API-Key — the key sent does not match the value configured on this service.",
        }), 401


@app.route("/health", methods=["GET"])
def health():
    # Cheap liveness signal. A 200 here means gunicorn is up and serving — which is exactly what
    # the proxy needs to know before it sends the real /activities request after a cold start.
    return jsonify({"status": "ok"}), 200


@app.route("/metrics", methods=["GET"])
def metrics_view():
    # Phase 0 diagnostics: counters (cache hit/miss, login paths, 429s) and per-operation latency
    # percentiles. Per-process (per gunicorn worker) and resets on restart. Sits behind the
    # X-API-Key gate via before_request, so it is not public when INTERNAL_API_KEY is configured.
    return jsonify({"status": "ok", "metrics": metrics.snapshot()}), 200


def _bearer_token():
    """Extract the opaque session token from an 'Authorization: Bearer <token>' header."""
    auth = request.headers.get("Authorization", "")
    if auth.startswith("Bearer "):
        return auth[len("Bearer "):].strip()
    return None


def _client_from_bearer():
    """Resolve the Bearer token to its Garmin client, or raise PermissionError.

    The token is the SOLE identity signal — any username/password in the request
    body is ignored, which is what closes the old email-keyed impersonation bypass.
    """
    return get_client_for_session(_bearer_token())


@app.route("/authenticate", methods=["POST"])
def authenticate():
    data = request.get_json(silent=True) or {}
    username = data.get("username")
    password = data.get("password")

    if not username or not password:
        return jsonify({"status": "error", "message": "Username and password are required"}), 400

    try:
        session_token = create_session(username, password)
        return jsonify({"status": "success", "session_token": session_token})
    except Exception as e:
        logger.exception("Authentication failed")
        return jsonify({"status": "error", "message": str(e)}), 500


@app.route("/logout", methods=["POST"])
def logout():
    # Idempotent: revoking a missing/unknown token is a no-op success.
    revoke_session(_bearer_token())
    return jsonify({"status": "success"})


@app.route("/user-stats", methods=["POST"])
def user_stats():
    try:
        client = _client_from_bearer()
    except PermissionError as e:
        return jsonify({"status": "error", "message": str(e)}), 401

    try:
        with metrics.timer("user-stats.fetch") as t:
            stats = client.get_stats_and_body(date.today().isoformat())
        logger.info("user-stats: fetch in %.0f ms", t.elapsed_ms)
        return jsonify({"status": "success", "data": stats})
    except Exception as e:
        logger.exception("user-stats failed")
        return jsonify({"status": "error", "message": str(e)}), 500


@app.route("/activities", methods=["POST"])
def activities():
    try:
        client = _client_from_bearer()
    except PermissionError as e:
        return jsonify({"status": "error", "message": str(e)}), 401

    data = request.get_json(silent=True) or {}
    start_date = data.get("startDate")
    end_date = data.get("endDate") or date.today().isoformat()
    activity_type = data.get("activityType")

    if not start_date:
        return jsonify({"status": "error", "message": "startDate is required"}), 400

    logger.info("activities: %s..%s type=%s", start_date, end_date, activity_type)
    try:
        with metrics.timer("activities.fetch") as t:
            activities_data = client.get_activities_by_date(start_date, end_date, activity_type)
        count = len(activities_data) if activities_data else 0
        logger.info("activities: returned %d items in %.0f ms", count, t.elapsed_ms)
        return jsonify({"status": "success", "data": activities_data})
    except GarminConnectTooManyRequestsError as e:
        # Surface rate limits as a real 429 (not a generic 500) so the proxy/app can tell
        # a Garmin throttle apart from other failures. If the proxy still logs a 429 whose
        # body does NOT match this JSON, the throttle came from an intermediary, not Garmin.
        metrics.incr("garmin.429")
        logger.warning("activities: Garmin rate limit (429): %s", e)
        return jsonify({"status": "error", "message": f"Garmin rate limit: {e}"}), 429
    except Exception as e:
        logger.exception("activities failed (%s)", type(e).__name__)
        return jsonify({"status": "error", "message": str(e)}), 500


@app.route("/activity/detail", methods=["POST"])
def activity_detail():
    try:
        client = _client_from_bearer()
    except PermissionError as e:
        return jsonify({"status": "error", "message": str(e)}), 401

    data = request.get_json(silent=True) or {}
    activity_id = data.get("activityId")
    if activity_id is None:
        return jsonify({"status": "error", "message": "activityId is required"}), 400

    try:
        activity_id_int = int(activity_id)
    except (TypeError, ValueError):
        return jsonify({"status": "error", "message": "activityId must be a number"}), 400

    try:
        with metrics.timer("activity-detail.fetch") as t:
            detail = get_activity_detail(client, activity_id_int)
        logger.info("activity-detail: fetch in %.0f ms", t.elapsed_ms)
        return jsonify({"status": "success", "data": detail})
    except Exception as e:
        logger.exception("activity-detail failed")
        return jsonify({"status": "error", "message": str(e)}), 500


@app.route("/progress-summary", methods=["POST"])
def progress_summary():
    try:
        client = _client_from_bearer()
    except PermissionError as e:
        return jsonify({"status": "error", "message": str(e)}), 401

    data = request.get_json(silent=True) or {}
    start_date = data.get("startDate")
    end_date = data.get("endDate")
    metric_name = data.get("metric") or "distance"
    group_by = data.get("groupByParentActivityType")
    if group_by is None:
        group_by = True

    if not start_date:
        return jsonify({"status": "error", "message": "startDate is required"}), 400
    if not end_date:
        return jsonify({"status": "error", "message": "endDate is required"}), 400

    try:
        with metrics.timer("progress-summary.fetch") as t:
            summary = client.get_progress_summary_between_dates(
                startdate=start_date,
                enddate=end_date,
                metric=metric_name,
                groupbyactivities=bool(group_by),
            )
        logger.info("progress-summary: fetch in %.0f ms", t.elapsed_ms)
        return jsonify({"status": "success", "data": summary})
    except Exception as e:
        logger.exception("progress-summary failed")
        return jsonify({"status": "error", "message": str(e)}), 500


@app.route("/upload-workout", methods=["POST"])
def upload_workout():
    try:
        client = _client_from_bearer()
    except PermissionError as e:
        return jsonify({"status": "error", "message": str(e)}), 401

    if "file" not in request.files:
        return jsonify({"status": "error", "message": "No file part in the request"}), 400

    file = request.files["file"]
    if file.filename == "":
        return jsonify({"status": "error", "message": "No selected file"}), 400

    try:
        workout_json = json.loads(file.read().decode("utf-8"))
        with metrics.timer("upload-workout.fetch") as t:
            response = client.upload_workout(workout_json)
        logger.info("upload-workout: upload in %.0f ms", t.elapsed_ms)
        return jsonify({"status": "success", "response": response})
    except json.JSONDecodeError as e:
        logger.error("JSON parse error: %s", e)
        return jsonify({"status": "error", "message": f"Invalid JSON format: {e}"}), 400
    except Exception as e:
        logger.exception("upload-workout failed")
        return jsonify({"status": "error", "message": str(e)}), 500


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
