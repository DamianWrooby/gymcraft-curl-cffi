"""Flask API endpoints for Garmin Connect authentication, stats, and workout upload."""

import json
import logging
import os
from datetime import date

from flask import Flask, jsonify, request
from flask_cors import CORS

from dotenv import load_dotenv

from garminconnect import GarminConnectTooManyRequestsError

from garmin_service import get_activity_detail, get_client

logging.basicConfig(level=logging.DEBUG)
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


@app.route("/authenticate", methods=["POST"])
def authenticate():
    data = request.get_json(silent=True) or {}
    username = data.get("username")
    password = data.get("password")

    if not username or not password:
        return jsonify({"status": "error", "message": "Username and password are required"}), 400

    try:
        get_client(username, password)
        return jsonify({"status": "success", "message": "Authenticated successfully"})
    except Exception as e:
        logger.exception("Authentication failed")
        return jsonify({"status": "error", "message": str(e)}), 500


@app.route("/user-stats", methods=["POST"])
def user_stats():
    data = request.get_json(silent=True) or {}
    username = data.get("username")
    password = data.get("password")

    if not username:
        return jsonify({"status": "error", "message": "Username is required"}), 400

    try:
        client = get_client(username, password)
        stats = client.get_stats_and_body(date.today().isoformat())
        return jsonify({"status": "success", "data": stats})
    except Exception as e:
        logger.exception("user-stats failed")
        return jsonify({"status": "error", "message": str(e)}), 500


@app.route("/activities", methods=["POST"])
def activities():
    data = request.get_json(silent=True) or {}
    username = data.get("username")
    password = data.get("password")
    start_date = data.get("startDate")
    end_date = data.get("endDate") or date.today().isoformat()
    activity_type = data.get("activityType")

    if not username:
        return jsonify({"status": "error", "message": "username is required"}), 400
    if not start_date:
        return jsonify({"status": "error", "message": "startDate is required"}), 400

    logger.info(
        "activities: %s..%s type=%s password_provided=%s", start_date, end_date, activity_type, bool(password)
    )
    try:
        client = get_client(username, password)
        activities_data = client.get_activities_by_date(start_date, end_date, activity_type)
        count = len(activities_data) if activities_data else 0
        logger.info("activities: returned %d items", count)
        return jsonify({"status": "success", "data": activities_data})
    except GarminConnectTooManyRequestsError as e:
        # Surface rate limits as a real 429 (not a generic 500) so the proxy/app can tell
        # a Garmin throttle apart from other failures. If the proxy still logs a 429 whose
        # body does NOT match this JSON, the throttle came from an intermediary, not Garmin.
        logger.warning("activities: Garmin rate limit (429): %s", e)
        return jsonify({"status": "error", "message": f"Garmin rate limit: {e}"}), 429
    except Exception as e:
        logger.exception("activities failed (%s)", type(e).__name__)
        return jsonify({"status": "error", "message": str(e)}), 500


@app.route("/activity/detail", methods=["POST"])
def activity_detail():
    data = request.get_json(silent=True) or {}
    username = data.get("username")
    password = data.get("password")
    activity_id = data.get("activityId")

    if not username:
        return jsonify({"status": "error", "message": "username is required"}), 400
    if activity_id is None:
        return jsonify({"status": "error", "message": "activityId is required"}), 400

    try:
        activity_id_int = int(activity_id)
    except (TypeError, ValueError):
        return jsonify({"status": "error", "message": "activityId must be a number"}), 400

    try:
        client = get_client(username, password)
        detail = get_activity_detail(client, activity_id_int)
        return jsonify({"status": "success", "data": detail})
    except Exception as e:
        logger.exception("activity-detail failed")
        return jsonify({"status": "error", "message": str(e)}), 500


@app.route("/progress-summary", methods=["POST"])
def progress_summary():
    data = request.get_json(silent=True) or {}
    username = data.get("username")
    password = data.get("password")
    start_date = data.get("startDate")
    end_date = data.get("endDate")
    metric = data.get("metric") or "distance"
    group_by = data.get("groupByParentActivityType")
    if group_by is None:
        group_by = True

    if not username:
        return jsonify({"status": "error", "message": "username is required"}), 400
    if not start_date:
        return jsonify({"status": "error", "message": "startDate is required"}), 400
    if not end_date:
        return jsonify({"status": "error", "message": "endDate is required"}), 400

    try:
        client = get_client(username, password)
        summary = client.get_progress_summary_between_dates(
            startdate=start_date,
            enddate=end_date,
            metric=metric,
            groupbyactivities=bool(group_by),
        )
        return jsonify({"status": "success", "data": summary})
    except Exception as e:
        logger.exception("progress-summary failed")
        return jsonify({"status": "error", "message": str(e)}), 500


@app.route("/upload-workout", methods=["POST"])
def upload_workout():
    if "username" not in request.form:
        return jsonify({"status": "error", "message": "Missing username"}), 400

    if "file" not in request.files:
        return jsonify({"status": "error", "message": "No file part in the request"}), 400

    file = request.files["file"]
    if file.filename == "":
        return jsonify({"status": "error", "message": "No selected file"}), 400

    username = request.form["username"]
    password = request.form.get("password")

    try:
        client = get_client(username, password)
        workout_json = json.loads(file.read().decode("utf-8"))
        response = client.upload_workout(workout_json)
        return jsonify({"status": "success", "response": response})
    except json.JSONDecodeError as e:
        logger.error("JSON parse error: %s", e)
        return jsonify({"status": "error", "message": f"Invalid JSON format: {e}"}), 400
    except Exception as e:
        logger.exception("upload-workout failed")
        return jsonify({"status": "error", "message": str(e)}), 500


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
