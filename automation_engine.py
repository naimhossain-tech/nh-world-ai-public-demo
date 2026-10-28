import os
import sqlite3
import uuid
from datetime import datetime, timezone
from pathlib import Path

from flask import Blueprint, current_app, jsonify, request

automation_bp = Blueprint("automation", __name__)

BASE_DIR = Path(__file__).resolve().parent
DB_PATH = Path(os.environ.get(
    "TASK_HISTORY_DB", str(BASE_DIR / "task_history.sqlite3")
))

TASK_TYPES = {
    "file_cleaner": (
        ("csv", "xlsx", "excel", "spreadsheet", "ফাইল পরিষ্কার",
         "ডেটা পরিষ্কার", "ডুপ্লিকেট", "স্প্রেডশিট"),
        ["নির্দেশ যাচাই", "CSV/XLSX ফাইল নির্বাচন", "পরিষ্কারের ফলাফল যাচাই"],
    ),
    "web_search": (
        ("search:", "সার্চ:", "ওয়েবে খুঁজুন", "ওয়েবে খুঁজুন", "খুঁজে দাও"),
        ["সার্চের বিষয় যাচাই", "অনুমোদিত সার্চ টুল ব্যবহার", "ফলাফল যাচাই"],
    ),
    "code_help": (
        ("python", "কোড", "program", "প্রোগ্রাম", "debug", "ডিবাগ"),
        ["কোডের প্রয়োজন বুঝুন", "সমাধানের খসড়া তৈরি", "সমাধান পর্যালোচনা"],
    ),
}

class PostgresCursor:
    """Expose PostgreSQL results as dictionary-like rows."""

    def __init__(self, cursor):
        self._cursor = cursor

    @property
    def rowcount(self):
        return self._cursor.rowcount

    def _as_dict(self, row):
        if row is None:
            return None
        names = [column[0] for column in self._cursor.description]
        return dict(zip(names, row))

    def fetchone(self):
        return self._as_dict(self._cursor.fetchone())

    def fetchall(self):
        return [
            self._as_dict(row)
            for row in self._cursor.fetchall()
        ]


class PostgresConnection:
    """Preserve the existing SQLite-style query interface."""

    def __init__(self, connection):
        self._connection = connection

    def execute(self, sql, parameters=()):
        cursor = self._connection.cursor()
        cursor.execute(sql.replace("?", "%s"), parameters)
        return PostgresCursor(cursor)

    def commit(self):
        return self._connection.commit()

    def rollback(self):
        return self._connection.rollback()

    def close(self):
        return self._connection.close()


def connect_db():
    database_url = os.environ.get(
        "TASK_HISTORY_DATABASE_URL", ""
    ).strip()

    if database_url:
        import ssl
        from urllib.parse import unquote, urlparse
        import pg8000.dbapi

        parsed = urlparse(database_url)
        if parsed.scheme not in ("postgres", "postgresql"):
            raise ValueError("Invalid PostgreSQL database URL.")
        if not parsed.hostname or not parsed.path.strip("/"):
            raise ValueError("PostgreSQL URL is missing database details.")

        raw_connection = pg8000.dbapi.connect(
            user=unquote(parsed.username or ""),
            password=unquote(parsed.password or ""),
            host=parsed.hostname,
            port=parsed.port or 5432,
            database=unquote(parsed.path.lstrip("/")),
            ssl_context=ssl.create_default_context(),
            timeout=10,
        )
        connection = PostgresConnection(raw_connection)
        try:
            connection.execute("""
                CREATE TABLE IF NOT EXISTS tasks (
                    id TEXT PRIMARY KEY,
                    instruction TEXT NOT NULL,
                    task_type TEXT NOT NULL,
                    status TEXT NOT NULL,
                    plan_json TEXT NOT NULL,
                    created_at TEXT NOT NULL
                )
            """)
            connection.commit()
            return connection
        except Exception:
            connection.rollback()
            connection.close()
            raise

    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(DB_PATH, timeout=10)
    connection.row_factory = sqlite3.Row
    connection.execute("""
        CREATE TABLE IF NOT EXISTS tasks (
            id TEXT PRIMARY KEY,
            instruction TEXT NOT NULL,
            task_type TEXT NOT NULL,
            status TEXT NOT NULL,
            plan_json TEXT NOT NULL,
            created_at TEXT NOT NULL
        )
    """)
    return connection

def classify_instruction(instruction):
    text = instruction.casefold()
    for task_type, (keywords, _steps) in TASK_TYPES.items():
        if any(keyword.casefold() in text for keyword in keywords):
            return task_type
    return "ai_assistance"

def code_for(task_type, instruction=""):
    text = instruction.casefold()

    duplicate_keywords = (
        "ডুপ্লিকেট", "duplicate", "duplicates",
        "সদৃশ সারি", "একই সারি", "duplicate row",
    )

    if task_type != "file_cleaner":
        return None

    if not any(word in text for word in duplicate_keywords):
        return None

    return {
        "language": "python",
        "title": "CSV ডুপ্লিকেট সারি সরানোর কোড",
        "source": """import csv
from pathlib import Path

input_file = Path("input.csv")
output_file = Path("output_cleaned.csv")

with input_file.open("r", encoding="utf-8-sig", newline="") as source:
    reader = csv.DictReader(source)

    if reader.fieldnames is None:
        raise ValueError("CSV ফাইলে header নেই।")

    fieldnames = reader.fieldnames
    rows = list(reader)

seen = set()
unique_rows = []

for row in rows:
    # সব কলামের মান এক হলে সারিটিকে ডুপ্লিকেট ধরা হবে।
    key = tuple(row.get(name) or "" for name in fieldnames)

    if key not in seen:
        seen.add(key)
        unique_rows.append(row)

with output_file.open("w", encoding="utf-8", newline="") as target:
    writer = csv.DictWriter(target, fieldnames=fieldnames)
    writer.writeheader()
    writer.writerows(unique_rows)

print(f"মোট সারি: {len(rows)}")
print(f"রাখা হয়েছে: {len(unique_rows)}")
print(f"বাদ দেওয়া ডুপ্লিকেট: {len(rows) - len(unique_rows)}")
print(f"নতুন ফাইল: {output_file}")
""",
    }


def plan_for(task_type, instruction=""):
    text = instruction.casefold()

    if task_type == "file_cleaner":
        duplicate_keywords = (
            "ডুপ্লিকেট", "duplicate", "duplicates",
            "সদৃশ সারি", "একই সারি", "duplicate row",
        )

        if any(word in text for word in duplicate_keywords):
            steps = [
                "CSV ফাইল ও কলাম যাচাই",
                "ডুপ্লিকেট শনাক্ত করার নিয়ম নির্ধারণ",
                "ডুপ্লিকেট সারি শনাক্ত করার পরিকল্পনা তৈরি",
                "শনাক্তকরণের ফলাফল যাচাই",
            ]
        else:
            steps = [
                "CSV/XLSX ফাইল ও কলাম যাচাই",
                "পরিষ্কারের নিয়ম নির্ধারণ",
                "ফাঁকা, ভুল ও অপ্রয়োজনীয় ডেটা পরীক্ষা",
                "পরিষ্কারের ফলাফল যাচাই",
            ]
    elif task_type in TASK_TYPES:
        steps = TASK_TYPES[task_type][1]
    else:
        steps = [
            "নির্দেশ ও প্রয়োজন যাচাই",
            "সম্ভাব্য সমাধান পরিকল্পনা",
            "ফলাফল পর্যালোচনা",
        ]

    result = {
        "steps": steps,
        "execution": "planning_only",
        "requires_confirmation_for_sensitive_actions": True,
    }

    generated_code = code_for(task_type, instruction)
    if generated_code is not None:
        result["code"] = generated_code

    return result

def serialize_task(row):
    return {
        "id": row["id"],
        "instruction": row["instruction"],
        "task_type": row["task_type"],
        "status": row["status"],
        "plan": __import__("json").loads(row["plan_json"]),
        "created_at": row["created_at"],
    }

@automation_bp.post("/api/tasks/plan")
def create_task_plan():
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return jsonify({"error": "JSON নির্দেশ পাঠান।"}), 400

    instruction = data.get("instruction", "")
    if not isinstance(instruction, str):
        return jsonify({"error": "নির্দেশটি টেক্সট হতে হবে।"}), 400

    instruction = instruction.strip()
    if not instruction:
        return jsonify({"error": "কাজের নির্দেশ লিখুন।"}), 400
    if len(instruction) > 4000:
        return jsonify({"error": "নির্দেশ ৪০০০ অক্ষরের মধ্যে রাখুন।"}), 400

    task_type = classify_instruction(instruction)
    plan = plan_for(task_type, instruction)
    task_id = uuid.uuid4().hex
    created_at = datetime.now(timezone.utc).isoformat()

    connection = connect_db()
    try:
        connection.execute(
            """INSERT INTO tasks
               (id, instruction, task_type, status, plan_json, created_at)
               VALUES (?, ?, ?, ?, ?, ?)""",
            (
                task_id, instruction, task_type, "planned",
                __import__("json").dumps(plan, ensure_ascii=False),
                created_at,
            ),
        )
        connection.commit()
    finally:
        connection.close()

    return jsonify({
        "task": {
            "id": task_id,
            "instruction": instruction,
            "task_type": task_type,
            "status": "planned",
            "plan": plan,
            "created_at": created_at,
        },
        "message": "পরিকল্পনা তৈরি হয়েছে; কোনো কাজ এখনো চালানো হয়নি।",
    }), 201


@automation_bp.post("/api/agent/execute/<task_id>")
def execute_agent_task(task_id):
    if request.form.get("confirmed") != "yes":
        return jsonify({
            "error": "কাজ চালানোর আগে স্পষ্ট অনুমোদন দিতে হবে।"
        }), 400

    uploaded = request.files.get("file")
    if uploaded is None or not uploaded.filename:
        return jsonify({
            "error": "কাজ চালাতে একটি CSV বা XLSX ফাইল দিন।"
        }), 400

    # Atomically claim the task so concurrent requests cannot run it twice.
    connection = connect_db()
    try:
        row = connection.execute(
            "SELECT * FROM tasks WHERE id = ?", (task_id,)
        ).fetchone()

        if row is None:
            return jsonify({"error": "কাজটি পাওয়া যায়নি।"}), 404

        if row["task_type"] != "file_cleaner":
            return jsonify({
                "error": "এই কাজের জন্য এখনো অনুমোদিত execution tool নেই।"
            }), 400

        if row["status"] != "planned":
            return jsonify({
                "error": "শুধু planned অবস্থার কাজ একবার চালানো যাবে।",
                "status": row["status"],
            }), 409

        cursor = connection.execute(
            "UPDATE tasks SET status = 'running' "
            "WHERE id = ? AND status = 'planned'",
            (task_id,),
        )

        if cursor.rowcount != 1:
            connection.rollback()
            latest = connection.execute(
                "SELECT status FROM tasks WHERE id = ?", (task_id,)
            ).fetchone()
            return jsonify({
                "error": "কাজটি ইতিমধ্যে চালু হয়েছে বা স্ট্যাটাস বদলেছে।",
                "status": latest["status"] if latest else "not_found",
            }), 409

        connection.commit()
    finally:
        connection.close()

    try:
        # Reuse the existing, validated CSV/XLSX cleaner.
        from app import clean_file

        cleaner_response = clean_file()
        if isinstance(cleaner_response, tuple):
            response = cleaner_response[0]
            http_status = cleaner_response[1]
        else:
            response = cleaner_response
            http_status = 200

        result = response.get_json(silent=True) or {}
    except Exception:
        result = {"error": "কাজ চালানোর সময় একটি অভ্যন্তরীণ সমস্যা হয়েছে।"}
        http_status = 500

    connection = connect_db()
    try:
        row = connection.execute(
            "SELECT * FROM tasks WHERE id = ?", (task_id,)
        ).fetchone()

        if row is None:
            return jsonify({"error": "কাজের রেকর্ড পাওয়া যায়নি।"}), 404

        plan = __import__("json").loads(row["plan_json"])

        if http_status >= 400:
            plan["execution_result"] = {
                "status": "failed",
                "message": result.get("error", "ফাইল প্রসেস করা যায়নি।"),
            }
            new_status = "failed"
        else:
            plan["execution_result"] = {
                "status": "completed",
                "output": result.get("output"),
                "download_url": result.get("download_url"),
                "rows_kept": result.get("rows_kept"),
                "blank_rows_removed": result.get("blank_rows_removed"),
                "duplicate_rows_removed": result.get("duplicate_rows_removed"),
            }
            new_status = "completed"

        connection.execute(
            "UPDATE tasks SET status = ?, plan_json = ? WHERE id = ?",
            (
                new_status,
                __import__("json").dumps(plan, ensure_ascii=False),
                task_id,
            ),
        )
        connection.commit()
    finally:
        connection.close()

    if http_status >= 400:
        return jsonify({
            "error": result.get("error", "ফাইল প্রসেস করা যায়নি।"),
            "task_id": task_id,
            "status": "failed",
        }), http_status

    return jsonify({
        "message": "Agent-এর কাজ সম্পন্ন হয়েছে।",
        "task_id": task_id,
        "status": "completed",
        "result": result,
    }), 200


@automation_bp.get("/api/tasks/history")
def task_history():
    try:
        limit = int(request.args.get("limit", "20"))
    except (TypeError, ValueError):
        return jsonify({"error": "limit একটি সংখ্যা হতে হবে।"}), 400

    limit = max(1, min(limit, 100))
    connection = connect_db()
    try:
        rows = connection.execute(
            "SELECT * FROM tasks ORDER BY created_at DESC LIMIT ?",
            (limit,),
        ).fetchall()
        return jsonify({"tasks": [serialize_task(row) for row in rows]})
    finally:
        connection.close()

@automation_bp.get("/api/tasks/<task_id>")
def task_detail(task_id):
    connection = connect_db()
    try:
        row = connection.execute(
            "SELECT * FROM tasks WHERE id = ?", (task_id,)
        ).fetchone()
        if row is None:
            return jsonify({"error": "কাজটি পাওয়া যায়নি।"}), 404
        return jsonify({"task": serialize_task(row)})
    finally:
        connection.close()
