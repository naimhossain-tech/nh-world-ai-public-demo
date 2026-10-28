"""Read-only project analysis for Naim AI Work Agent."""
import re
import hmac
from pathlib import Path

from flask import Blueprint, jsonify, request
from security_detector import detect_security_issues
import os
import subprocess
import sys
import threading

project_intelligence_bp = Blueprint("project_intelligence", __name__)

PROJECT_ROOT = Path(__file__).resolve().parent
SKIP_DIRS = {
    ".venv", "venv", ".git", "uploads", "results",
    "__pycache__", "node_modules", ".pytest_cache",
}
SKIP_SUFFIXES = {
    ".db", ".sqlite", ".sqlite3", ".pyc", ".pyo",
}
SOURCE_SUFFIXES = {
    ".py", ".html", ".js", ".css", ".json", ".toml",
    ".ini", ".cfg", ".txt", ".md", ".yml", ".yaml",
}
MAX_FILES = 500
MAX_FILE_BYTES = 200_000
MAX_TOTAL_BYTES = 1_500_000


def analyze_project():
    """Inventory source files and report static findings without writing files."""
    files = []
    routes = []
    blueprints = set()
    test_files = []
    findings = []
    skipped_large = 0
    total_bytes = 0

    for path in sorted(PROJECT_ROOT.rglob("*")):
        relative = path.relative_to(PROJECT_ROOT)
        parts = relative.parts

        if any(part in SKIP_DIRS for part in parts):
            continue
        if any(part.startswith(".env") for part in parts):
            continue
        if path.is_symlink() or not path.is_file():
            continue
        if path.suffix.lower() in SKIP_SUFFIXES:
            continue
        if path.name.endswith((".bak", ".backup")):
            continue
        if len(files) >= MAX_FILES:
            findings.append({
                "severity": "info",
                "title": "ফাইল স্ক্যানের সীমা",
                "detail": f"নিরাপত্তার জন্য সর্বোচ্চ {MAX_FILES}টি ফাইল নেওয়া হয়েছে।",
                "solution": "বড় প্রজেক্ট হলে স্ক্যানের সীমা পর্যালোচনা করুন।",
            })
            break

        item = {
            "path": relative.as_posix(),
            "extension": path.suffix.lower() or "(extension নেই)",
            "size_bytes": path.stat().st_size,
        }
        files.append(item)

        if path.name.startswith("test_") or path.name.endswith("_test.py"):
            test_files.append(relative.as_posix())

        if path.suffix.lower() not in SOURCE_SUFFIXES:
            continue
        if item["size_bytes"] > MAX_FILE_BYTES:
            skipped_large += 1
            continue
        if total_bytes + item["size_bytes"] > MAX_TOTAL_BYTES:
            skipped_large += 1
            continue

        try:
            content = path.read_text(encoding="utf-8")
        except (UnicodeDecodeError, OSError):
            continue

        total_bytes += item["size_bytes"]
        for line_number, line in enumerate(content.splitlines(), start=1):
            route_match = re.search(
                r"""@\s*(?:app|[A-Za-z_]\w*)\.(?:route|get|post|put|delete|patch)\s*\(\s*(['"])(.*?)\1""",
                line,
            )
            if route_match and path.suffix.lower() == ".py":
                routes.append({
                    "file": relative.as_posix(),
                    "line": line_number,
                    "rule": route_match.group(2),
                })

            if re.search(r"\bregister_blueprint\s*\(", line):
                blueprints.add(relative.as_posix())

            if re.search(r"\bTODO\b|\bFIXME\b", line, re.IGNORECASE):
                findings.append({
                    "severity": "info",
                    "title": "অসমাপ্ত কাজের চিহ্ন",
                    "detail": f"{relative.as_posix()}:{line_number}-এ TODO/FIXME আছে।",
                    "solution": "কাজটি এখনও প্রয়োজন কি না যাচাই করে টেস্ট ও সমাধান যোগ করুন।",
                })

            if re.match(r"^\s*except\s*:", line):
                findings.append({
                    "severity": "warning",
                    "title": "অতিরিক্ত বিস্তৃত exception",
                    "detail": f"{relative.as_posix()}:{line_number}-এ bare except পাওয়া গেছে।",
                    "solution": "সম্ভব হলে নির্দিষ্ট exception ধরুন এবং প্রয়োজনীয় error log রাখুন।",
                })

    if not test_files:
        findings.append({
            "severity": "warning",
            "title": "টেস্ট ফাইল পাওয়া যায়নি",
            "detail": "স্ক্যান করা প্রজেক্টে প্রচলিত নামের কোনো টেস্ট ফাইল পাওয়া যায়নি।",
            "solution": "প্রধান API, CSV Cleaner এবং Task History-এর automated test যোগ করুন।",
        })

    if not routes:
        findings.append({
            "severity": "info",
            "title": "Route শনাক্ত হয়নি",
            "detail": "সাধারণ route decorator থেকে কোনো endpoint শনাক্ত করা যায়নি।",
            "solution": "Flask route declaration-এর ধরন ম্যানুয়ালি যাচাই করুন।",
        })

    return {
        "status": "ok",
        "read_only": True,
        "project": PROJECT_ROOT.name,
        "summary": {
            "files_found": len(files),
            "routes_found": len(routes),
            "blueprint_registration_files": len(blueprints),
            "test_files_found": len(test_files),
            "findings_found": len(findings),
            "source_bytes_scanned": total_bytes,
            "large_or_over_limit_files_skipped": skipped_large,
        },
        "files": files,
        "routes": routes,
        "blueprint_registration_files": sorted(blueprints),
        "test_files": sorted(test_files),
        "findings": findings,
        "limits": {
            "max_files": MAX_FILES,
            "max_file_bytes": MAX_FILE_BYTES,
            "max_total_source_bytes": MAX_TOTAL_BYTES,
        },
    }


@project_intelligence_bp.post("/api/project-intelligence/scan")
def scan_project():
    """Return a fresh read-only project report."""
    try:
        return jsonify(analyze_project())
    except OSError:
        return jsonify({
            "status": "error",
            "message": "প্রজেক্ট স্ক্যান করতে ফাইল-সিস্টেম সমস্যা হয়েছে।",
        }), 500


@project_intelligence_bp.post("/api/project-intelligence/security-scan")
def scan_security():
    """Run read-only heuristic security checks on this project."""
    try:
        report = detect_security_issues(PROJECT_ROOT)
        return jsonify(report)
    except OSError:
        return jsonify({
            "status": "error",
            "message": "নিরাপত্তা স্ক্যান করতে ফাইল-সিস্টেম সমস্যা হয়েছে।",
        }), 500


_TEST_RUN_LOCK = threading.Lock()

@project_intelligence_bp.post("/api/project-intelligence/test-run")
def run_project_tests():
    """Run a fixed allowlist of unit tests after server-side token validation."""
    if os.environ.get("NH_ENABLE_TEST_RUNNER") != "1":
        return jsonify({
            "status": "disabled",
            "message": "সার্ভারে Test Runner সক্রিয় করা নেই।",
        }), 403

    expected_token = os.environ.get("NH_TEST_RUNNER_TOKEN", "")
    supplied_token = request.headers.get("X-NH-Test-Token", "")

    if len(expected_token) < 32 or not supplied_token:
        return jsonify({
            "status": "forbidden",
            "message": "অনুমতি যাচাই করা যায়নি। সার্ভার token সেটিং পরীক্ষা করুন।",
        }), 403

    if not hmac.compare_digest(supplied_token, expected_token):
        return jsonify({
            "status": "forbidden",
            "message": "Token সঠিক নয়।",
        }), 403

    if not _TEST_RUN_LOCK.acquire(blocking=False):
        return jsonify({
            "status": "busy",
            "message": "একটি Test Run ইতিমধ্যে চলছে।",
        }), 409

    try:
        result = subprocess.run(
            [
                sys.executable, "-m", "unittest", "-v",
                "test_app.py", "test_cleaner.py", "test_auth.py",
                "test_security_api.py", "test_security_detector.py",
            ],
            cwd=PROJECT_ROOT,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=60,
            shell=False,
            check=False,
        )
        output = (result.stdout + "\n" + result.stderr).strip()
        match = re.search(r"Ran\s+(\d+)\s+tests?\s+in\s+([\d.]+)s", output)
        return jsonify({
            "status": "completed" if result.returncode == 0 else "failed",
            "passed": result.returncode == 0,
            "exit_code": result.returncode,
            "tests_run": int(match.group(1)) if match else None,
            "duration_seconds": float(match.group(2)) if match else None,
            "output": output[-12000:],
        })
    except subprocess.TimeoutExpired:
        return jsonify({
            "status": "timeout",
            "passed": False,
            "message": "টেস্ট চালাতে ৬০ সেকেন্ডের বেশি সময় লেগেছে।",
        }), 200
    except OSError:
        return jsonify({
            "status": "error",
            "passed": False,
            "message": "সার্ভারে টেস্ট চালানো যায়নি।",
        }), 500
    finally:
        _TEST_RUN_LOCK.release()
