"""Read-only heuristic security checks for project source files."""
import re
from pathlib import Path

SECRET_PATTERNS = [
    (
        "সম্ভাব্য hardcoded API key",
        re.compile(
            r"""(?i)\b(?:api[_-]?key|access[_-]?token|client[_-]?secret)\b"""
            r"""\s*[:=]\s*['"]([^'"]{12,})['"]"""
        ),
    ),
    (
        "সম্ভাব্য private key",
        re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
    ),
]

RISK_PATTERNS = [
    (
        "সম্ভাব্য shell command injection ঝুঁকি",
        re.compile(r"\bsubprocess\.(?:run|Popen|call|check_call|check_output)\s*\("),
        re.compile(r"\bshell\s*=\s*True\b"),
        "shell=True ও ব্যবহারকারীর নিয়ন্ত্রিত input একসঙ্গে আছে কি না যাচাই করুন; সম্ভব হলে argument list ও shell=False ব্যবহার করুন।",
        "high",
    ),
    (
        "সম্ভাব্য dynamic code execution",
        re.compile(r"\b(?:eval|exec)\s*\("),
        None,
        "অবিশ্বস্ত input এখানে পৌঁছায় কি না যাচাই করুন; সম্ভব হলে নির্দিষ্ট parser বা allowlist ব্যবহার করুন।",
        "high",
    ),
    (
        "সম্ভাব্য SQL string interpolation",
        re.compile(r"\b(?:execute|executemany)\s*\("),
        re.compile(r"""(?:f['"]|\.format\s*\(|%\s*[\w(]|['"][^'"]*['"]\s*\+)"""),
        "SQL parameterized query ব্যবহার করুন; SQL string-এর সঙ্গে user input জোড়া লাগাবেন না।",
        "medium",
    ),
    (
        "সম্ভাব্য দুর্বল TLS যাচাই",
        re.compile(r"\bverify\s*=\s*False\b"),
        None,
        "TLS certificate যাচাই বন্ধ করবেন না, যদি না সীমিত ও নিয়ন্ত্রিত পরীক্ষার স্পষ্ট কারণ থাকে।",
        "medium",
    ),
]

SKIP_DIRS = {
    ".git", ".venv", "venv", "node_modules", "__pycache__",
    ".pytest_cache", "uploads", "results",
}
SKIP_SUFFIXES = {
    ".db", ".sqlite", ".sqlite3", ".pyc", ".pyo", ".bak",
}
SOURCE_SUFFIXES = {
    ".py", ".html", ".js", ".css", ".json", ".toml",
    ".ini", ".cfg", ".yml", ".yaml",
}
MAX_FILES = 500
MAX_FILE_BYTES = 200_000
MAX_TOTAL_BYTES = 1_500_000


def detect_security_issues(project_root):
    """Return heuristic findings without modifying or executing project files."""
    root = Path(project_root).resolve()
    findings = []
    scanned = 0
    skipped = 0
    file_count = 0

    def add(severity, title, relative, line_number, solution, detail):
        findings.append({
            "severity": severity,
            "title": title,
            "file": relative,
            "line": line_number,
            "detail": detail,
            "solution": solution,
            "confidence": "heuristic",
        })

    for path in sorted(root.rglob("*")):
        relative_path = path.relative_to(root)
        if any(part in SKIP_DIRS for part in relative_path.parts):
            continue
        if any(part.startswith(".env") for part in relative_path.parts):
            continue
        if path.is_symlink() or not path.is_file():
            continue
        if path.suffix.lower() in SKIP_SUFFIXES:
            continue
        if path.name.endswith((".backup", ".bak")):
            continue
        if path.suffix.lower() not in SOURCE_SUFFIXES:
            continue

        if file_count >= MAX_FILES:
            break
        file_count += 1

        try:
            size = path.stat().st_size
            if size > MAX_FILE_BYTES or scanned + size > MAX_TOTAL_BYTES:
                skipped += 1
                continue
            content = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            skipped += 1
            continue

        scanned += size
        lines = content.splitlines()

        # Report secret-like values by location only; never return the matched value.
        for line_number, line in enumerate(lines, 1):
            if re.search(r"(?i)\b(?:example|sample|placeholder|your[_ -]?key|changeme)\b", line):
                continue
            for title, pattern in SECRET_PATTERNS:
                if pattern.search(line):
                    add(
                        "high", title, relative_path.as_posix(), line_number,
                        "সন্দেহজনক মানটি গোপন রাখুন; exposed হলে provider থেকে key rotate করুন এবং environment variable/secret manager ব্যবহার করুন।",
                        "কোডে secret-এর মতো মান পাওয়া গেছে; প্রকৃত secret কি না ম্যানুয়ালি যাচাই করুন।",
                    )
                    break

        # Multi-line context is required for subprocess shell=True checks.
        for index, line in enumerate(lines):
            line_number = index + 1
            window = "\n".join(lines[index:index + 8])

            for title, call_pattern, context_pattern, solution, severity in RISK_PATTERNS:
                if not call_pattern.search(line):
                    continue
                if context_pattern is not None:
                    if not context_pattern.search(window):
                        continue
                add(
                    severity, title, relative_path.as_posix(), line_number,
                    solution,
                    "ঝুঁকিপূর্ণ API বা query তৈরির pattern শনাক্ত হয়েছে; surrounding code দেখে নিশ্চিত করুন।",
                )

    # Deduplicate exact findings while preserving order.
    unique = []
    seen = set()
    for finding in findings:
        key = (finding["title"], finding["file"], finding["line"])
        if key not in seen:
            seen.add(key)
            unique.append(finding)

    return {
        "status": "ok",
        "read_only": True,
        "analysis_type": "heuristic_static_analysis",
        "summary": {
            "issues_found": len(unique),
            "files_scanned": file_count,
            "source_bytes_scanned": scanned,
            "files_skipped": skipped,
        },
        "findings": unique,
        "notice": (
            "এটি সম্ভাব্য pattern শনাক্ত করে; নিশ্চিত vulnerability নির্ধারণ করে না। "
            "স্ক্যানার কোনো project code চালায় বা পরিবর্তন করে না।"
        ),
    }
