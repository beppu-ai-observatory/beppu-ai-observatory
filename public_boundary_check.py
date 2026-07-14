#!/usr/bin/env python3
"""公開専用リポジトリに非公開データや秘密情報が混入していないか検査する。"""

from __future__ import annotations

import argparse
import csv
import io
import re
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path, PurePosixPath


ALLOWED_EXACT_PATHS = {
    ".github/workflows/public-boundary-check.yml",
    "LICENSE",
    "LICENSE.md",
    "README.md",
    "free_questions.csv",
    "public_boundary_check.py",
    "questions_v6.csv",
    "tests/test_public_boundary_check.py",
}
RESULT_PATH_PATTERNS = (
    re.compile(
        r"results/[0-9]{4}-(?:0[1-9]|1[0-2])/"
        r"(?:README\.md|ranking\.md|summary\.csv)\Z"
    ),
    re.compile(
        r"results/[0-9]{4}-(?:0[1-9]|1[0-2])/corrections/"
        r"[0-9]{4}-(?:0[1-9]|1[0-2])-(?:0[1-9]|[12][0-9]|3[01])/"
        r"(?:CORRECTION\.md|ranking\.md|summary\.csv)\Z"
    ),
)

PRIVATE_BASENAME_PATTERNS = (
    re.compile(r"observation_.*\.csv\Z", re.IGNORECASE),
    re.compile(r"api-preflight.*\Z", re.IGNORECASE),
    re.compile(r"observe\.log\Z", re.IGNORECASE),
    re.compile(r"run_metadata\.json\Z", re.IGNORECASE),
    re.compile(r"reviewed_responses\.csv\Z", re.IGNORECASE),
    re.compile(r"reviewed_mentions\.csv\Z", re.IGNORECASE),
    re.compile(r"review_quality_warnings\.csv\Z", re.IGNORECASE),
    re.compile(r"aggregation_count_report\.csv\Z", re.IGNORECASE),
    re.compile(r"sources\.csv\Z", re.IGNORECASE),
    re.compile(r"question_labels\.csv\Z", re.IGNORECASE),
    re.compile(r"mentions\.csv\Z", re.IGNORECASE),
    re.compile(r"review_notes\.md\Z", re.IGNORECASE),
    re.compile(r"audit_report\.md\Z", re.IGNORECASE),
    re.compile(r"defects\.csv\Z", re.IGNORECASE),
    re.compile(r"review_state\.json\Z", re.IGNORECASE),
    re.compile(r"AI観測所_全質問回答確認用_.*\.xlsx\Z"),
)
PRIVATE_PATH_PARTS = {
    "incomplete",
    "observation_context",
    "post_aggregation_audit",
    "private-data",
    "raw",
    "reports",
    "run_evidence",
}
PRIVATE_CSV_COLUMNS = {
    "answer",
    "answer_sha256",
    "citation_urls",
    "completed_at",
    "decision",
    "decision_reason",
    "error",
    "executed_at",
    "mentions_complete",
    "needs_review",
    "raw_name",
    "request_id",
    "review_status",
    "self_reference",
    "unique_url_count",
    "urls",
}
QUESTION_SCHEMA = ("id", "category", "type", "question")
SUMMARY_SCHEMAS = {
    ("region", "category", "official_name", "engine", "model_id", "mention_count", "total_score"),
    (
        "region",
        "category",
        "official_name",
        "engine",
        "model_id",
        "mention_count",
        "total_score",
        "status",
    ),
}

SECRET_PATTERNS = (
    ("GitHub token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{30,}\b")),
    ("GitHub fine-grained token", re.compile(r"\bgithub_pat_[A-Za-z0-9_]{50,}\b")),
    ("OpenAI token", re.compile(r"\bsk-(?!ant-)(?:proj-|admin-)?[A-Za-z0-9_-]{20,}\b")),
    ("Anthropic token", re.compile(r"\bsk-ant-[A-Za-z0-9_-]{20,}\b")),
    ("Google API key", re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b")),
    ("xAI token", re.compile(r"\bxai-[A-Za-z0-9_-]{20,}\b")),
    ("AWS access key", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("private key", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----")),
    (
        "literal bearer token",
        re.compile(r"(?i)\bAuthorization\s*:\s*Bearer\s+[A-Za-z0-9._-]{20,}"),
    ),
)
SECRET_ASSIGNMENT = re.compile(
    r"(?i)\b(OPENAI_API_KEY|ANTHROPIC_API_KEY|GEMINI_API_KEY|XAI_API_KEY|"
    r"DATA_REPO_TOKEN|GITHUB_TOKEN)\b\s*[:=]\s*[\"']?([^\s\"']+)"
)
SAFE_ASSIGNMENT_PREFIXES = (
    "$",
    "${{",
    "secrets.",
    "<",
    "your_",
    "example",
    "dummy",
    "test",
    "redacted",
    "changeme",
    "read-",
)
URL_PATTERN = re.compile(r"(?i)(?:https?://|\bwww\.)")
MAX_PUBLIC_FILE_BYTES = 2_000_000


@dataclass(frozen=True, order=True)
class Finding:
    location: str
    label: str


def git(root: Path, *args: str) -> bytes:
    completed = subprocess.run(
        ["git", "-C", str(root), *args],
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    return completed.stdout


def tracked_paths(root: Path) -> list[str]:
    return [
        item.decode("utf-8", errors="surrogateescape")
        for item in git(root, "ls-files", "-z").split(b"\0")
        if item
    ]


def is_allowed_public_path(path: str) -> bool:
    return path in ALLOWED_EXACT_PATHS or any(
        pattern.fullmatch(path) for pattern in RESULT_PATH_PATTERNS
    )


def private_path_label(path: str) -> str | None:
    pure_path = PurePosixPath(path)
    if PRIVATE_PATH_PARTS.intersection(part.lower() for part in pure_path.parts[:-1]):
        return "private directory"
    for pattern in PRIVATE_BASENAME_PATTERNS:
        if pattern.fullmatch(pure_path.name):
            return "private filename"
    return None


def secret_labels(text: str) -> set[str]:
    labels = {label for label, pattern in SECRET_PATTERNS if pattern.search(text)}
    for match in SECRET_ASSIGNMENT.finditer(text):
        candidate = match.group(2).strip().lower()
        if len(candidate) >= 12 and not candidate.startswith(SAFE_ASSIGNMENT_PREFIXES):
            labels.add(f"literal {match.group(1).upper()}")
    return labels


def csv_header(text: str) -> tuple[str, ...] | None:
    try:
        header = next(csv.reader(io.StringIO(text.lstrip("\ufeff"))))
    except (StopIteration, csv.Error):
        return None
    return tuple(column.strip() for column in header)


def csv_policy_label(path: str, text: str) -> str | None:
    header = csv_header(text)
    if header is None:
        return "missing or invalid CSV header"
    if PRIVATE_CSV_COLUMNS.intersection(header):
        return "private CSV columns"
    if path in {"questions_v6.csv", "free_questions.csv"}:
        return None if header == QUESTION_SCHEMA else "unexpected question CSV schema"
    if PurePosixPath(path).name == "summary.csv":
        return None if header in SUMMARY_SCHEMAS else "unexpected public summary CSV schema"
    return "CSV path is not public"


def result_artifact_contains_url(path: str, text: str) -> bool:
    return path.startswith("results/") and bool(URL_PATTERN.search(text))


def scan_tracked_tree(root: Path) -> tuple[list[Finding], int]:
    findings: set[Finding] = set()
    paths = tracked_paths(root)
    for relative in paths:
        if not is_allowed_public_path(relative):
            findings.add(Finding(relative, "path is not on the public allowlist"))
        path_label = private_path_label(relative)
        if path_label:
            findings.add(Finding(relative, path_label))

        absolute = root / relative
        if absolute.is_symlink():
            findings.add(Finding(relative, "symbolic links are not allowed"))
            continue
        if not absolute.is_file():
            continue
        if absolute.stat().st_size > MAX_PUBLIC_FILE_BYTES:
            findings.add(Finding(relative, "public file exceeds size limit"))
            continue
        data = absolute.read_bytes()
        if b"\0" in data:
            findings.add(Finding(relative, "binary files are not allowed"))
            continue
        text = data.decode("utf-8", errors="replace")

        if absolute.suffix.lower() == ".csv":
            csv_label = csv_policy_label(relative, text)
            if csv_label:
                findings.add(Finding(relative, csv_label))
        if result_artifact_contains_url(relative, text):
            findings.add(Finding(relative, "URL found in public result artifact"))
        for line_number, line in enumerate(text.splitlines(), start=1):
            for secret_label in secret_labels(line):
                findings.add(Finding(f"{relative}:{line_number}", secret_label))
    return sorted(findings), len(paths)


def scan_history(root: Path) -> list[Finding]:
    """履歴に一度でも追加された秘密情報・非公開パス・非許可パスを検査する。"""
    findings: set[Finding] = set()
    current_commit = "unknown"
    names = git(
        root, "log", "--all", "--name-only", "--pretty=format:__COMMIT__%H"
    ).decode("utf-8", errors="replace")
    for line in names.splitlines():
        if line.startswith("__COMMIT__"):
            current_commit = line.removeprefix("__COMMIT__")
            continue
        path = line.strip()
        if not path:
            continue
        if not is_allowed_public_path(path):
            findings.add(
                Finding(f"history:{current_commit[:12]}:{path}", "path is not on the public allowlist")
            )
        label = private_path_label(path)
        if label:
            findings.add(Finding(f"history:{current_commit[:12]}:{path}", label))

    patch = git(
        root,
        "log",
        "--all",
        "--patch",
        "--unified=0",
        "--no-ext-diff",
        "--no-renames",
    ).decode("utf-8", errors="replace")
    current_path = "unknown"
    new_line = 0
    for line in patch.splitlines():
        if line.startswith("commit "):
            current_commit = line.split(maxsplit=1)[1]
        elif line.startswith("+++ b/"):
            current_path = line[6:]
        elif line.startswith("@@"):
            match = re.search(r"\+(\d+)", line)
            new_line = int(match.group(1)) if match else 0
        elif line.startswith("+") and not line.startswith("+++"):
            added = line[1:]
            for secret_label in secret_labels(added):
                findings.add(
                    Finding(
                        f"history:{current_commit[:12]}:{current_path}:{new_line}",
                        secret_label,
                    )
                )
            if current_path.startswith("results/") and URL_PATTERN.search(added):
                findings.add(
                    Finding(
                        f"history:{current_commit[:12]}:{current_path}:{new_line}",
                        "URL found in public result artifact",
                    )
                )
            new_line += 1
        elif not line.startswith("-"):
            new_line += 1
    return sorted(findings)


def print_findings(findings: list[Finding], *, scope: str) -> None:
    print(
        f"public_boundary_check failed scope={scope} findings={len(findings)}",
        file=sys.stderr,
    )
    for finding in findings:
        # 検出した秘密値や本文はログへ出さない。
        print(f"- {finding.location}: {finding.label}", file=sys.stderr)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parent)
    parser.add_argument("--history", action="store_true", help="Git履歴も検査する")
    args = parser.parse_args()
    root = args.root.resolve()

    findings, path_count = scan_tracked_tree(root)
    if findings:
        print_findings(findings, scope="tracked-tree")
        return 1
    print(f"public_boundary_check passed scope=tracked-tree tracked_files={path_count}")

    if args.history:
        history_findings = scan_history(root)
        if history_findings:
            print_findings(history_findings, scope="history")
            return 1
        print("public_boundary_check passed scope=history")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
