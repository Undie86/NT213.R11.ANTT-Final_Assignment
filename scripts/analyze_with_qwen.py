import argparse
import hashlib
import json
import os
import time
import requests

# ============================================================
# CONFIG
# ============================================================

PROJECT_DIR = r"C:\Users\PC\Documents\T07-sardjuliet"
INPUT_DIR = os.path.join(PROJECT_DIR, "data", "clean")
OUTPUT_DIR = os.path.join(PROJECT_DIR, "results")

BASE_URL = "http://127.0.0.1:8080"
API_URL = f"{BASE_URL}/v1/chat/completions"
MODEL = "Qwen3.6-40B"
REQUEST_TIMEOUT = 1800
MAX_RETRIES = 3
MAX_CODE_CHARS = 50000
TEMPERATURE = 0.1
MAX_TOKENS = 1000

CATEGORIES = ["sqli", "xss", "cmdi"]
LANGUAGES = ["java", "php", "c#"]

# ============================================================
# SYSTEM PROMPT
# ============================================================

SYSTEM_PROMPT = """
You are a source-code vulnerability analyst.

Determine whether the specified CWE is actually exploitable from the provided code.

Analyze actual code semantics and reachable execution paths.
Do not trust dataset labels, comments, filenames, variable names, or function names.

Check:
- attacker-controlled input
- reachable dataflow
- dangerous sink
- validation or sanitization
- language semantics and control flow

CWE rules:
- SQL injection: attacker input must alter SQL syntax or semantics at an execution sink.
- Command injection: attacker input must alter or inject OS commands at an execution sink.
- XSS: attacker input must reach a browser context without effective context-appropriate encoding.

Return exactly one JSON object:

{
  "vulnerable": true,
  "confidence": 0.0,
  "reason": ""
}

Rules:
- vulnerable must be true or false.
- confidence must be between 0.0 and 1.0.
- reason must be at most 2 short sentences.
- Explain only the decisive dataflow or semantic reason.
- Do not discuss unrelated good methods or alternative implementations.
- Do not repeat the source code.
- Do not use Markdown.
- Do not include text before or after the JSON object.
"""
# ============================================================
# SERVER
# ============================================================


def check_server():
    try:
        response = requests.get(f"{BASE_URL}/health", timeout=10)
        return response.status_code == 200
    except requests.RequestException:
        return False


# ============================================================
# JSONL
# ============================================================


def load_jsonl(path):
    with open(path, "r", encoding="utf-8") as f:
        for line_number, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue
            try:
                yield json.loads(line)
            except json.JSONDecodeError:
                print(f"[WARN] Invalid JSON: {path}:{line_number}")


def append_jsonl(path, record):
    with open(path, "a", encoding="utf-8", buffering=1024 * 1024) as f:
        f.write(
            json.dumps(record, ensure_ascii=False, separators=(",", ":"))
            + "\n"
        )


# ============================================================
# FIND INPUT FILES
# ============================================================


def find_input_files():
    files = []
    for language in LANGUAGES:
        language_dir = os.path.join(INPUT_DIR, language)
        if not os.path.isdir(language_dir):
            print(f"[WARN] Language directory not found: {language_dir}")
            continue

        for category in CATEGORIES:
            path = os.path.join(language_dir, f"{category}.jsonl")
            if os.path.isfile(path):
                files.append(
                    {"language": language, "category": category, "path": path}
                )
    return files


# ============================================================
# SAMPLE KEY
# ============================================================


def make_sample_key(record, language, category):
    sample_id = record.get("id")
    if sample_id is None:
        code = record.get("code", "")
        sample_id = hashlib.sha256(code.encode("utf-8")).hexdigest()
    return f"{language}:{category}:{sample_id}"


# ============================================================
# BUILD PROMPT
# ============================================================


def build_prompt(record):
    cwe = record.get("cwe", "")
    language = record.get("language", "")
    code = record.get("code", "")

    if len(code) > MAX_CODE_CHARS:
        code = code[:MAX_CODE_CHARS]

    return f"""
CWE:
{cwe}
Language:
{language}
Source code:
{code}
Analyze whether the specified CWE is actually exploitable.
Return JSON only.
"""


# ============================================================
# JSON EXTRACTION
# ============================================================


def extract_json(text):
    text = text.strip()

    if text.startswith("```"):
        lines = text.splitlines()[1:]
        if lines and lines[-1].strip().startswith("```"):
            lines = lines[:-1]
        text = "\n".join(lines).strip()

    try:
        return json.loads(text)
    except json.JSONDecodeError:
        pass

    start = text.find("{")
    end = text.rfind("}")
    if start >= 0 and end > start:
        candidate = text[start : end + 1]
        try:
            return json.loads(candidate)
        except json.JSONDecodeError:
            pass

    return None


# ============================================================
# VALIDATE MODEL OUTPUT
# ============================================================


def validate_analysis(parsed):
    if not isinstance(parsed, dict):
        return False

    required_keys = {"vulnerable", "confidence", "reason"}
    if not required_keys.issubset(parsed.keys()):
        return False

    if not isinstance(parsed["vulnerable"], bool):
        return False

    if not isinstance(parsed["confidence"], (int, float)):
        return False

    if not isinstance(parsed["reason"], str):
        return False

    return True


# ============================================================
# CALL QWEN
# ============================================================


def call_qwen(record):
    prompt = build_prompt(record)
    payload = {
        "model": MODEL,
        "messages": [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": prompt},
        ],
        "temperature": TEMPERATURE,
        "max_tokens": MAX_TOKENS,
        "stream": False,
        "chat_template_kwargs": {"enable_thinking": False},
    }

    last_error = None

    for attempt in range(1, MAX_RETRIES + 1):
        try:
            response = requests.post(
                API_URL, json=payload, timeout=REQUEST_TIMEOUT
            )
            response.raise_for_status()

            result = response.json()
            choices = result.get("choices", [])
            if not choices:
                raise RuntimeError("No choices returned")

            message = choices[0].get("message", {})
            content = (message.get("content") or "").strip()
            if not content:
                raise RuntimeError("Empty model response")

            parsed = extract_json(content)
            if parsed is None:
                raise RuntimeError("Invalid JSON response")

            if not validate_analysis(parsed):
                raise RuntimeError("Invalid analysis schema")

            return {"analysis": parsed, "raw_output": content}

        except Exception as e:
            last_error = str(e)
            print(f"  RETRY {attempt}/{MAX_RETRIES}: {last_error}")
            if attempt < MAX_RETRIES:
                time.sleep(3 * attempt)

    raise RuntimeError(last_error)


# ============================================================
# RESUME
# ============================================================


def load_completed(path):
    completed = set()
    if not os.path.isfile(path):
        return completed

    for record in load_jsonl(path):
        key = record.get("_sample_key")
        if key:
            completed.add(key)

    return completed


# ============================================================
# PROCESS FILE
# ============================================================


def process_file(input_info, stats):
    language = input_info["language"]
    category = input_info["category"]
    input_path = input_info["path"]

    output_name = f"{language}_{category}_analysis.jsonl"
    error_name = f"{language}_{category}_errors.jsonl"

    output_path = os.path.join(OUTPUT_DIR, output_name)
    error_path = os.path.join(OUTPUT_DIR, error_name)

    completed = load_completed(output_path)

    print("\n" + "=" * 70)
    print(f"LANGUAGE: {language}")
    print(f"CATEGORY: {category}")
    print(f"INPUT   : {input_path}")
    print(f"OUTPUT  : {output_path}")
    print(f"RESUME  : {len(completed):,}")
    print("=" * 70)

    local_total = 0
    local_done = 0
    local_failed = 0

    for record in load_jsonl(input_path):
        local_total += 1
        stats["total"] += 1

        key = make_sample_key(record, language, category)
        if key in completed:
            stats["skipped"] += 1
            continue

        sample_id = record.get("id", "unknown")
        print(f"[{language}/{category}] {sample_id}")

        start = time.time()

        try:
            result = call_qwen(record)
            elapsed = time.time() - start

            output_record = {
                "_sample_key": key,
                "id": record.get("id"),
                "suite_id": record.get("suite_id"),
                "language": language,
                "cwe": record.get("cwe"),
                "category": category,
                "label": record.get("label"),
                "state": record.get("state"),
                "file": record.get("file"),
                "llm_analysis": result["analysis"],
                "llm_meta": {
                    "model": MODEL,
                    "elapsed_seconds": round(elapsed, 3),
                },
            }

            append_jsonl(output_path, output_record)
            completed.add(key)

            local_done += 1
            stats["processed"] += 1

            vulnerable = result["analysis"]["vulnerable"]
            if vulnerable:
                stats["llm_vulnerable"] += 1
            else:
                stats["llm_safe"] += 1

            print(f"  OK {elapsed:.1f}s vulnerable={vulnerable}")

        except KeyboardInterrupt:
            print("\nInterrupted by user.")
            raise

        except Exception as e:
            local_failed += 1
            stats["failed"] += 1

            error_record = {
                "_sample_key": key,
                "id": sample_id,
                "language": language,
                "category": category,
                "error": str(e),
            }

            append_jsonl(error_path, error_record)
            print(f"  ERROR: {e}")

    print(f"\nFINISHED {language}/{category}")
    print(f"READ   : {local_total:,}")
    print(f"DONE   : {local_done:,}")
    print(f"FAILED : {local_failed:,}")


# ============================================================
# MAIN
# ============================================================


def main():
    parser = argparse.ArgumentParser(
        description="Analyze clean CWE dataset using local Qwen"
    )
    parser.add_argument(
        "--category", choices=["sqli", "xss", "cmdi", "all"], default="all"
    )
    parser.add_argument(
        "--language", choices=["java", "php", "c#", "all"], default="all"
    )

    args = parser.parse_args()

    os.makedirs(OUTPUT_DIR, exist_ok=True)

    print("\n" + "=" * 70)
    print("QWEN CWE ANALYSIS")
    print("=" * 70)
    print(f"Server     : {BASE_URL}")
    print(f"Model      : {MODEL}")
    print(f"Input      : {INPUT_DIR}")
    print(f"Output     : {OUTPUT_DIR}")
    print(f"Max chars  : {MAX_CODE_CHARS}")
    print(f"Max tokens : {MAX_TOKENS}")
    print("=" * 70)

    if not check_server():
        print(f"\nERROR: llama-server is offline\nExpected: {API_URL}")
        return

    print("\nllama-server: ONLINE")

    input_files = find_input_files()

    if args.category != "all":
        input_files = [
            item for item in input_files if item["category"] == args.category
        ]

    if args.language != "all":
        input_files = [
            item for item in input_files if item["language"] == args.language
        ]

    if not input_files:
        print("No input files found.")
        return

    print("\nINPUT FILES:")
    for item in input_files:
        print(f"  [{item['language']}] {item['path']}")

    stats = {
        "total": 0,
        "processed": 0,
        "skipped": 0,
        "failed": 0,
        "llm_vulnerable": 0,
        "llm_safe": 0,
    }

    started = time.time()

    try:
        for input_info in input_files:
            process_file(input_info, stats)
    except KeyboardInterrupt:
        print("\nStopped safely.\nRun again to resume.")

    elapsed = time.time() - started
    stats["elapsed_seconds"] = round(elapsed, 3)
    stats["samples_per_hour"] = (
        round((stats["processed"] / elapsed * 3600), 2) if elapsed > 0 else 0
    )

    stats_path = os.path.join(OUTPUT_DIR, "analysis_stats.json")
    with open(stats_path, "w", encoding="utf-8") as f:
        json.dump(stats, f, ensure_ascii=False, indent=2)

    print("\n" + "=" * 70)
    print("ANALYSIS COMPLETE")
    print("=" * 70)
    print(json.dumps(stats, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()