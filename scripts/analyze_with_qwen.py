import os
import json
import time
import argparse
import requests


PROJECT_DIR = r"C:\Users\PC\Documents\T07-sardjuliet"

INPUT_DIRS = [
    os.path.join(PROJECT_DIR, "data", "processed", "sard_php"),
    os.path.join(PROJECT_DIR, "data", "processed", "juliet_cpp"),
]

OUTPUT_DIR = os.path.join(PROJECT_DIR, "results")

BASE_URL = "http://127.0.0.1:8080"
API_URL = f"{BASE_URL}/v1/chat/completions"

MODEL = "Qwen3.6-40B"

REQUEST_TIMEOUT = 1800
MAX_RETRIES = 3

# Giới hạn kích thước source gửi vào model.
# 50k ký tự ~ phù hợp cho hầu hết sample SARD/Juliet.
MAX_CODE_CHARS = 50000

TEMPERATURE = 0.1

# Chỉ yêu cầu JSON ngắn nên 1000 token là đủ.
MAX_TOKENS = 1000


SYSTEM_PROMPT = r"""
You are a source-code vulnerability analysis expert.

Analyze the provided source code for the specified CWE.

Your goal is to determine whether the specified vulnerability is actually exploitable by understanding the actual code semantics and execution flow, rather than relying only on function names, variable names, dataset labels, comments, or suspicious source-to-sink patterns.

Determine exploitability based only on the provided source code.

Return exactly one valid JSON object:

{
  "vulnerable": true,
  "confidence": 0.0,
  "reason": "",
  "evidence": []
}

Rules:

- "vulnerable" is true only if the specified CWE is actually exploitable through a reachable execution path.
- Do not assume code is vulnerable or safe because of dataset labels, CWE metadata, comments, function names, variable names, or suspicious patterns.
- Analyze actual language semantics and execution flow.
- Respect the semantics of the specified programming language.
- A source-to-sink pattern alone does not mean the code is vulnerable.
- Check whether attacker-controlled input can actually reach and exploit the sink.
- Consider assignments, transformations, validation, type checks, branches, early returns, exceptions, fatal errors, and other control-flow conditions.
- Analyze what operations and functions actually do, not what their names suggest.
- Do not treat a variable as safe because its name contains words such as "sanitized", "safe", or "clean".
- Do not treat a function as safe because its name sounds like a sanitizer or validator.
- If a function is unknown and its implementation is not provided, treat its behavior as unknown.
- Do not invent the behavior of custom, undefined, or non-standard functions.
- If exploitability depends on unknown code, explain the uncertainty and reduce confidence appropriately.

Language-specific rules:

- For PHP, analyze actual runtime types, HTTP request parameter types, arrays, implicit conversions, explicit conversions, and PHP control-flow semantics.
- Do not assume a numeric-looking HTTP parameter is automatically an integer.
- Distinguish strict type checking from numeric parsing or validation.
- For C and C++, analyze pointers, references, arrays, object fields, function calls, constructors, destructors, inheritance, namespaces, and interprocedural data flow when the relevant code is provided.
- Track attacker-controlled data through function parameters, return values, references, pointers, objects, and class members when possible.
- Do not apply PHP semantics to C/C++ code.
- Do not apply C/C++ semantics to PHP code.

Dataflow rules:

- Determine whether attacker-controlled data has an actual reachable execution path to the dangerous sink.
- A syntactic source-to-sink relationship is not automatically a reachable dataflow.
- If a validation, type check, branch, early return, exception, fatal error, or other condition prevents attacker-controlled input from reaching the sink, the vulnerability is not exploitable through that path.
- If the sink is reachable but attacker-controlled input cannot alter the relevant command, query, or dangerous context, do not mark the code vulnerable.
- If relevant code required to determine exploitability is missing, do not invent it.

CWE-specific rules:

- For SQL injection, determine whether attacker-controlled input can alter SQL syntax or SQL semantics at the actual SQL execution sink.
- For command injection, determine whether attacker-controlled input can alter or inject operating system commands at the command execution sink.
- For cross-site scripting, determine whether attacker-controlled input can reach a browser output context without effective context-appropriate encoding or escaping.
- Do not assume HTML escaping protects SQL or command execution.
- Do not assume URL encoding protects SQL or command execution.
- Do not assume Base64 encoding automatically protects any dangerous sink.
- Analyze the actual transformation and the exact sink context.

Output rules:

- "reason" must be short, maximum 3 sentences.
- Explain the actual semantic or control-flow reason for the decision.
- "evidence" must be an array containing only the most important exact code snippets supporting the decision.
- Do not modify, normalize, summarize, or invent code evidence.
- Confidence should reflect semantic certainty, not pattern matching.

Do not include Markdown fences.
Do not include any text before or after the JSON object.
"""


def check_server():
    try:
        response = requests.get(
            f"{BASE_URL}/health",
            timeout=10,
        )
        return response.status_code == 200

    except requests.RequestException:
        return False


def load_jsonl(path):
    with open(path, "r", encoding="utf-8") as f:
        for line_number, line in enumerate(f, 1):
            line = line.strip()

            if not line:
                continue

            try:
                yield json.loads(line)

            except json.JSONDecodeError as e:
                print(
                    f"[WARN] Invalid JSON: "
                    f"{path}:{line_number}: {e}"
                )


def find_input_files():
    files = []

    for directory in INPUT_DIRS:
        if not os.path.isdir(directory):
            print(f"[WARN] Input directory not found: {directory}")
            continue

        for name in [
            "sqli.jsonl",
            "xss.jsonl",
            "cmdi.jsonl",
        ]:
            path = os.path.join(directory, name)

            if os.path.isfile(path):
                files.append(path)

    return files


def get_category(path):
    return os.path.splitext(
        os.path.basename(path)
    )[0]


def get_dataset(path):
    normalized = os.path.normpath(path).lower()

    if "\\sard_php\\" in normalized:
        return "sard_php"

    if "\\juliet_cpp\\" in normalized:
        return "juliet_cpp"

    return "unknown"


def make_sample_key(record, dataset, category):
    sample_id = record.get("id")

    if sample_id is None:
        sample_id = record.get("test_id")

    if sample_id is None:
        sample_id = record.get("relative_path")

    if sample_id is None:
        # hash() thay đổi giữa các Python process.
        # Dùng SHA-256 để resume ổn định.
        import hashlib

        sample_id = hashlib.sha256(
            record.get("code", "").encode("utf-8")
        ).hexdigest()

    return f"{dataset}:{category}:{sample_id}"


def build_prompt(record):
    cwe = record.get("cwe", "")
    language = record.get("language", "")
    code = record.get("code", "")

    if len(code) > MAX_CODE_CHARS:
        code = code[:MAX_CODE_CHARS]

    numbered_code = "\n".join(
        f"{line_number:05d} | {line}"
        for line_number, line in enumerate(
            code.splitlines(),
            1,
        )
    )

    return f"""
Analyze the following source code.

Specified CWE:
{cwe}

Programming language:
{language}

Source code:
```text
{numbered_code}
```

Determine whether the specified CWE is actually exploitable from the code itself.
Do not trust dataset metadata, comments, labels, names, or patterns as proof.
Return the required JSON only.
"""


def extract_json(text):
    text = text.strip()

    if text.startswith("```"):
        lines = text.splitlines()

        if lines:
            lines = lines[1:]

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
        candidate = text[start:end + 1]

        try:
            return json.loads(candidate)

        except json.JSONDecodeError:
            pass

    return None


def validate_analysis(parsed):
    if not isinstance(parsed, dict):
        return False

    required_keys = {
        "vulnerable",
        "confidence",
        "reason",
        "evidence",
    }

    if not required_keys.issubset(parsed.keys()):
        return False

    if not isinstance(parsed["vulnerable"], bool):
        return False

    if not isinstance(
        parsed["confidence"],
        (int, float),
    ):
        return False

    if not isinstance(parsed["reason"], str):
        return False

    if not isinstance(parsed["evidence"], list):
        return False

    return True


def call_qwen(record):
    prompt = build_prompt(record)

    payload = {
        "model": MODEL,
        "messages": [
            {
                "role": "system",
                "content": SYSTEM_PROMPT,
            },
            {
                "role": "user",
                "content": prompt,
            },
        ],
        "temperature": TEMPERATURE,
        "max_tokens": MAX_TOKENS,
        "stream": False,
        "chat_template_kwargs": {
            "enable_thinking": False,
        },
    }

    last_error = None

    for attempt in range(1, MAX_RETRIES + 1):
        try:
            response = requests.post(
                API_URL,
                json=payload,
                timeout=REQUEST_TIMEOUT,
            )

            response.raise_for_status()

            result = response.json()
            choices = result.get("choices", [])

            if not choices:
                raise RuntimeError(
                    "No choices returned by llama-server"
                )

            choice = choices[0]
            message = choice.get("message", {})

            content = (
                message.get("content") or ""
            ).strip()

            finish_reason = choice.get(
                "finish_reason",
                "unknown",
            )

            if not content:
                raise RuntimeError(
                    "Empty model response "
                    f"(finish_reason={finish_reason})"
                )

            parsed = extract_json(content)

            if parsed is None:
                preview = content[:500].replace(
                    "\n",
                    " ",
                )
                print(
                    f"  [DEBUG] Invalid JSON preview: "
                    f"{preview}"
                )
                raise RuntimeError(
                    "Model returned invalid JSON"
                )

            if not validate_analysis(parsed):
                raise RuntimeError(
                    "Model JSON does not match "
                    "required schema"
                )

            return {
                "analysis": parsed,
                "raw_output": content,
            }

        except Exception as e:
            last_error = str(e)

            print(
                f"  [RETRY {attempt}/{MAX_RETRIES}] "
                f"{last_error}"
            )

            if attempt < MAX_RETRIES:
                time.sleep(3 * attempt)

    raise RuntimeError(last_error)


def load_completed(path):
    completed = set()

    if not os.path.isfile(path):
        return completed

    for record in load_jsonl(path):
        key = record.get("_sample_key")

        if key:
            completed.add(key)

    return completed


def append_jsonl(path, record):
    with open(
        path,
        "a",
        encoding="utf-8",
        buffering=1024 * 1024,
    ) as f:
        f.write(
            json.dumps(
                record,
                ensure_ascii=False,
                separators=(",", ":"),
            )
            + "\n"
        )


def process_file(input_path, stats):
    dataset = get_dataset(input_path)
    category = get_category(input_path)

    output_path = os.path.join(
        OUTPUT_DIR,
        f"{dataset}_{category}_analysis.jsonl",
    )

    error_path = os.path.join(
        OUTPUT_DIR,
        f"{dataset}_{category}_errors.jsonl",
    )

    completed = load_completed(output_path)

    print()
    print("=" * 70)
    print(f"DATASET : {dataset}")
    print(f"CATEGORY: {category}")
    print(f"INPUT   : {input_path}")
    print(f"OUTPUT  : {output_path}")
    print(f"RESUME  : {len(completed):,} completed")
    print("=" * 70)

    local_total = 0
    local_done = 0
    local_failed = 0

    for record in load_jsonl(input_path):
        local_total += 1
        stats["total"] += 1

        key = make_sample_key(
            record,
            dataset,
            category,
        )

        if key in completed:
            stats["skipped"] += 1
            continue

        sample_id = record.get(
            "id",
            record.get(
                "test_id",
                record.get(
                    "relative_path",
                    "unknown",
                ),
            ),
        )

        print(f"[{dataset}/{category}] {sample_id}")

        start = time.time()

        try:
            result = call_qwen(record)
            elapsed = time.time() - start

            output_record = dict(record)

            output_record["_sample_key"] = key
            output_record["llm_analysis"] = (
                result["analysis"]
            )
            output_record["llm_raw_output"] = (
                result["raw_output"]
            )
            output_record["llm_meta"] = {
                "model": MODEL,
                "server": BASE_URL,
                "elapsed_seconds": round(
                    elapsed,
                    3,
                ),
            }

            append_jsonl(
                output_path,
                output_record,
            )

            completed.add(key)

            local_done += 1
            stats["processed"] += 1

            vulnerable = result[
                "analysis"
            ].get("vulnerable")

            if vulnerable is True:
                stats["llm_vulnerable"] += 1

            elif vulnerable is False:
                stats["llm_not_vulnerable"] += 1

            print(
                f"  OK {elapsed:.1f}s "
                f"vulnerable={vulnerable}"
            )

        except KeyboardInterrupt:
            print()
            print("Interrupted by user.")
            raise

        except Exception as e:
            local_failed += 1
            stats["failed"] += 1

            error_record = {
                "_sample_key": key,
                "id": sample_id,
                "dataset": dataset,
                "category": category,
                "error": str(e),
                "record": record,
            }

            append_jsonl(
                error_path,
                error_record,
            )

            print(f"  ERROR: {e}")

    print()
    print(
        f"Finished {dataset}/{category}: "
        f"read={local_total:,} "
        f"done={local_done:,} "
        f"failed={local_failed:,}"
    )


def main():
    parser = argparse.ArgumentParser(
        description=(
            "Run local Qwen vulnerability analysis "
            "on SARD PHP and Juliet C/C++ JSONL files."
        )
    )

    parser.add_argument(
        "--category",
        choices=[
            "sqli",
            "xss",
            "cmdi",
            "all",
        ],
        default="all",
        help="Category to analyze.",
    )

    args = parser.parse_args()

    os.makedirs(
        OUTPUT_DIR,
        exist_ok=True,
    )

    print()
    print("=" * 70)
    print("QWEN VULNERABILITY ANALYSIS")
    print("=" * 70)
    print(f"Server         : {BASE_URL}")
    print(f"Model          : {MODEL}")
    print(f"Max code chars : {MAX_CODE_CHARS}")
    print(f"Max tokens     : {MAX_TOKENS}")
    print(f"Output         : {OUTPUT_DIR}")
    print("=" * 70)

    if not check_server():
        print()
        print(
            "ERROR: llama-server is not responding."
        )
        print(f"Expected: {API_URL}")
        return

    print()
    print("llama-server: ONLINE")

    input_files = find_input_files()

    if args.category != "all":
        input_files = [
            path
            for path in input_files
            if get_category(path)
            == args.category
        ]

    if not input_files:
        print("No input JSONL files found.")
        return

    print()
    print("Input files:")

    for path in input_files:
        print(f"  {path}")

    stats = {
        "total": 0,
        "processed": 0,
        "skipped": 0,
        "failed": 0,
        "llm_vulnerable": 0,
        "llm_not_vulnerable": 0,
    }

    started = time.time()

    try:
        for input_path in input_files:
            process_file(
                input_path,
                stats,
            )

    except KeyboardInterrupt:
        print()
        print("Stopped safely.")
        print(
            "Run the same command again to resume."
        )

    elapsed = time.time() - started

    stats["elapsed_seconds"] = round(
        elapsed,
        3,
    )

    stats["samples_per_hour"] = round(
        (
            stats["processed"]
            / elapsed
            * 3600
        )
        if elapsed > 0
        else 0,
        2,
    )

    stats_path = os.path.join(
        OUTPUT_DIR,
        "analysis_stats.json",
    )

    with open(
        stats_path,
        "w",
        encoding="utf-8",
    ) as f:
        json.dump(
            stats,
            f,
            ensure_ascii=False,
            indent=2,
        )

    print()
    print("=" * 70)
    print("ANALYSIS COMPLETE")
    print("=" * 70)
    print(
        json.dumps(
            stats,
            ensure_ascii=False,
            indent=2,
        )
    )


if __name__ == "__main__":
    main()
