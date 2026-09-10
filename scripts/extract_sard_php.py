import json
import os
import re
from collections import Counter

RAW_DIR = r"C:\Users\PC\Documents\T07-sardjuliet\data\raw\sard_php"
OUT_DIR = r"C:\Users\PC\Documents\T07-sardjuliet\data\processed\sard_php"

TARGET_CWES = {
    "CWE-78": "cmdi",
    "CWE-79": "xss",
    "CWE-80": "xss",
    "CWE-89": "sqli",
}

os.makedirs(OUT_DIR, exist_ok=True)


def parse_description(description):
    result = {
        "source": None,
        "sanitization": None,
        "dataflow": None,
        "context": None,
        "sink": None,
    }
    if not description:
        return result

    for line in description.splitlines():
        line = line.strip()
        if ":" not in line:
            continue

        key, value = line.split(":", 1)
        key = key.strip().lower()
        value = value.strip()

        if key in result:
            result[key] = value

    return result


def remove_comments(code):
    result = list(code)
    i = 0
    n = len(code)

    while i < n:
        if code[i] == '"':
            i += 1
            while i < n:
                if code[i] == "\\":
                    i += 2
                    continue
                if code[i] == '"':
                    i += 1
                    break
                i += 1
            continue

        if code[i] == "'":
            i += 1
            while i < n:
                if code[i] == "\\":
                    i += 2
                    continue
                if code[i] == "'":
                    i += 1
                    break
                i += 1
            continue

        if code[i : i + 2] == "//":
            result[i] = " "
            result[i + 1] = " "
            i += 2
            while i < n and code[i] != "\n":
                result[i] = " "
                i += 1
            continue

        if code[i] == "#":
            result[i] = " "
            i += 1
            while i < n and code[i] != "\n":
                result[i] = " "
                i += 1
            continue

        if code[i : i + 2] == "/*":
            result[i] = " "
            result[i + 1] = " "
            i += 2
            while i < n - 1:
                if code[i : i + 2] == "*/":
                    result[i] = " "
                    result[i + 1] = " "
                    i += 2
                    break
                if code[i] != "\n":
                    result[i] = " "
                i += 1
            continue

        i += 1

    return "".join(result)


def normalize_cwe(value):
    value = str(value).strip()
    if not value:
        return None

    if not value.upper().startswith("CWE-"):
        value = f"CWE-{value}"

    match = re.fullmatch(r"CWE-0*(\d+)", value, re.IGNORECASE)
    if not match:
        return value.upper()

    return f"CWE-{int(match.group(1))}"


def process_testcase(testcase_dir, outputs, stats):
    manifest_path = os.path.join(testcase_dir, "manifest.sarif")
    if not os.path.isfile(manifest_path):
        stats["missing_manifest"] += 1
        return

    try:
        with open(manifest_path, "r", encoding="utf-8") as f:
            manifest = json.load(f)
    except Exception:
        stats["manifest_errors"] += 1
        return

    runs = manifest.get("runs", [])
    if not runs:
        stats["invalid_manifests"] += 1
        return

    run = runs[0]
    properties = run.get("properties", {})
    state = properties.get("state")
    language = properties.get("language")

    if str(language).lower() != "php":
        stats["non_php"] += 1
        return

    results = run.get("results", [])
    cwes = set()

    for result in results:
        rule_id = normalize_cwe(result.get("ruleId", ""))
        if rule_id in TARGET_CWES:
            cwes.add(rule_id)

        for taxa in result.get("taxa", []):
            taxa_id = normalize_cwe(taxa.get("id", ""))
            if taxa_id in TARGET_CWES:
                cwes.add(taxa_id)

    for taxonomy in run.get("taxonomies", []):
        if str(taxonomy.get("name", "")).strip().lower() != "cwe":
            continue

        for taxa in taxonomy.get("taxa", []):
            taxa_id = normalize_cwe(taxa.get("id", ""))
            if taxa_id in TARGET_CWES:
                cwes.add(taxa_id)

    if not cwes:
        stats["other_cwe"] += 1
        return

    source_path = os.path.join(testcase_dir, "src", "sample.php")
    if not os.path.isfile(source_path):
        stats["missing_source"] += 1
        return

    try:
        with open(
            source_path, "r", encoding="utf-8", errors="replace"
        ) as f:
            code_raw = f.read()
    except Exception:
        stats["source_errors"] += 1
        return

    if state == "bad":
        label = 1
    elif state == "good":
        label = 0
    else:
        stats["unknown_state"] += 1
        return

    code = remove_comments(code_raw).strip()
    description = properties.get("description", "")
    parsed = parse_description(description)
    test_id = properties.get("id")

    for cwe in sorted(cwes):
        category = TARGET_CWES[cwe]
        result_kind = None
        start_line = None

        for result in results:
            rule_id = normalize_cwe(result.get("ruleId", ""))
            if rule_id != cwe:
                continue

            result_kind = result.get("kind")
            locations = result.get("locations", [])
            if locations:
                region = (
                    locations[0]
                    .get("physicalLocation", {})
                    .get("region", {})
                )
                start_line = region.get("startLine")
            break

        record = {
            "id": test_id,
            "language": "php",
            "cwe": cwe,
            "category": category,
            "label": label,
            "state": state,
            "result_kind": result_kind,
            "code": code,
            "source": parsed["source"],
            "sanitization": parsed["sanitization"],
            "dataflow": parsed["dataflow"],
            "context": parsed["context"],
            "sink": parsed["sink"],
            "start_line": start_line,
        }

        outputs[category].write(
            json.dumps(
                record, ensure_ascii=False, separators=(",", ":")
            )
            + "\n"
        )
        stats["samples"][category] += 1
        stats["labels"][category][str(label)] += 1


def main():
    output_paths = {
        category: os.path.join(OUT_DIR, f"{category}.jsonl")
        for category in set(TARGET_CWES.values())
    }

    outputs = {
        category: open(
            path, "w", encoding="utf-8", buffering=1024 * 1024
        )
        for category, path in output_paths.items()
    }

    categories = sorted(set(TARGET_CWES.values()))

    stats = {
        "testcase_dirs": 0,
        "samples": {category: 0 for category in categories},
        "labels": {category: Counter() for category in categories},
        "missing_manifest": 0,
        "manifest_errors": 0,
        "invalid_manifests": 0,
        "non_php": 0,
        "other_cwe": 0,
        "missing_source": 0,
        "source_errors": 0,
        "unknown_state": 0,
    }

    try:
        with os.scandir(RAW_DIR) as entries:
            for entry in entries:
                if not entry.is_dir():
                    continue

                stats["testcase_dirs"] += 1
                process_testcase(entry.path, outputs, stats)

                if stats["testcase_dirs"] % 10000 == 0:
                    print(
                        f"[{stats['testcase_dirs']:,}] "
                        + " ".join(
                            f"{category.upper()}={stats['samples'][category]:,}"
                            for category in categories
                        )
                    )
    finally:
        for f in outputs.values():
            f.close()

    for category in categories:
        stats["labels"][category] = dict(stats["labels"][category])

    stats_path = os.path.join(OUT_DIR, "extraction_stats.json")
    with open(stats_path, "w", encoding="utf-8") as f:
        json.dump(stats, f, ensure_ascii=False, indent=2)

    print()
    print("=" * 60)
    print("EXTRACTION COMPLETE")
    print("=" * 60)
    print(json.dumps(stats, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()