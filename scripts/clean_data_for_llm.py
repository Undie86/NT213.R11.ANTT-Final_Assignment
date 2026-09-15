import json
import os
import re

# ============================================================
# PROJECT CONFIG
# ============================================================

PROJECT_DIR = r"C:\Users\PC\Documents\T07-sardjuliet"

INPUT_DIR = os.path.join(PROJECT_DIR, "data", "processed")
OUTPUT_DIR = os.path.join(PROJECT_DIR, "data", "clean")

DATASETS = {
    "java": {
        "input": os.path.join(INPUT_DIR, "java"),
        "output": os.path.join(OUTPUT_DIR, "java"),
    },
    "php": {
        "input": os.path.join(INPUT_DIR, "php"),
        "output": os.path.join(OUTPUT_DIR, "php"),
    },
    "c#": {
        "input": os.path.join(INPUT_DIR, "c#"),
        "output": os.path.join(OUTPUT_DIR, "c#"),
    },
}

CATEGORIES = ["cmdi", "xss", "sqli"]


# ============================================================
# REMOVE COPYRIGHT / LICENSE BLOCKS
# ============================================================


def remove_copyright_blocks(code):
    patterns = [
        r"/\*.*?Copyright.*?\*/",  # C style copyright block
        r"<!--.*?Copyright.*?-->",  # HTML style copyright block
        r"/\*Copyright.*?\*/",  # PHP style copyright block
    ]

    cleaned = code
    for pattern in patterns:
        cleaned = re.sub(pattern, "", cleaned, flags=re.IGNORECASE | re.DOTALL)
    return cleaned


# ============================================================
# REMOVE HTML / PHP METADATA BLOCKS
# ============================================================


def remove_html_metadata(code):
    def replace_comment(match):
        comment = match.group(0)
        metadata_patterns = [
            r"\bunsafe sample\b",
            r"\bsafe sample\b",
            r"\binput\s*:",
            r"\bsanitize\s*:",
            r"\bsanitization\s*:",
            r"\bsink\s*:",
            r"\bsource\s*:",
            r"\bconstruction\s*:",
            r"\bfile\s*:",
            r"\bno filtering\b",
            r"\bfiltering\b",
            r"\bflaw\b",
            r"\bfix\b",
            r"\bvulnerable\b",
            r"\bsafe\b",
        ]

        for pattern in metadata_patterns:
            if re.search(pattern, comment, re.IGNORECASE):
                return ""
        return comment

    return re.sub(r"<!--.*?-->", replace_comment, code, flags=re.DOTALL)


# ============================================================
# REMOVE C / JAVA / CSHARP BLOCK COMMENT METADATA
# ============================================================


def remove_block_comment_metadata(code):
    def replace_comment(match):
        comment = match.group(0)
        metadata_patterns = [
            r"\bunsafe sample\b",
            r"\bsafe sample\b",
            r"\binput\s*:",
            r"\bsanitize\s*:",
            r"\bsanitization\s*:",
            r"\bsink\s*:",
            r"\bsource\s*:",
            r"\bconstruction\s*:",
            r"\bno filtering\b",
            r"\bflaw\b",
            r"\bfix\b",
            r"\bvulnerable\b",
        ]

        for pattern in metadata_patterns:
            if re.search(pattern, comment, re.IGNORECASE):
                return ""
        return comment

    return re.sub(r"/\*.*?\*/", replace_comment, code, flags=re.DOTALL)


# ============================================================
# REMOVE SINGLE LINE METADATA COMMENTS
# ============================================================


def remove_line_metadata(code):
    lines = []
    metadata_patterns = [
        r"^\s*//\s*flaw\s*$",
        r"^\s*//\s*fix\s*$",
        r"^\s*//.*unsafe sample.*$",
        r"^\s*//.*safe sample.*$",
        r"^\s*//.*input\s*:.*$",
        r"^\s*//.*sanitize\s*:.*$",
        r"^\s*//.*sanitization\s*:.*$",
        r"^\s*//.*sink\s*:.*$",
        r"^\s*//.*source\s*:.*$",
        r"^\s*//.*no filtering.*$",
        r"^\s*//.*vulnerable.*$",
    ]

    for line in code.splitlines():
        remove = False
        for pattern in metadata_patterns:
            if re.search(pattern, line, re.IGNORECASE):
                remove = True
                break
        if not remove:
            lines.append(line)

    return "\n".join(lines)


# ============================================================
# REMOVE PHP # METADATA COMMENTS
# ============================================================


def remove_php_hash_metadata(code):
    lines = []
    metadata_patterns = [
        r"^\s*#\s*unsafe sample.*$",
        r"^\s*#\s*safe sample.*$",
        r"^\s*#.*input\s*:.*$",
        r"^\s*#.*sanitize\s*:.*$",
        r"^\s*#.*sink\s*:.*$",
        r"^\s*#.*flaw.*$",
        r"^\s*#.*fix.*$",
    ]

    for line in code.splitlines():
        remove = False
        for pattern in metadata_patterns:
            if re.search(pattern, line, re.IGNORECASE):
                remove = True
                break
        if not remove:
            lines.append(line)

    return "\n".join(lines)


# ============================================================
# REMOVE EXTRA EMPTY LINES
# ============================================================


def normalize_whitespace(code):
    lines = [line.rstrip() for line in code.splitlines()]
    cleaned_lines = []
    empty_count = 0

    for line in lines:
        if line.strip() == "":
            empty_count += 1
            if empty_count <= 2:  # Maximum 2 consecutive empty lines
                cleaned_lines.append("")
        else:
            empty_count = 0
            cleaned_lines.append(line)

    return "\n".join(cleaned_lines).strip()


# ============================================================
# MAIN CLEAN FUNCTION
# ============================================================


def clean_code(code, language):
    cleaned = code
    cleaned = remove_copyright_blocks(cleaned)
    cleaned = remove_html_metadata(cleaned)
    cleaned = remove_block_comment_metadata(cleaned)
    cleaned = remove_line_metadata(cleaned)

    if language == "php":
        cleaned = remove_php_hash_metadata(cleaned)

    cleaned = normalize_whitespace(cleaned)
    return cleaned


# ============================================================
# PROCESS JSONL FILE
# ============================================================


def process_file(input_path, output_path, language):
    total = 0
    cleaned_count = 0
    errors = 0

    print(f"\nINPUT:\n{input_path}\n\nOUTPUT:\n{output_path}\n")

    os.makedirs(os.path.dirname(output_path), exist_ok=True)

    with open(input_path, "r", encoding="utf-8") as infile, open(
        output_path, "w", encoding="utf-8"
    ) as outfile:
        for line_number, line in enumerate(infile, start=1):
            line = line.strip()
            if not line:
                continue

            total += 1

            try:
                record = json.loads(line)
                original_code = record.get("code", "")
                cleaned_code = clean_code(original_code, language)

                cleaned_record = {
                    "id": record.get("id"),
                    "suite_id": record.get("suite_id"),
                    "language": record.get("language"),
                    "cwe": record.get("cwe"),
                    "category": record.get("category"),
                    "label": record.get("label"),
                    "state": record.get("state"),
                    "file": record.get("file"),
                    "code": cleaned_code,
                }

                outfile.write(
                    json.dumps(cleaned_record, ensure_ascii=False) + "\n"
                )
                cleaned_count += 1

            except Exception as e:
                errors += 1
                print(f"ERROR line {line_number}:\n{str(e)}")

    print(
        f"\nRESULT:\nTOTAL:   {total}\nCLEANED: {cleaned_count}\nERRORS:  {errors}"
    )
    return {"total": total, "cleaned": cleaned_count, "errors": errors}


# ============================================================
# PROCESS LANGUAGE
# ============================================================


def process_language(language, config):
    input_dir = config["input"]
    output_dir = config["output"]

    print("\n" + "=" * 70)
    print(f"PROCESSING: {language.upper()}")
    print("=" * 70)

    if not os.path.exists(input_dir):
        print(f"\nINPUT DIRECTORY NOT FOUND:\n{input_dir}")
        return

    language_total = 0
    language_cleaned = 0
    language_errors = 0

    for category in CATEGORIES:
        input_path = os.path.join(input_dir, f"{category}.jsonl")
        output_path = os.path.join(output_dir, f"{category}.jsonl")

        print(f"\nCATEGORY: {category.upper()}")

        if not os.path.exists(input_path):
            print(f"\nINPUT FILE NOT FOUND:\n{input_path}")
            continue

        result = process_file(input_path, output_path, language)
        language_total += result["total"]
        language_cleaned += result["cleaned"]
        language_errors += result["errors"]

    print("\n" + "-" * 70)
    print(f"{language.upper()} SUMMARY")
    print("-" * 70)
    print(
        f"TOTAL:   {language_total}\nCLEANED: {language_cleaned}\nERRORS:  {language_errors}"
    )


# ============================================================
# MAIN
# ============================================================


def main():
    print("\n" + "=" * 70)
    print("T07 DATASET CLEANER FOR LLM")
    print("=" * 70)
    print(f"\nINPUT:\n{INPUT_DIR}\n\nOUTPUT:\n{OUTPUT_DIR}")

    for language, config in DATASETS.items():
        process_language(language, config)

    print("\n" + "=" * 70)
    print("ALL DONE")
    print("=" * 70)


if __name__ == "__main__":
    main()