import json
import os
import re

PROJECT_DIR = r"C:\Users\PC\Documents\T07-sardjuliet"

DATASETS = {
    "java": os.path.join(PROJECT_DIR, "data", "processed", "java"),
    "php": os.path.join(PROJECT_DIR, "data", "processed", "php"),
    "csharp": os.path.join(PROJECT_DIR, "data", "processed", "c#"),
}

CATEGORIES = ["cmdi", "xss", "sqli"]


def contains_pattern(text, pattern):
    """Kiểm tra regex không phân biệt hoa thường."""
    if not text:
        return False
    return bool(re.search(pattern, text, re.IGNORECASE))


def inspect_file(jsonl_path):
    stats = {
        "total": 0,
        "filename_bad": 0,
        "filename_good": 0,
        "code_bad_method": 0,
        "code_good_method": 0,
        "code_bad_word": 0,
        "code_good_word": 0,
        "state_bad": 0,
        "state_good": 0,
        "state_unknown": 0,
        "label_1": 0,
        "label_0": 0,
        "mixed_bad_good": 0,
        "examples": {
            "filename_bad": [],
            "filename_good": [],
            "code_bad_method": [],
            "code_good_method": [],
            "mixed": [],
        },
    }

    if not os.path.exists(jsonl_path):
        return None

    with open(jsonl_path, "r", encoding="utf-8", errors="ignore") as file:
        for line_number, line in enumerate(file, start=1):
            line = line.strip()
            if not line:
                continue

            try:
                record = json.loads(line)
            except json.JSONDecodeError:
                print(f"Invalid JSON line {line_number}: {jsonl_path}")
                continue

            stats["total"] += 1
            filepath = record.get("file", "")
            code = record.get("code", "")
            state = record.get("state", "unknown")
            label = record.get("label", None)

            # STATE
            if state == "bad":
                stats["state_bad"] += 1
            elif state == "good":
                stats["state_good"] += 1
            else:
                stats["state_unknown"] += 1

            # LABEL
            if label == 1:
                stats["label_1"] += 1
            elif label == 0:
                stats["label_0"] += 1

            # FILENAME
            filename_bad = contains_pattern(
                filepath, r"(^|[_\\/\-.])bad([_\\/\-.]|$)"
            )
            filename_good = contains_pattern(
                filepath, r"(^|[_\\/\-.])good([_\\/\-.]|$)"
            )

            if filename_bad:
                stats["filename_bad"] += 1
                if len(stats["examples"]["filename_bad"]) < 3:
                    stats["examples"]["filename_bad"].append(filepath)

            if filename_good:
                stats["filename_good"] += 1
                if len(stats["examples"]["filename_good"]) < 3:
                    stats["examples"]["filename_good"].append(filepath)

            # CODE METHODS
            bad_method = contains_pattern(
                code,
                r"\b(?:public\s+|private\s+|protected\s+)?"
                r"(?:static\s+)?"
                r"(?:void\s+)?"
                r"bad\s*\(",
            )
            good_method = contains_pattern(
                code,
                r"\b(?:public\s+|private\s+|protected\s+)?"
                r"(?:static\s+)?"
                r"(?:void\s+)?"
                r"good[A-Za-z0-9_]*\s*\(",
            )

            if bad_method:
                stats["code_bad_method"] += 1
                if len(stats["examples"]["code_bad_method"]) < 3:
                    stats["examples"]["code_bad_method"].append(filepath)

            if good_method:
                stats["code_good_method"] += 1
                if len(stats["examples"]["code_good_method"]) < 3:
                    stats["examples"]["code_good_method"].append(filepath)

            # WORD DETECTION
            if contains_pattern(code, r"\bbad\b"):
                stats["code_bad_word"] += 1
            if contains_pattern(code, r"\bgood\b"):
                stats["code_good_word"] += 1

            # MIXED
            if bad_method and good_method:
                stats["mixed_bad_good"] += 1
                if len(stats["examples"]["mixed"]) < 3:
                    stats["examples"]["mixed"].append(filepath)

    return stats


def print_examples(title, examples):
    if not examples:
        return
    print(f"\n{title}")
    for example in examples:
        print(f"    {example}")


def print_result(language, category, stats):
    print("\n" + "=" * 70)
    print(f"{language.upper()} - {category.upper()}")
    print("=" * 70 + "\n")

    print(f"TOTAL RECORDS: {stats['total']}\n")
    print("CURRENT LABELS:")
    print(f"  label=1: {stats['label_1']}")
    print(f"  label=0: {stats['label_0']}\n")

    print("CURRENT STATE:")
    print(f"  bad: {stats['state_bad']}")
    print(f"  good: {stats['state_good']}")
    print(f"  unknown: {stats['state_unknown']}\n")

    print("FILENAME:")
    print(f"  contains bad: {stats['filename_bad']}")
    print(f"  contains good: {stats['filename_good']}\n")

    print("CODE METHODS:")
    print(f"  contains bad(): {stats['code_bad_method']}")
    print(f"  contains good*(): {stats['code_good_method']}\n")

    print("CODE WORDS:")
    print(f"  contains 'bad': {stats['code_bad_word']}")
    print(f"  contains 'good': {stats['code_good_word']}\n")

    print("MIXED:")
    print(f"  contains both bad() and good*(): {stats['mixed_bad_good']}")

    print_examples(
        "EXAMPLES - FILENAME BAD:", stats["examples"]["filename_bad"]
    )
    print_examples(
        "EXAMPLES - FILENAME GOOD:", stats["examples"]["filename_good"]
    )
    print_examples(
        "EXAMPLES - CODE BAD METHOD:", stats["examples"]["code_bad_method"]
    )
    print_examples(
        "EXAMPLES - CODE GOOD METHOD:", stats["examples"]["code_good_method"]
    )
    print_examples("EXAMPLES - MIXED BAD + GOOD:", stats["examples"]["mixed"])
    print()


def main():
    print("\n" + "=" * 70)
    print("SARD DATASET INSPECTOR")
    print("=" * 70)

    grand_total = 0

    for language, directory in DATASETS.items():
        for category in CATEGORIES:
            jsonl_path = os.path.join(directory, f"{category}.jsonl")
            stats = inspect_file(jsonl_path)

            if stats is None:
                print(f"\nSKIP: {language.upper()} {category.upper()}")
                print(f"File not found:\n{jsonl_path}")
                continue

            print_result(language, category, stats)
            grand_total += stats["total"]

    print("=" * 70)
    print("ALL DONE")
    print(f"TOTAL RECORDS INSPECTED: {grand_total}")
    print("=" * 70)


if __name__ == "__main__":
    main()