from pathlib import Path
import json
import re
from collections import Counter

RAW_DIR = Path(
    r"C:\Users\PC\Documents\T07-sardjuliet\data\raw\juliet_cpp\C"
)

TESTCASES_DIR = RAW_DIR / "testcases"

OUT_DIR = Path(
    r"C:\Users\PC\Documents\T07-sardjuliet\data\processed\juliet_cpp"
)

TARGET_CWES = {
    "78": ("CWE-78", "cmdi"),
    "80": ("CWE-80", "xss"),
    "89": ("CWE-89", "sqli"),
}

def detect_cwe(path: Path):
    match = re.search(
        r"CWE0*(\d+)",
        str(path),
        re.IGNORECASE
    )

    if not match:
        return None

    number = match.group(1)

    return TARGET_CWES.get(number)

def mask_comments_and_strings(code: str):
    result = list(code)

    i = 0
    n = len(code)

    while i < n:

        if code[i:i + 2] == "//":

            result[i] = " "
            result[i + 1] = " "

            i += 2

            while i < n and code[i] != "\n":
                result[i] = " "
                i += 1

            continue

        if code[i:i + 2] == "/*":

            result[i] = " "
            result[i + 1] = " "

            i += 2

            while i < n - 1:

                if code[i:i + 2] == "*/":

                    result[i] = " "
                    result[i + 1] = " "

                    i += 2
                    break

                if code[i] != "\n":
                    result[i] = " "

                i += 1

            continue

        if code[i] == '"':

            result[i] = " "
            i += 1

            while i < n:

                if code[i] == "\\":

                    result[i] = " "
                    i += 1

                    if i < n:
                        result[i] = " "
                        i += 1

                    continue

                if code[i] == '"':

                    result[i] = " "
                    i += 1
                    break

                if code[i] != "\n":
                    result[i] = " "

                i += 1

            continue

        if code[i] == "'":

            result[i] = " "
            i += 1

            while i < n:

                if code[i] == "\\":

                    result[i] = " "
                    i += 1

                    if i < n:
                        result[i] = " "
                        i += 1

                    continue

                if code[i] == "'":

                    result[i] = " "
                    i += 1
                    break

                if code[i] != "\n":
                    result[i] = " "

                i += 1

            continue

        i += 1

    return "".join(result)

def remove_comments(code: str):
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

        if code[i:i + 2] == "//":

            result[i] = " "
            result[i + 1] = " "

            i += 2

            while i < n and code[i] != "\n":
                result[i] = " "
                i += 1

            continue

        if code[i:i + 2] == "/*":

            result[i] = " "
            result[i + 1] = " "

            i += 2

            while i < n - 1:

                if code[i:i + 2] == "*/":

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

def find_matching_brace(
    masked_code: str,
    open_index: int
):
    depth = 0

    for i in range(
        open_index,
        len(masked_code)
    ):

        char = masked_code[i]

        if char == "{":
            depth += 1

        elif char == "}":

            depth -= 1

            if depth == 0:
                return i

    return None

def find_primary_functions(code: str):
    masked = mask_comments_and_strings(code)

    pattern = re.compile(
        r"""
        \b
        (?:[\w:<>~*&]+\s+)*
        \b(good|bad)
        \s*
        \(
        [^)]*
        \)
        \s*
        (?:
            const\s*
        )?
        \{
        """,
        re.VERBOSE
    )

    found = {}

    for match in pattern.finditer(masked):

        function_name = match.group(1)

        if function_name in found:
            continue

        open_brace = masked.find(
            "{",
            match.start(),
            match.end()
        )

        if open_brace == -1:
            continue

        close_brace = find_matching_brace(
            masked,
            open_brace
        )

        if close_brace is None:
            continue

        found[function_name] = {
            "start": match.start(),
            "open_brace": open_brace,
            "close_brace": close_brace,
        }

    return found

def extract_function(
    code: str,
    function_info: dict
):
    start = function_info["start"]

    end = (
        function_info["close_brace"] + 1
    )

    return code[start:end].strip()

def normalize_function_name(
    code: str,
    original_name: str
):
    pattern = re.compile(
        rf"\b{re.escape(original_name)}\s*\("
    )

    return pattern.sub(
        "testcase(",
        code,
        count=1
    )

def clean_for_training(
    code: str,
    original_function_name: str
):
    cleaned = remove_comments(code)

    cleaned = normalize_function_name(
        cleaned,
        original_function_name
    )

    return cleaned.strip()

def make_record(
    file_path: Path,
    code: str,
    cwe: str,
    category: str,
    state: str,
    function_name: str,
):
    relative_path = file_path.relative_to(
        TESTCASES_DIR
    )

    return {
        "id": (
            str(relative_path)
            .replace("\\", "/")
            + f"::{function_name}"
        ),
        "language": "cpp",
        "cwe": cwe,
        "category": category,
        "label": 1 if state == "bad" else 0,
        "state": state,
        "function": function_name,
        "code": code,
        "source_file": file_path.name,
        "relative_path": (
            str(relative_path)
            .replace("\\", "/")
        ),
    }

def main():

    if not RAW_DIR.exists():
        raise FileNotFoundError(
            f"RAW_DIR does not exist:\n{RAW_DIR}"
        )

    if not TESTCASES_DIR.exists():
        raise FileNotFoundError(
            "testcases directory does not exist:\n"
            f"{TESTCASES_DIR}"
        )

    OUT_DIR.mkdir(
        parents=True,
        exist_ok=True
    )

    outputs = {
        "sqli": OUT_DIR / "sqli.jsonl",
        "xss": OUT_DIR / "xss.jsonl",
        "cmdi": OUT_DIR / "cmdi.jsonl",
    }

    for path in outputs.values():
        path.write_text(
            "",
            encoding="utf-8"
        )

    stats = Counter()

    total_files = 0
    matched_files = 0
    bad_records = 0
    good_records = 0

    source_files = []

    for extension in (
        "*.c",
        "*.cpp",
        "*.cc",
        "*.cxx",
    ):
        source_files.extend(
            TESTCASES_DIR.rglob(extension)
        )

    print("=" * 70)
    print("JULIET C/C++ v1.3 EXTRACTION")
    print("=" * 70)

    print(f"RAW : {RAW_DIR}")
    print(f"TEST: {TESTCASES_DIR}")
    print(f"OUT : {OUT_DIR}")
    print()

    print(
        f"Found {len(source_files):,} C/C++ files"
    )

    for file_path in source_files:

        total_files += 1

        cwe_info = detect_cwe(file_path)

        if cwe_info is None:
            continue

        cwe, category = cwe_info

        try:

            code = file_path.read_text(
                encoding="utf-8",
                errors="replace"
            )

        except Exception as exc:

            print(
                f"[WARN] Cannot read "
                f"{file_path}: {exc}"
            )

            stats["read_error"] += 1
            continue

        functions = find_primary_functions(code)

        if not functions:

            stats["no_primary_good_bad"] += 1
            continue

        matched_files += 1

        if "bad" in functions:

            bad_code = extract_function(
                code,
                functions["bad"]
            )

            bad_code = clean_for_training(
                bad_code,
                "bad"
            )

            record = make_record(
                file_path=file_path,
                code=bad_code,
                cwe=cwe,
                category=category,
                state="bad",
                function_name="bad",
            )

            with outputs[category].open(
                "a",
                encoding="utf-8"
            ) as f:

                f.write(
                    json.dumps(
                        record,
                        ensure_ascii=False
                    )
                    + "\n"
                )

            bad_records += 1
            stats[f"{category}.bad"] += 1
            stats[f"{cwe}.bad"] += 1

        else:

            stats["missing_bad"] += 1

        if "good" in functions:

            good_code = extract_function(
                code,
                functions["good"]
            )

            good_code = clean_for_training(
                good_code,
                "good"
            )

            record = make_record(
                file_path=file_path,
                code=good_code,
                cwe=cwe,
                category=category,
                state="good",
                function_name="good",
            )

            with outputs[category].open(
                "a",
                encoding="utf-8"
            ) as f:

                f.write(
                    json.dumps(
                        record,
                        ensure_ascii=False
                    )
                    + "\n"
                )

            good_records += 1
            stats[f"{category}.good"] += 1
            stats[f"{cwe}.good"] += 1

        else:

            stats["missing_good"] += 1

    stats_output = {
        "dataset": (
            "Juliet Test Suite "
            "for C/C++ v1.3"
        ),
        "raw_dir": str(RAW_DIR),
        "testcases_dir": str(TESTCASES_DIR),
        "output_dir": str(OUT_DIR),
        "target_cwes": {
            key: {
                "cwe": value[0],
                "category": value[1],
            }
            for key, value in TARGET_CWES.items()
        },
        "extraction_method": (
            "Primary good()/bad() functions "
            "extracted separately"
        ),
        "label_encoding": {
            "bad": 1,
            "good": 0,
        },
        "leakage_mitigation": [
            "Comments removed",
            "Primary bad()/good() function "
            "name normalized to testcase()",
        ],
        "total_source_files_scanned": total_files,
        "matched_source_files": matched_files,
        "bad_records": bad_records,
        "good_records": good_records,
        "total_records": (
            bad_records + good_records
        ),
        "statistics": dict(stats),
    }

    stats_path = (
        OUT_DIR / "extraction_stats.json"
    )

    stats_path.write_text(
        json.dumps(
            stats_output,
            indent=2,
            ensure_ascii=False
        ),
        encoding="utf-8"
    )

    print()
    print("=" * 70)
    print("EXTRACTION COMPLETE")
    print("=" * 70)

    print(
        f"Source files scanned : "
        f"{total_files:,}"
    )

    print(
        f"Matched source files : "
        f"{matched_files:,}"
    )

    print(
        f"Bad records          : "
        f"{bad_records:,}"
    )

    print(
        f"Good records         : "
        f"{good_records:,}"
    )

    print(
        f"Total records        : "
        f"{bad_records + good_records:,}"
    )

    print()

    for category, path in outputs.items():

        count = 0

        if path.exists():

            with path.open(
                encoding="utf-8"
            ) as f:

                count = sum(
                    1
                    for _ in f
                )

        print(
            f"{category:6}: "
            f"{count:,} records"
        )

        print(
            f"         {path}"
        )

    print()
    print(
        f"Stats: {stats_path}"
    )

if __name__ == "__main__":
    main()