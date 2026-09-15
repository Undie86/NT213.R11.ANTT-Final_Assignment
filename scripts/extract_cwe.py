import os
import json
import re


# ============================================================
# PROJECT
# ============================================================

PROJECT_DIR = r"C:\Users\PC\Documents\T07-sardjuliet"


# ============================================================
# DATASETS
# ============================================================

DATASETS = {

    "java": {
        "input": os.path.join(
            PROJECT_DIR,
            "data",
            "raw",
            "java"
        ),

        "output": os.path.join(
            PROJECT_DIR,
            "data",
            "processed",
            "java"
        ),

        "extensions": [".java"]
    },


    "php": {
        "input": os.path.join(
            PROJECT_DIR,
            "data",
            "raw",
            "php"
        ),

        "output": os.path.join(
            PROJECT_DIR,
            "data",
            "processed",
            "php"
        ),

        "extensions": [".php"]
    },


    "csharp": {
        "input": os.path.join(
            PROJECT_DIR,
            "data",
            "raw",
            "c#"
        ),

        "output": os.path.join(
            PROJECT_DIR,
            "data",
            "processed",
            "c#"
        ),

        "extensions": [".cs"]
    }

}


# ============================================================
# CWE MAPPING
# ============================================================

CWE_MAPPING = {

    "CWE-78": {
        "number": "78",
        "category": "cmdi"
    },


    "CWE-79": {
        "number": "79",
        "category": "xss"
    },


    "CWE-89": {
        "number": "89",
        "category": "sqli"
    }

}


# ============================================================
# FIND CWE
# ============================================================

def find_cwe(filepath):

    """
    Tìm CWE trong đường dẫn / tên file.

    Hỗ trợ:

    CWE78
    CWE078
    CWE-78
    CWE_78
    CWE_078

    CWE89
    CWE_89

    cwe_78
    cwe_089
    """

    normalized_path = filepath.replace(
        "\\",
        "/"
    )

    for cwe, info in CWE_MAPPING.items():

        number = info["number"]

        pattern = (
            rf"CWE[-_]?0*{number}(?!\d)"
        )

        if re.search(
            pattern,
            normalized_path,
            re.IGNORECASE
        ):

            return (
                cwe,
                info["category"]
            )

    return None, None


# ============================================================
# GET SUITE ID
# ============================================================

def get_suite_id(
    filepath,
    input_dir
):

    """
    Ví dụ:

    raw/java/
        144352-v1.0.0/
            src/
                ...

    Kết quả:

    144352-v1.0.0
    """

    relative_path = os.path.relpath(
        filepath,
        input_dir
    )

    parts = relative_path.split(
        os.sep
    )

    if parts:

        return parts[0]

    return "unknown"


# ============================================================
# JAVA LABEL
# ============================================================

def get_java_label(
    filepath,
    code
):

    """
    JULIET JAVA:

    Một file có thể chứa:

        bad()

    và:

        goodG2B1()
        goodG2B2()

    Nhưng file đó vẫn là một CWE testcase.

    Vì dataset của bạn đánh giá CẤP FILE:

        Có vulnerability trong file -> 1
        Không có vulnerability -> 0

    Không dựa vào tên hàm.
    """

    filename = os.path.basename(
        filepath
    ).lower()


    # Juliet split testcase dạng:

    # xxx_81_bad.java
    # xxx_81_good.java

    if re.search(
        r"(?:_|-)bad\.(java)$",
        filename
    ):

        return 1, "vulnerable"


    if re.search(
        r"(?:_|-)good\.(java)$",
        filename
    ):

        return 0, "safe"


    # File Juliet bình thường có CWE testcase.

    # Ví dụ:
    #
    # CWE78_OS_Command_Injection__Environment_03.java
    #
    # Bên trong có bad() + good()
    #
    # Theo FILE-LEVEL:
    #
    # Có bad path -> vulnerable

    if re.search(
        r"(?i)POTENTIAL\s+FLAW",
        code
    ):

        return 1, "vulnerable"


    # Nếu không tìm thấy POTENTIAL FLAW
    # thì không đủ bằng chứng có CWE.

    return 0, "safe"


# ============================================================
# PHP LABEL
# ============================================================

def get_php_label(
    filepath,
    code
):

    """
    PHP SARD dataset.

    Metadata chính thức nằm trong comment.

    Vulnerable sample:

        Unsafe sample

    và thường:

        //flaw


    Safe sample:

        Safe sample

    Không dùng tên hàm.
    """


    # Unsafe sample

    unsafe_sample = re.search(
        r"(?i)\bunsafe\s+sample\b",
        code
    )


    # flaw marker

    flaw_marker = re.search(
        r"(?i)//\s*flaw\b",
        code
    )


    # Safe sample

    safe_sample = re.search(
        r"(?i)(?<!un)\bsafe\s+sample\b",
        code
    )


    # --------------------------------------------------------
    # VULNERABLE
    # --------------------------------------------------------

    if unsafe_sample:

        return 1, "vulnerable"


    if flaw_marker:

        return 1, "vulnerable"


    # --------------------------------------------------------
    # SAFE
    # --------------------------------------------------------

    if safe_sample:

        return 0, "safe"


    # Không xác định được metadata.

    # Không dùng unknown trong dataset cuối.

    return 0, "safe"


# ============================================================
# CSHARP LABEL
# ============================================================

def get_csharp_label(
    filepath,
    code
):

    """
    C# SARD dataset.

    Vulnerable testcase thường có:

        //flaw

    Safe testcase có thể không dùng:

        //fix

    Ví dụ safe:

        SHA512 function.
        Always Safe

    Vì vậy:

    1. Có //flaw
       -> vulnerable

    2. Có explicit "Always Safe"
       -> safe

    3. Có "Safe"
       -> safe

    Không dựa vào tên hàm.
    """


    # --------------------------------------------------------
    # VULNERABLE
    # --------------------------------------------------------

    flaw_marker = re.search(
        r"(?i)//\s*flaw\b",
        code
    )


    if flaw_marker:

        return 1, "vulnerable"


    # --------------------------------------------------------
    # SAFE
    # --------------------------------------------------------

    always_safe = re.search(
        r"(?i)\balways\s+safe\b",
        code
    )


    if always_safe:

        return 0, "safe"


    safe_marker = re.search(
        r"(?i)\bsafe\b",
        code
    )


    if safe_marker:

        return 0, "safe"


    # Không tìm thấy flaw.

    return 0, "safe"


# ============================================================
# GET LABEL
# ============================================================

def get_label(
    language,
    filepath,
    code
):

    """
    Dispatcher.

    Trả về:

        label
        state
    """


    if language == "java":

        return get_java_label(
            filepath,
            code
        )


    if language == "php":

        return get_php_label(
            filepath,
            code
        )


    if language == "csharp":

        return get_csharp_label(
            filepath,
            code
        )


    return 0, "safe"


# ============================================================
# PROCESS DATASET
# ============================================================

def process_dataset(
    language,
    config
):


    input_dir = config["input"]

    output_dir = config["output"]

    extensions = config["extensions"]


    print()

    print(
        "=" * 70
    )

    print(
        f"PROCESSING: {language.upper()}"
    )

    print(
        "=" * 70
    )

    print()

    print(
        "INPUT:"
    )

    print(
        input_dir
    )

    print()

    print(
        "OUTPUT:"
    )

    print(
        output_dir
    )

    print()


    # --------------------------------------------------------
    # CHECK INPUT
    # --------------------------------------------------------

    if not os.path.exists(
        input_dir
    ):

        print(
            "ERROR: INPUT DIRECTORY NOT FOUND"
        )

        return


    # --------------------------------------------------------
    # CREATE OUTPUT
    # --------------------------------------------------------

    os.makedirs(
        output_dir,
        exist_ok=True
    )


    # --------------------------------------------------------
    # OPEN OUTPUT FILES
    # --------------------------------------------------------

    output_files = {}


    for cwe, info in CWE_MAPPING.items():

        category = info["category"]


        output_path = os.path.join(
            output_dir,
            f"{category}.jsonl"
        )


        output_files[category] = open(
            output_path,
            "w",
            encoding="utf-8"
        )


    # --------------------------------------------------------
    # COUNTERS
    # --------------------------------------------------------

    counts = {

        "cmdi": 0,

        "xss": 0,

        "sqli": 0

    }


    vulnerable_counts = {

        "cmdi": 0,

        "xss": 0,

        "sqli": 0

    }


    safe_counts = {

        "cmdi": 0,

        "xss": 0,

        "sqli": 0

    }


    ids = {

        "cmdi": 0,

        "xss": 0,

        "sqli": 0

    }


    files_found = 0

    files_processed = 0


    # ========================================================
    # WALK FILES
    # ========================================================

    try:


        for root, dirs, files in os.walk(
            input_dir
        ):


            for filename in files:


                filepath = os.path.join(
                    root,
                    filename
                )


                extension = os.path.splitext(
                    filename
                )[1].lower()


                # ------------------------------------------------
                # CHECK EXTENSION
                # ------------------------------------------------

                if extension not in extensions:

                    continue


                files_found += 1


                # ------------------------------------------------
                # FIND CWE
                # ------------------------------------------------

                cwe, category = find_cwe(
                    filepath
                )


                if not cwe:

                    continue


                # ------------------------------------------------
                # READ FILE
                # ------------------------------------------------

                try:


                    with open(
                        filepath,
                        "r",
                        encoding="utf-8",
                        errors="ignore"
                    ) as source_file:


                        code = source_file.read()


                except Exception:


                    print()

                    print(
                        "CANNOT READ:"
                    )

                    print(
                        filepath
                    )

                    continue


                # ------------------------------------------------
                # GET LABEL
                # ------------------------------------------------

                label, state = get_label(
                    language,
                    filepath,
                    code
                )


                # ------------------------------------------------
                # SUITE ID
                # ------------------------------------------------

                suite_id = get_suite_id(
                    filepath,
                    input_dir
                )


                # ------------------------------------------------
                # RELATIVE PATH
                # ------------------------------------------------

                relative_file = os.path.relpath(
                    filepath,
                    input_dir
                )


                # ------------------------------------------------
                # RECORD
                # ------------------------------------------------

                record = {

                    "id":
                        ids[category],


                    "suite_id":
                        suite_id,


                    "language":
                        language,


                    "cwe":
                        cwe,


                    "category":
                        category,


                    # 1 = vulnerable
                    # 0 = safe

                    "label":
                        label,


                    "state":
                        state,


                    "file":
                        relative_file,


                    "code":
                        code

                }


                # ------------------------------------------------
                # WRITE JSONL
                # ------------------------------------------------

                output_files[
                    category
                ].write(

                    json.dumps(
                        record,
                        ensure_ascii=False
                    )

                    + "\n"

                )


                # ------------------------------------------------
                # UPDATE COUNTERS
                # ------------------------------------------------

                ids[
                    category
                ] += 1


                counts[
                    category
                ] += 1


                if label == 1:


                    vulnerable_counts[
                        category
                    ] += 1


                else:


                    safe_counts[
                        category
                    ] += 1


                files_processed += 1


    finally:


        for file_handle in output_files.values():

            file_handle.close()


    # ========================================================
    # RESULT
    # ========================================================

    print()

    print(
        "RESULT"
    )

    print()


    print(
        f"FILES FOUND:      {files_found}"
    )


    print(
        f"FILES PROCESSED:  {files_processed}"
    )


    print()


    for category in [

        "cmdi",

        "xss",

        "sqli"

    ]:


        print(
            f"{category.upper()}:"
        )


        print(
            f"  TOTAL:       {counts[category]}"
        )


        print(
            f"  VULNERABLE:  {vulnerable_counts[category]}"
        )


        print(
            f"  SAFE:        {safe_counts[category]}"
        )


        print()


# ============================================================
# MAIN
# ============================================================

def main():


    print()

    print(
        "=" * 70
    )

    print(
        "T07 SARD JULIET CWE EXTRACTOR"
    )

    print(
        "=" * 70
    )


    for language, config in DATASETS.items():


        process_dataset(
            language,
            config
        )


    print()

    print(
        "=" * 70
    )

    print(
        "ALL DONE"
    )

    print(
        "=" * 70
    )


# ============================================================
# ENTRY POINT
# ============================================================

if __name__ == "__main__":

    main()