"""
Fuzz Tester for Assigned FAME-ML Functions
Fall 2025 – Maddie Larkin (Task 4)

This script fuzzes the five required forensic-analysis methods:
    1. checkIfParsablePython
    2. getPythonParseObject
    3. getFunctionDefinitions
    4. getDataLoadCount
    5. getModelLoadCounta
"""

import os
import random
import string
import tempfile
import traceback

# -------------------------------------------------------
# FIXED IMPORTS — must come from FAME_ML package
# -------------------------------------------------------
from FAME_ML import py_parser
from FAME_ML import lint_engine

# -------------------------------------------------------
# Configuration
# -------------------------------------------------------

NUM_TESTS = 250
OUTPUT_DIR = "fuzz-results"
CRASH_LOG = os.path.join(OUTPUT_DIR, "crashes.txt")

os.makedirs(OUTPUT_DIR, exist_ok=True)

# -------------------------------------------------------
# Helper: Generate Python-like random code
# -------------------------------------------------------

KEYWORDS = [
    "import", "def", "class", "return", "for", "while",
    "if", "try", "except", "with", "lambda", "yield"
]

def random_identifier():
    length = random.randint(3, 12)
    letters = string.ascii_letters + "_"
    return ''.join(random.choice(letters) for _ in range(length))


def random_python_snippet():
    lines = []
    for _ in range(random.randint(5, 20)):
        choice = random.randint(0, 5)

        if choice == 0:
            lines.append(f"{random_identifier()} = {random.randint(0, 99999)}")

        elif choice == 1:
            lines.append(f"def {random_identifier()}():\n    pass")

        elif choice == 2:
            lines.append(f"import {random_identifier()}")

        elif choice == 3:
            lines.append(f"{random_identifier()}({random_identifier()})")

        elif choice == 4:
            lines.append(random.choice(KEYWORDS))

        else:
            garbage = ''.join(random.choice(string.printable) for _ in range(10))
            lines.append(garbage)

    return "\n".join(lines)

# -------------------------------------------------------
# Helper: Write snippet to temp .py file
# -------------------------------------------------------

def write_temp_python_file(snippet):
    fd, path = tempfile.mkstemp(suffix=".py", text=True)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        f.write(snippet)
    return path

# -------------------------------------------------------
# Helper: Crash Logging
# -------------------------------------------------------

def record_crash(test_id, function_name, snippet, error_msg):
    with open(CRASH_LOG, "a", encoding="utf-8") as f:
        f.write("\n" + "=" * 70 + "\n")
        f.write(f"Test #{test_id} – Function: {function_name}\n")
        f.write("Input snippet:\n")
        f.write(snippet + "\n\n")
        f.write("Error:\n")
        f.write(error_msg + "\n")

# -------------------------------------------------------
# Fuzz Logic
# -------------------------------------------------------

def fuzz_target(py_path, snippet, test_id):
    targets = [
        ("checkIfParsablePython", lambda: py_parser.checkIfParsablePython(py_path)),
        ("getPythonParseObject", lambda: py_parser.getPythonParseObject(py_path)),
        ("getFunctionDefinitions",
            lambda: py_parser.getFunctionDefinitions(py_parser.getPythonParseObject(py_path))),
        ("getDataLoadCount", lambda: lint_engine.getDataLoadCount(py_path)),
        ("getModelLoadCounta", lambda: lint_engine.getModelLoadCounta(py_path)),
    ]

    for func_name, func in targets:
        try:
            func()
        except Exception as e:
            print(f"[CRASH] {func_name} failed on test {test_id}")
            record_crash(test_id, func_name, snippet, traceback.format_exc())

# -------------------------------------------------------
# Main Loop
# -------------------------------------------------------

def main():
    print(f"🔧 Starting fuzzing... Running {NUM_TESTS} tests.")
    print(f"Crash log will be stored in: {CRASH_LOG}")

    for test_id in range(1, NUM_TESTS + 1):
        snippet = random_python_snippet()
        py_path = write_temp_python_file(snippet)

        fuzz_target(py_path, snippet, test_id)

        os.remove(py_path)

    print("\n✨ Fuzzing complete!")
    if os.path.exists(CRASH_LOG):
        print("⚠️ Crashes were found. See fuzz-results/crashes.txt")
    else:
        print("🎉 No crashes found — great job!")

if __name__ == "__main__":
    main()
