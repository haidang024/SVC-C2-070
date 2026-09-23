# PB-4: Import Isolation Verification

import ast
import os

import pytest

PROHIBITED_IMPORTS = ["agenticstar", "platform"]
STDLIB_PLATFORM_ALLOWED = True


def _scan_imports(filepath: str) -> list[str]:
    with open(filepath) as source_file:
        tree = ast.parse(source_file.read(), filename=filepath)

    violations = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                for prohibited in PROHIBITED_IMPORTS:
                    if alias.name == prohibited or alias.name.startswith(f"{prohibited}."):
                        if prohibited == "platform" and STDLIB_PLATFORM_ALLOWED and alias.name == "platform":
                            continue
                        violations.append(f"{filepath}:{node.lineno} — import {alias.name}")
        elif isinstance(node, ast.ImportFrom) and node.module:
            for prohibited in PROHIBITED_IMPORTS:
                if node.module == prohibited or node.module.startswith(f"{prohibited}."):
                    if prohibited == "platform" and STDLIB_PLATFORM_ALLOWED and node.module == "platform":
                        continue
                    violations.append(f"{filepath}:{node.lineno} — from {node.module} import ...")
    return violations


def _find_python_files(directory: str) -> list[str]:
    py_files = []
    for root, _dirs, files in os.walk(directory):
        for filename in files:
            if filename.endswith(".py"):
                py_files.append(os.path.join(root, filename))
    return py_files


class TestImportIsolation:
    def test_no_prohibited_imports_in_src(self):
        src_dir = os.path.join(os.path.dirname(__file__), "..", "..", "src")
        if not os.path.exists(src_dir):
            pytest.skip("src/ directory not found")
        violations = []
        for filepath in _find_python_files(src_dir):
            violations.extend(_scan_imports(filepath))
        assert violations == [], "Import Isolation violations found:\n" + "\n".join(violations)
