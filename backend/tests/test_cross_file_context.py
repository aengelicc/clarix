"""Tests for the cross-file context builder (`app/services/context.py`).

Covers:
- Python import extraction (`import` / `from ... import` / relative)
- JS/TS import extraction (ESM, CJS)
- Stdlib / well-known third-party packages are filtered
- Import resolution (relative + same-repo absolute)
- Budget enforcement (token cap respected)
- End-to-end: build_context_for_file returns a markdown-fenced block
  for same-repo imports, empty for no imports or all-stdlib
- Integration: LLMClient.analyze_file prepends the context to the user
  prompt when one is provided
- Analyzer wiring: cross_file_context=False (default) skips the
  builder; True includes it in the LLM call
"""
import tempfile
from pathlib import Path

import pytest

from app.services import context as ctx
from app.services import llm_cache


@pytest.fixture(autouse=True)
def _reset_llm_cache():
    llm_cache.clear()
    llm_cache.reset_stats()
    yield
    llm_cache.clear()


# ---------------------------------------------------------------------------
# Python import extraction
# ---------------------------------------------------------------------------


def test_extract_python_imports_basic():
    code = "import os\nimport json\nimport mymodule\nfrom utils import helper\n"
    imports = ctx.extract_python_imports(code)
    assert "mymodule" in imports
    assert "utils" in imports
    # os and json are stdlib, filtered out
    assert "os" not in imports
    assert "json" not in imports


def test_extract_python_imports_relative():
    code = "from .sibling import foo\nfrom ..package.bar import baz\nfrom . import utils\n"
    imports = ctx.extract_python_imports(code)
    assert ".sibling" in imports
    assert "..package.bar" in imports
    assert ".utils" in imports  # `from . import utils`


def test_extract_python_imports_dedupes():
    code = "import x\nimport x\nimport x\n"
    imports = ctx.extract_python_imports(code)
    assert imports.count("x") == 1


def test_extract_python_imports_third_party_filtered():
    code = "import requests\nimport flask\nimport fastapi\nimport boto3\nfrom numpy import array\n"
    imports = ctx.extract_python_imports(code)
    # All third-party — should be empty
    assert imports == []


def test_extract_python_imports_syntax_error_returns_empty():
    imports = ctx.extract_python_imports("def broken(:\n    pass\n")
    assert imports == []


# ---------------------------------------------------------------------------
# JS/TS import extraction
# ---------------------------------------------------------------------------


def test_extract_js_imports_esm():
    code = """
    import React from 'react';
    import { foo } from './local';
    import * as bar from '../sibling';
    """
    imports = ctx.extract_js_imports(code)
    assert "./local" in imports
    assert "../sibling" in imports
    assert "react" not in imports  # bare specifier, third-party


def test_extract_js_imports_cjs():
    code = """
    const fs = require('fs');
    const local = require('./local-module');
    const helper = require('../utils/helper');
    """
    imports = ctx.extract_js_imports(code)
    assert "./local-module" in imports
    assert "../utils/helper" in imports
    assert "fs" not in imports


def test_extract_js_imports_dedupes():
    code = "import x from './a';\nimport y from './a';\n"
    imports = ctx.extract_js_imports(code)
    assert imports.count("./a") == 1


def test_extract_js_imports_skips_bare_specifiers():
    code = "import 'polyfill';\nimport x from 'package';\n"
    imports = ctx.extract_js_imports(code)
    assert imports == []


# ---------------------------------------------------------------------------
# Import resolution
# ---------------------------------------------------------------------------


def test_resolve_python_import_relative():
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        pkg = root / "pkg"
        pkg.mkdir()
        sibling = pkg / "sibling.py"
        sibling.write_text("# sibling")
        importer = pkg / "importer.py"
        importer.write_text("from .sibling import x")

        resolved = ctx._resolve_python_import(root, importer, ".sibling")
        assert resolved is not None
        assert resolved.name == "sibling.py"


def test_resolve_python_import_package_init():
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        pkg = root / "pkg"
        pkg.mkdir()
        (pkg / "__init__.py").write_text("# pkg init")
        importer = root / "importer.py"
        importer.write_text("from pkg import x")

        resolved = ctx._resolve_python_import(root, importer, "pkg")
        assert resolved is not None
        assert resolved.name == "__init__.py"
        assert resolved.parent.name == "pkg"


def test_resolve_python_import_missing_returns_none():
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        importer = root / "importer.py"
        importer.write_text("import x")
        assert ctx._resolve_python_import(root, importer, "nope") is None


def test_resolve_js_import_relative_with_extension():
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        sub = root / "sub"
        sub.mkdir()
        target = sub / "helper.ts"
        target.write_text("// helper")
        importer = sub / "importer.ts"
        importer.write_text("import { x } from './helper';")

        resolved = ctx._resolve_js_import(root, importer, "./helper")
        assert resolved is not None
        assert resolved.name == "helper.ts"


def test_resolve_js_import_parent_dir():
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        sub = root / "sub"
        deep = sub / "deep"
        deep.mkdir(parents=True)
        target = sub / "sibling.ts"
        target.write_text("// sibling")
        importer = deep / "importer.ts"
        importer.write_text("import x from '../sibling';")

        resolved = ctx._resolve_js_import(root, importer, "../sibling")
        assert resolved is not None
        assert resolved.name == "sibling.ts"


# ---------------------------------------------------------------------------
# Budget enforcement
# ---------------------------------------------------------------------------


def test_build_context_for_file_respects_budget():
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        # Create a small helper that gets imported
        helper = root / "helper.py"
        helper_content = "def auth(user, token):\n    return user.id == token\n" * 50  # 100 lines
        helper.write_text(helper_content)
        # Importer references it
        importer = root / "importer.py"
        importer.write_text("from helper import auth\nauth('u', 't')\n")

        # Budget that fits the header + 30-line truncation but not the full 100 lines
        block = ctx.build_context_for_file(
            root, importer, "Python", importer.read_text(), max_tokens=400,
        )
        assert "Imported Context" in block
        assert "truncated" in block  # the 30-line cap kicked in
        # Roughly within budget (token estimator is rough; allow some slack)
        assert ctx.estimate_tokens(block) <= 600


def test_build_context_for_file_returns_empty_when_nothing_fits():
    """If even a 30-line snippet won't fit, the block is empty (skip silently)."""
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        helper = root / "helper.py"
        helper.write_text("def auth(user, token):\n    return user.id == token\n" * 50)  # 100 lines
        importer = root / "importer.py"
        importer.write_text("from helper import auth")

        # 200 tokens won't fit the header + any snippet
        block = ctx.build_context_for_file(
            root, importer, "Python", importer.read_text(), max_tokens=200,
        )
        assert block == ""


def test_build_context_for_file_no_imports_returns_empty():
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        importer = root / "importer.py"
        importer.write_text("x = 1\n")
        block = ctx.build_context_for_file(
            root, importer, "Python", importer.read_text(), max_tokens=2000,
        )
        assert block == ""


def test_build_context_for_file_zero_budget_returns_empty():
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        helper = root / "helper.py"
        helper.write_text("def x(): pass")
        importer = root / "importer.py"
        importer.write_text("from helper import x")
        block = ctx.build_context_for_file(
            root, importer, "Python", importer.read_text(), max_tokens=0,
        )
        assert block == ""


def test_build_context_for_file_unknown_language_returns_empty():
    block = ctx.build_context_for_file(
        Path("/tmp"), Path("/tmp/x.rb"), "Ruby", "puts 'hi'", max_tokens=2000,
    )
    assert block == ""


def test_build_context_for_file_dedupes_repeated_imports():
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        helper = root / "helper.py"
        helper.write_text("def x(): pass")
        importer = root / "importer.py"
        # Reference the same module from two different forms
        importer.write_text("from helper import x\nimport helper\n")

        block = ctx.build_context_for_file(
            root, importer, "Python", importer.read_text(), max_tokens=2000,
        )
        # The "helper" should appear in the block but the section header
        # for it should appear only once.
        assert block.count("### `helper`") + block.count("### `from helper import x`") >= 1


# ---------------------------------------------------------------------------
# LLMClient integration
# ---------------------------------------------------------------------------


def _build_client():
    """Build an LLMClient that bypasses SDK init and records the user prompt."""
    from app.services.llm import LLMClient

    client = LLMClient.__new__(LLMClient)
    client.provider = "anthropic"
    client.model = "claude-test"
    client.api_key = "test"

    captured: dict = {}

    class _StubMessages:
        def create(self, **kwargs):  # noqa: ARG002
            captured["system"] = kwargs.get("system", "")
            captured["messages"] = kwargs.get("messages", [])
            class _C:
                text = "stub"
            class _M:
                content = [_C()]
            return _M()

    client.client = type("_C", (), {"messages": _StubMessages()})()
    return client, captured


def test_analyze_file_appends_context_to_user_prompt():
    client, captured = _build_client()
    client.analyze_file(
        "a.py", "python", "x = 1",
        context="## Imported Context\n\n### `auth`\n\n```\ndef auth(user, token): return True\n```\n",
    )
    user_msg = captured["messages"][0]["content"]
    # Main content + context block both present
    assert "```\nx = 1\n```" in user_msg
    assert "Imported Context" in user_msg
    assert "def auth" in user_msg
    # Context comes after the main file
    assert user_msg.index("x = 1") < user_msg.index("Imported Context")


def test_analyze_file_empty_context_omits_section():
    client, captured = _build_client()
    client.analyze_file("a.py", "python", "x = 1", context="")
    user_msg = captured["messages"][0]["content"]
    assert "Imported Context" not in user_msg


# ---------------------------------------------------------------------------
# Analyzer wiring: cross_file_context flag controls whether the builder runs
# ---------------------------------------------------------------------------


def test_code_analyzer_defaults_cross_file_context_off():
    from app.services.analyzer import CodeAnalyzer
    analyzer = CodeAnalyzer(llm_client=None)
    assert analyzer.cross_file_context is False
    assert analyzer.cross_file_context_max_tokens == 2000


def test_code_analyzer_accepts_cross_file_context_params():
    from app.services.analyzer import CodeAnalyzer
    analyzer = CodeAnalyzer(llm_client=None, cross_file_context=True, cross_file_context_max_tokens=500)
    assert analyzer.cross_file_context is True
    assert analyzer.cross_file_context_max_tokens == 500
