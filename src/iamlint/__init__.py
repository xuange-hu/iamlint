"""iamlint - AWS IAM policy audit with the line, column and bytes that prove it.

Zero runtime dependencies. The public surface is small on purpose:
:func:`analyze_paths`, :func:`analyze_text`, :func:`run_demo`.
"""

from __future__ import annotations

__version__ = "0.1.0"

__all__ = ["__version__", "analyze_paths", "analyze_text", "rule_ids"]
