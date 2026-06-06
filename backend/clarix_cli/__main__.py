"""Run Clarix CLI as a module: `python -m clarix_cli ...`"""
from clarix_cli.cli import main

if __name__ == "__main__":
    raise SystemExit(main())
