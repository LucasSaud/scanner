#!/usr/bin/env python3
"""
VSCode Security Scanner — Entry Point

Usage:
    uv run python main.py         # Launch GUI (default)
    uv run python main.py --cli   # Run CLI scan
"""

import sys

import customtkinter as ctk

ctk.set_appearance_mode("system")
ctk.set_default_color_theme("blue")


def run_gui():
    from gui.app import VSCodeSecurityScannerApp
    app = VSCodeSecurityScannerApp()
    app.mainloop()


def main():
    args = sys.argv[1:]
    if args and args[0] == "--cli":
        cli_args = args[1:]
        sys.argv = ["cli.py"] + cli_args
        from cli import main as cli_main
        cli_main()
    else:
        run_gui()


if __name__ == "__main__":
    main()
