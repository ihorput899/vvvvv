#!/usr/bin/env python3
"""
DorkStrike PRO - Advanced Google Dork Scanner
A comprehensive tool for discovering sensitive information using Google dorks.

Author: Kilo Code
Version: 1.0.0
"""

import sys
import os
import argparse

# Ensure the script can find its modules when run from desktop
script_dir = os.path.dirname(os.path.abspath(__file__))
if script_dir not in sys.path:
    sys.path.insert(0, script_dir)

from ui import DorkStrikeUI
import tkinter as tk

def main():
    """Main entry point for DorkStrike PRO"""
    parser = argparse.ArgumentParser(description="DorkStrike PRO - Advanced Google Dork Scanner")
    parser.add_argument('--cli', action='store_true', help='Run in command line mode (not implemented yet)')
    parser.add_argument('--domain', help='Target domain for CLI mode')
    parser.add_argument('--category', choices=['ALL', 'CRYPTO', 'SECRETS', 'VULNERABILITIES'],
                       default='ALL', help='Pattern category to scan')
    parser.add_argument('--threads', type=int, default=10, help='Number of threads to use')
    parser.add_argument('--output', help='Output file for CLI mode')

    args = parser.parse_args()

    if args.cli:
        print("CLI mode not implemented yet. Use GUI mode.")
        sys.exit(1)

    # GUI Mode
    try:
        root = tk.Tk()
        app = DorkStrikeUI(root)
        root.mainloop()
    except Exception as e:
        print(f"Error starting GUI: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()