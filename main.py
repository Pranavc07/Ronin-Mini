#!/usr/bin/env python3
"""Thin launcher so `python main.py ...` keeps working for a direct clone.
The real CLI lives in ronin_mini/main.py -- see run.py's docstring for why.
"""

import sys

from ronin_mini.main import main

if __name__ == "__main__":
    sys.exit(main())
