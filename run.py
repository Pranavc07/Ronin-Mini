#!/usr/bin/env python3
"""Thin launcher so `python run.py ...` keeps working for a direct clone.
The real CLI lives in ronin_mini/run.py -- this just delegates to it so the
package (ronin_mini/) can be pip-installed and imported (e.g. by ronin-pro)
without also needing a copy of this repo-root launcher.
"""

import sys

from ronin_mini.run import main

if __name__ == "__main__":
    sys.exit(main())
