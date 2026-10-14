"""Import bootstrap for the IDP's tests.

Mirrors the sys.path setup in IDENTITY_PROVIDER/main.py: the component's own directory
becomes the import root and the project root is added so `shared` resolves.
"""

import os
import sys

_TESTS_DIR = os.path.dirname(os.path.abspath(__file__))
_COMPONENT_DIR = os.path.dirname(_TESTS_DIR)
_PROJECT_ROOT = os.path.dirname(_COMPONENT_DIR)

for path in (_PROJECT_ROOT, _COMPONENT_DIR):
    if path not in sys.path:
        sys.path.insert(0, path)
