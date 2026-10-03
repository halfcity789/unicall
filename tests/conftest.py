"""conftest: make sibling imports (pe_builder) work inside tests."""
import os
import sys

sys.path.insert(0, os.path.dirname(__file__))
