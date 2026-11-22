"""``py -m quantumnet`` entry point.

The ``__main__`` guard is load-bearing, not decoration: without it, merely
*importing* ``quantumnet.__main__`` (which any tool that walks and imports every
module will do) parses ``sys.argv`` and runs the CLI.  That silently breaks
import audits and makes the package hostile to introspection.
"""

from .cli import main

if __name__ == "__main__":
    main()
