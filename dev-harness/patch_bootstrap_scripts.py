"""Add proot-distro to the two PrimeTech bootstrap package lists.

Runs on the builder. Idempotent, and it touches exactly one line in each
file, leaving every other PrimeTech change in those scripts alone.
"""

import io
import sys

BUILD = "scripts/build-bootstraps.sh"
GENERATE = "scripts/generate-bootstraps.sh"

BUILD_ANCHOR = '\t\tPACKAGES+=("proot") # PrimeTech: available in every APT bootstrap\n'
BUILD_ADD = ('\t\tPACKAGES+=("proot-distro") '
             '# PrimeTech: deploys canonical Buster OS rootfs releases\n')

GENERATE_ANCHOR = "\tpull_package proot # PrimeTech: available in every APT bootstrap\n"
GENERATE_ADD = ("\tpull_package proot-distro "
                "# PrimeTech: deploys canonical Buster OS rootfs releases\n")


def patch(path, anchor, addition, remove_bad):
    with io.open(path, "r", encoding="utf-8", newline="") as handle:
        text = handle.read()

    # Undo the literal-'t' line a shell quoting mishap left behind.
    if remove_bad in text:
        text = text.replace(remove_bad, "", 1)
        print("  removed the malformed line from %s" % path)

    if addition in text:
        print("  %s already lists proot-distro" % path)
    elif anchor in text:
        text = text.replace(anchor, anchor + addition, 1)
        print("  added proot-distro to %s" % path)
    else:
        print("  ANCHOR NOT FOUND in %s" % path)
        return False

    with io.open(path, "w", encoding="utf-8", newline="") as handle:
        handle.write(text)
    return True


ok = patch(BUILD, BUILD_ANCHOR, BUILD_ADD,
           't\tPACKAGES+=("proot-distro") # PrimeTech: deploys canonical Buster OS rootfs releases\n')
ok = patch(GENERATE, GENERATE_ANCHOR, GENERATE_ADD, "") and ok
sys.exit(0 if ok else 1)
