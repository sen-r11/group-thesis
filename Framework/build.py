# Packs the framework into one exe that runs without Python installed

# python build.py
#
# The result is dist\gthesis.exe. PyInstaller is needed to build it, but not
# to run it: the exe carries its own Python and the pywin32 pieces the live
# channel needs. Build it on the same kind of Windows it will run on.

import os
import shutil
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
NAME = "gthesis"
ENTRY = "gthesis.py"
DATA = ["sysmon-config.xml"]

# The rules are imported through Detection.indicators, and the alert
# formatter through a try block, so they are named here to be certain they
# are packed
HIDDEN = [
    "win32evtlog", "win32event", "win32api", "win32con",
    "Alerts.formatting", "Alerts.io_utils", "Alerts.alertGenerator",
    "Detection.engine", "Detection.state", "Detection.indicators",
    "Evaluation.corpus",
]


def main():
    try:
        import PyInstaller  # noqa: F401
    except ImportError:
        print("error: PyInstaller is missing. Install it with:", file=sys.stderr)
        print("  pip install pyinstaller", file=sys.stderr)
        return 2

    command = [sys.executable, "-m", "PyInstaller", "--noconfirm", "--onefile",
               "--console", "--name", NAME, "--distpath", os.path.join(HERE, "dist"),
               "--workpath", os.path.join(HERE, "build"),
               "--specpath", os.path.join(HERE, "build")]

    for name in DATA:
        source = os.path.join(HERE, name)
        if os.path.isfile(source):
            command += ["--add-data", "%s%s." % (source, os.pathsep)]

    for name in HIDDEN:
        command += ["--hidden-import", name]

    command.append(os.path.join(HERE, ENTRY))

    print("building %s.exe" % NAME)
    finished = subprocess.run(command, cwd=HERE)
    if finished.returncode != 0:
        return finished.returncode

    exe = os.path.join(HERE, "dist", NAME + ".exe")
    if not os.path.isfile(exe):
        print("error: the build reported success but produced no exe",
              file=sys.stderr)
        return 2

    size = os.path.getsize(exe) / (1024 * 1024)
    print("")
    print("built %s  (%.1f MB)" % (exe, size))
    print("")
    print("Copy it to the analysis VM. It needs no Python and no packages.")
    print("Sysmon still has to be installed there, and the channel still")
    print("needs administrator rights, which the exe asks for itself.")

    # The working folders are large and rebuildable
    shutil.rmtree(os.path.join(HERE, "build"), ignore_errors=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
