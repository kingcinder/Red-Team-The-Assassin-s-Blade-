"""Process primitives for the Ligolo daemon lifecycle.

The Mech package deliberately contains no subprocess implementation. This
small boundary keeps process ownership outside ``core/mech`` while allowing
the Ligolo API manager to inject/mock the process constructor in tests.
"""
import subprocess

Popen = subprocess.Popen
TimeoutExpired = subprocess.TimeoutExpired
STDOUT = subprocess.STDOUT
DEVNULL = subprocess.DEVNULL
