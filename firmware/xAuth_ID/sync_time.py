# Injects the build time as COMPILER_UNIX_TIME. The firmware uses it only as a
# floor -- no valid clock reading can be earlier than the build -- never as
# the time to set. The time itself is set over USB with tools/rtc_sync.py.
import time
from SCons.Script import Import

Import("env")

build_time = int(time.time())
env.Append(CPPDEFINES=[("COMPILER_UNIX_TIME", build_time)])
print(f"---> Build time floor: {build_time} <---")
