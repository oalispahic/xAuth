import time
from SCons.Script import Import

Import("env")


current_unix_time = int(time.time()) + 10

env.Append(CPPDEFINES=[("COMPILER_UNIX_TIME", current_unix_time)])
print(f"---> Current Unix Time: {current_unix_time} <---")