# `pio run -t rtc_check` / `pio run -t rtc_set`. Deliberately separate commands,
# not something that runs after every upload: the time only needs setting on
# first setup, after a battery change, and for the yearly drift fix.
Import("env")

for mode in ("check", "set"):
    env.AddCustomTarget(
        name=f"rtc_{mode}",
        dependencies=None,
        actions=f'"$PYTHONEXE" "$PROJECT_DIR/tools/rtc_sync.py" {mode}',
        title=f"rtc_{mode}",
        description=f"{mode} the DS3231 over USB serial",
    )
