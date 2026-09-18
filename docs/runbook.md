# xAuth runbook

For the version of you that has forgotten how any of this works. Commands
assume the production stack from `deploy/` and this shorthand:

```sh
C="docker compose -f deploy/docker-compose.yml --env-file deploy/xauth.env"
KS=/srv/xauth/keystore/auth
```

## Provision a new keychain

**From the dashboard:** sign in with an admin keychain, open **Devices**
(`https://auth.example.com/admin`), enter a label, **Create device**. The page
shows the firmware header once: copy it into
`firmware/xAuth_ID/include/securekey.hpp` on the machine you flash from, then
continue from step 2 below. To make the new keychain an admin too, add its ID
to `ADMIN_DEVICES` in `deploy/xauth.env` and `$C up -d auth-web`.

**From the shell** (no admin keychain at hand, or the dashboard is down):

1. On the machine you flash from (it needs PlatformIO and the repo), create
   the device **and** its firmware header in one step, against the real
   keystore. The easiest way is to run it on the server and copy the header
   over an encrypted channel, then delete it:

   ```sh
   # on the server
   sudo install -d -o 10001 -g 10000 -m 0700 /tmp/fw
   $C run --rm -v /tmp/fw:/out provision add --label "spare keychain" --firmware-header /out/securekey.hpp
   # prints the new ID, e.g. 7Q5V
   scp server:/tmp/fw/securekey.hpp firmware/xAuth_ID/include/securekey.hpp
   ssh server 'sudo shred -u /tmp/fw/securekey.hpp && sudo rmdir /tmp/fw'
   ```

   The header holds the key. It is gitignored; never commit, paste or email it.
2. Flash: `cd firmware/xAuth_ID && pio run -t upload`.
3. Set the time: `pio run -t rtc_set`. Check with `pio run -t rtc_check`:
   `osf=0 state=ok` and a difference of 0 or ±1 s.
4. Delete the header from the laptop too: `shred -u include/securekey.hpp`
   (macOS: `rm -P`). The keystore has the key; the keychain has the key;
   nothing else should.
5. Label the physical device with its ID.
6. Sign in once at the auth site to prove it.

## A keychain is lost or stolen

Dashboard: **Devices → Revoke**. Or from the shell:

```sh
$C run --rm provision revoke 7Q5V
```

That's it. Within `STATUS_CACHE_SECONDS` (default 5 s) every session and
every app token of that device stops working, and its codes are refused.

- Don't `activate` a lost device if it turns up again: whoever had it may
  still hold a session cookie or token that would come back to life.
  Provision a new one instead.
- Check the logs for what it was used for: `$C logs auth-web | grep 7Q5V`.

## A phone with an app token is lost

Sign in on the auth site from a browser, find the token under **App
tokens**, revoke it. The keychain keeps working.

## The keychain shows "SET TIME" / "CLOCK ERROR" / "NO CLOCK"

| Screen | Meaning | Fix |
|---|---|---|
| `SET TIME` | New device, or the RTC battery died / was removed. | `pio run -t rtc_set` |
| `CLOCK ERROR` | The clock is earlier than a time this keychain has already seen. Something moved it back. | `pio run -t rtc_check` to see the offset, then `rtc_set`. If it keeps happening, the RTC module is failing. |
| `NO CLOCK` | The DS3231 isn't on the I2C bus. | Wiring. Expect `0x68`. |

A trusted clock only accepts corrections of up to 5 minutes over USB. If it
is further off than that, it was tampered with or has a hardware fault;
treat the keychain as suspect.

## Codes are refused but the keychain looks fine

1. `pio run -t rtc_check` -- the difference should be within a few seconds.
   The server accepts the previous, current and next 90 s window, so up to
   ~90 s of drift still works; beyond that, resync.
2. Is the device active? `$C run --rm provision list`
3. Is the verifier up? `$C ps`, `$C logs verifier`. `operation not
   permitted` there after an upgrade means the seccomp profile needs
   regenerating: `deploy/seccomp/generate.sh`.
4. Are you rate-limited? Two attempts per 90 s window per device. Wait for
   the next code.

## Locked out of the dashboard

The last active admin device cannot be revoked from the dashboard, but a
lost admin keychain still leaves you without one. SSH in:

```sh
$C run --rm provision revoke <lost>
$C run --rm provision add --label "new admin" --firmware-header ...   # as above
# put the new ID in ADMIN_DEVICES in deploy/xauth.env
$C up -d auth-web
```

## Backups

The keystore is the one thing that cannot be rebuilt. Redis can be lost:
everyone signs in again and app tokens have to be recreated.

One-time: make a GPG key on your laptop (not the server), export only the
public half to the server:

```sh
gpg --quick-gen-key 'xauth backups' default default never
gpg --export --armor 'xauth backups' > xauth-backup.pub   # copy this to the server
# on the server:
gpg --import xauth-backup.pub
```

Nightly, on the server (cron):

```sh
tools/backup-keystore.sh /srv/xauth/keystore/auth /srv/xauth/backups 'xauth backups' \
  && rclone copy /srv/xauth/backups remote:xauth-backups
```

After every provisioning change, and at least monthly, on the laptop:

```sh
tools/restore-test.sh xauth-keystore-<latest>.sqlite.gpg
```

It must say `OK: restorable` and list the devices you expect.

## Restore the keystore

```sh
$C stop verifier
gpg --decrypt xauth-keystore-<date>.sqlite.gpg > /tmp/auth    # on the laptop, then copy
sudo install -o 10001 -g 10000 -m 0600 /tmp/auth /srv/xauth/keystore/auth
shred -u /tmp/auth
$C start verifier
$C run --rm provision list
```

Devices provisioned after that backup are gone: reflash them.

## Recovery: the only keychain is gone

The server is the root of trust, and SSH is the way back in. There is no
recovery code and no bypass on the login page -- anything that could get in
without a keychain would be the weakest point of the whole system.

- **Before it happens:** keep a second keychain, provisioned and labelled
  "backup", in a drawer. With it, recovery is: revoke the lost one, sign in
  with the backup, provision a replacement.
- **Without one:** SSH into the server, `provision revoke` the lost device,
  provision and flash a new one (above). Apps are unreachable through the
  gate until then, by design.

## Alerts

auth-web logs a line starting with `ALERT` when a device's attempt budget is
exhausted or it collects `ALERT_FAILURES_PER_HOUR` failures in an hour. With
`ALERT_WEBHOOK_URL` set, the same goes to that URL as JSON (an ntfy topic
works well).

An alert for a device ID you don't own is someone guessing. It's expected
and harmless at 2 attempts per 90 s -- the odds of guessing a code are about
1 in 10^8 per attempt. An alert for **your** device ID means someone knows
it: watch it, and revoke if you see anything else.

## After changing code

```sh
make test test-verifier            # OTP vectors, verifier cases
cd auth-web && npm test            # web tier
make adversarial                   # the attack suite, with the dev harness up
deploy/seccomp/generate.sh         # if verifier/ or core/ changed
```

Then the hardened-stack run from `deploy/README.md`. All of it must pass
before deploying.

## Upgrading the server

```sh
git pull
deploy/seccomp/generate.sh           # only if verifier/ or core/ changed
$C up -d --build
$C logs --tail 20
```

Sessions and tokens survive (they're in Redis). Then sign in once to check.
