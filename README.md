# ZTNA-SDP — Running the IDP and the Client

This guide covers running the two components involved in the **FIDO2
registration / authentication** flow:

| Component | Directory | What it is |
|-----------|-----------|------------|
| **IDP** (Identity Provider) | `IDENTITY_PROVIDER/` | FastAPI service. Owns accounts, runs the WebAuthn ceremony, issues JWTs. Listens on port **9000**. |
| **Client** (device agent) | `SDP_CLIENT/` | CLI agent. Does first-factor login, selects a hardware trust anchor, runs the FIDO2 ceremony against the IDP. |

> The Gateway and Resource Node are **not** needed for this flow and are
> intentionally left out of this guide. The SDP Controller has been removed
> from the project: its FIDO2/IDP responsibilities live in `IDENTITY_PROVIDER/`, and
> the Gateway now verifies access tokens against the IDP's JWKS directly.

The two processes run **side by side in separate terminals**. Start the IDP
first, provision a user, then start the Client.

---

## What the flow does

1. **Client** prompts for username + password → `POST /auth/login` on the IDP → receives a short-lived `login_token`.
2. **Client** selects a hardware trust anchor: internal TPM → external USB security key → **abort** (there is no software-only fallback).
3. **Client** runs the WebAuthn ceremony against the IDP (`/fido2/register/*` on first run for a device, `/fido2/authenticate/*` afterwards).
4. **IDP** verifies the attestation / assertion signature and issues an access token (15 min) + refresh token.
5. **Client** stays running and auto-refreshes the access token until you stop it with `Ctrl-C`.

On step 3's first run for a device, the client asks the TPM to **certify** the
new credential key, and the IDP refuses to enrol it unless that certification
checks out. See [Hardware attestation](#hardware-attestation) below.

---

## Configuration (both OSes)

All configuration is read from environment variables via `python-dotenv`.
A `.env` file already exists at the project root; `.env.example` documents
every key. The defaults that matter here:

| Variable | Default | Meaning |
|----------|---------|---------|
| `IDP_HOST` / `IDP_PORT` | `0.0.0.0` / `9000` | Address the IDP binds to |
| `IDP_BASE_URL` | `http://localhost:9000` | URL the Client uses to reach the IDP |
| `RP_ID` | `ztna.example.com` | WebAuthn Relying Party ID (Client and IDP must agree; they share this setting). **Must be a registrable domain** — see the warning below |
| `IDP_DB_PATH` | `./data/idp.db` | SQLite DB, created on first start |
| `IDP_JWT_PRIVATE_KEY_PATH` | `./certs/idp_jwt_private.pem` | RS256 signing key, generated on first start |
| `IDP_ENFORCE_TPM_ATTESTATION` | `true` | Refuse to enrol a credential whose hardware custody was not proven |
| `IDP_TPM_ROOT_CA_DIR` | `./certs/tpm_roots` | TPM vendor attestation-CA roots; empty means per-device key pinning instead |

Both the IDP server and the admin CLI resolve `./data` and `./certs`
**relative to the current working directory**, so always run them from
inside `IDENTITY_PROVIDER/`.

---

## Hardware attestation

The project rule is that device identity is hardware-rooted, with no
software-only fallback. Until recently the client asserted that and the IDP
believed it: the credential key really did live in the TPM, but the
registration carried no proof, so a client with no TPM at all could have sent
identical bytes.

It is now proven. On first registration for a device the client asks the TPM
to **certify** the new credential key with a restricted attestation key, and
sends the result as a WebAuthn `fmt="tpm"` attestation statement. The IDP
checks that:

- the attested public area describes the same key as the credential —
  attesting one key while enrolling another is the obvious attack;
- the certified key is marked `fixedTPM`, `fixedParent` and
  `sensitiveDataOrigin`, i.e. the chip generated it and it can never be
  duplicated out;
- the statement is bound to *this* ceremony's challenge, so a captured one
  cannot be replayed;
- the attestation key that signed it is one this deployment trusts.

That last point has two postures. Drop your TPM vendor's attestation-CA root
certificates into `IDP_TPM_ROOT_CA_DIR` and every attestation must chain to
one of them — the only way to prove the chip is genuine silicon rather than a
simulator. With no roots configured (the default, and the only option under a
WSL software TPM) the IDP instead **pins** each device's attestation key on
its first enrolment and requires every later credential from that device to
match. That does not prove the first enrolment came from real hardware, and
the IDP records the difference — `vendor-root` versus `first-ak` / `pinned-ak`
— on the credential and in its logs rather than blurring the two.

The posture is printed at startup:

```
TPM attestation enforced: True
TPM root certificate store: ./certs/tpm_roots
Trusted TPM roots loaded: 0
Attestation-key trust: per-device pinning (no vendor roots configured - genuine silicon is NOT proven)
```

### How each platform proves it

The proof is produced entirely inside the client, so the IDP receives the same
standard WebAuthn attestation in every case and never learns which operating
system it is talking to.

| Trust anchor | How it proves custody | Trust level reachable |
|---|---|---|
| Linux / WSL (`tpm2-tools`) | This client asks the chip to certify the key. Needs `tpm2-tools` and, under WSL, `swtpm` + `swtpm-tools`. | `pinned-ak` — the attestation key is self-issued, so it chains to nothing |
| Windows (Windows Hello) | Windows drives the chip itself and returns a ready-made attestation signed by a Microsoft-issued certificate — once its attestation key is provisioned, see below. | `vendor-root`, if you load Microsoft's roots — genuine hardware actually proven |
| USB security key | The key sends its own `packed` attestation, signed by its manufacturer. | Manufacturer certificate, verified |
| Windows (CNG, fallback) | Cannot. Windows exposes TPM key attestation through CNG only in a Microsoft-specific container, not the WebAuthn one. | none — enrolment refused |

Windows tries Windows Hello **before** CNG: only Hello can attest, and it adds
real user verification (a PIN, face or fingerprint on every sign-in) where CNG
signs silently.

### RP_ID must be a registrable domain, or Windows will not attest

This project originally used `RP_ID=ztna.local`, and on Windows that silently
disabled hardware attestation.

Windows treats an attestation as identifying the machine, so it only releases
one to a relying party whose name it can treat as a real, registrable domain.
`.local` is reserved for multicast DNS and is not registrable. Given such a
name Windows does not fail — it returns a perfectly good credential with
`fmt="none"`, the IDP then refuses the enrolment, and nothing in either
message mentions `RP_ID`.

Measured on a Dell G15 5520 with an Intel firmware TPM, sweeping one variable
at a time with `SDP_CLIENT/tools/webauthn_variants.py`:

| RP_ID | attestation | size |
|---|---|---|
| `ztna.local` | `none` | 194 bytes |
| `localhost` | **`tpm`** | 4002 bytes, full chain |

The options-structure version and the resident-key flag made no difference;
only the name did. The client now warns before the ceremony when `RP_ID` uses
a reserved suffix, rather than leaving the cause to be guessed at.

No DNS lookup is involved — the IDP is reached at `IDP_BASE_URL`, and `RP_ID`
is only the label credentials are bound to — so any registrable name works, as
does `localhost`. Both sides must use the same value, and changing it
invalidates existing credentials, which then re-enrol.

A machine that returns `none` with a good `RP_ID` genuinely cannot attest; use
[an exception](#devices-that-cannot-prove-custody) or a USB security key.
`SDP_CLIENT/tools/attestation_probe.html` checks the same question through a
browser.

Enforcement applies only at registration. Already-enrolled credentials keep
authenticating regardless.

### Devices that cannot prove custody

Some devices genuinely cannot produce the proof, and no client work will
change that. Admit them **one at a time**, never by switching enforcement off
for the whole deployment:

```bash
cd IDENTITY_PROVIDER
.venv/bin/python admin_cli.py grant-attestation-exception \
    --username alice \
    --device-id 45c68349-8936-5716-ae20-d864d2470a2f \
    --days 30 \
    --reason "Dell G15: Windows Hello returns no attestation to any caller"
```

The device id is the `CLIENT_DEVICE_ID` the client prints at startup. The
exception names one user and one device, records who granted it and why,
lapses on its own, and is listed by `list-attestation-exceptions` (revoke with
`revoke-attestation-exception`). Enforcement stays on for every other device,
and a credential enrolled this way is still recorded as **not**
hardware-attested — the exception permits the enrolment, it does not invent a
proof that was never given.

One thing an exception can never do is admit an attestation key that
contradicts the one already pinned to a device. That is not missing evidence
but evidence that the device's hardware root changed, and it is refused
regardless.

---

# Linux / WSL2

## 1. Prerequisites

- Python 3.11 or newer (`python3 --version`)
- `python3-venv` (`sudo apt install python3-venv` on Debian/Kali/Ubuntu)

A pre-built virtual environment already ships in each component
(`IDENTITY_PROVIDER/.venv`, `SDP_CLIENT/.venv`). If it works, skip step 2. Verify:

```bash
cd /path/to/ztna-sdp
IDENTITY_PROVIDER/.venv/bin/python    -c "import fastapi, uvicorn, fido2, jwt, argon2; print('idp deps OK')"
SDP_CLIENT/.venv/bin/python -c "import fido2, cryptography, requests, psutil, dotenv, kyber_py; print('client deps OK')"
```

## 2. (Re)create the virtual environments — only if the check above fails

```bash
cd /path/to/ztna-sdp

python3 -m venv IDENTITY_PROVIDER/.venv
IDENTITY_PROVIDER/.venv/bin/pip install -r IDENTITY_PROVIDER/requirements.txt

python3 -m venv SDP_CLIENT/.venv
SDP_CLIENT/.venv/bin/pip install -r SDP_CLIENT/requirements.txt
```

## 3. Start the IDP  — terminal 1

```bash
cd /path/to/ztna-sdp/IDENTITY_PROVIDER

# one-time: create the account the client will log in as
.venv/bin/python admin_cli.py create-user --username alice
# (you will be prompted to set and confirm a password)

# start the server
.venv/bin/python main.py
```

Leave this running. On first start it creates `data/idp.db` and generates
the RS256 keypair under `certs/`. A `WARNING: IDP_ADMIN_API_KEY is a
default value` line is expected for local dev and is harmless.

Verify from another shell:

```bash
curl http://localhost:9000/healthz            # -> {"status":"ok"}
curl http://localhost:9000/.well-known/jwks.json
```

Useful admin commands (work whether or not the server is running):

```bash
.venv/bin/python admin_cli.py list-users
.venv/bin/python admin_cli.py disable-user --username alice
.venv/bin/python admin_cli.py enable-user  --username alice
```

## 4. Start the Client  — terminal 2

```bash
cd /path/to/ztna-sdp/SDP_CLIENT
.venv/bin/python main.py
```

Enter the username (`alice`) and password when prompted.

**Non-interactive credentials** (skip the prompt — useful when the terminal
does not provide a real stdin): CLI flags override environment variables.

```bash
.venv/bin/python main.py --username alice --password 's3cret'
# or
CLIENT_USERNAME=alice CLIENT_PASSWORD='s3cret' .venv/bin/python main.py
```

To force a fresh registration later, delete the cached credential:

```bash
rm -f /path/to/ztna-sdp/SDP_CLIENT/certs/credentials/*.bin
```

## 5. Trust anchor on Linux / WSL2

The Client resolves its hardware root of trust in this order, and **aborts**
if none is found (no software-only identity fallback):

**Native Linux**

1. **Internal TPM** via `tpm2-tools` against the default device (`/dev/tpmrm0`).
   Install the tools and make sure your user can reach the device:
   ```bash
   sudo apt install tpm2-tools
   tpm2_getcap properties-fixed        # should print TPM properties
   sudo usermod -aG tss $USER          # then log out and back in
   ```
2. **External USB FIDO2 key** — plug one in and touch it when prompted.
3. Otherwise: abort.

**WSL2**

A WSL2 kernel does **not** pass the host's physical TPM through, so step 1
above finds nothing. WSL is therefore the one environment where a **software
TPM** is accepted — it implements the identical TPM2 command set and is the
recognised development stand-in. The Client tries it automatically, but only
under WSL and only after the real-device probe fails.

```bash
sudo apt install swtpm swtpm-tools tpm2-tools

mkdir -p ~/.swtpm/ztna
swtpm socket --tpm2 --server type=tcp,port=2321 \
             --ctrl type=tcp,port=2322 --flags not-need-init \
             --tpmstate dir=$HOME/.swtpm/ztna &
```

The default endpoint is `swtpm:host=127.0.0.1,port=2321`; override it with
`TPM_SWTPM_TCTI` in `.env`. USB keys are also invisible under WSL2 unless
you attach them with [`usbipd-win`](https://github.com/dorssel/usbipd-win).

**Forcing a specific target (any platform)**

Set `TPM_TCTI` in `.env` to override the probe order entirely, e.g.
`TPM_TCTI=device:/dev/tpmrm0` or `TPM_TCTI=swtpm:host=127.0.0.1,port=2321`.

The startup log names which backend served the anchor:
`Trust anchor selected: internal_tpm | backend=tpm2-tools | simulated=False`.

---

# Windows

## 1. Prerequisites

- Python 3.11 or newer from [python.org](https://www.python.org/downloads/) (tick *"Add python.exe to PATH"* during install). Check with `py --version`.
- A USB FIDO2 / CTAP2 security key if you want the Client to complete the ceremony (Windows exposes it to the `fido2` library directly).

> If the repo was ever used under WSL, `IDENTITY_PROVIDER\.venv` and
> `SDP_CLIENT\.venv` already exist as **Linux** virtual environments
> (`bin/python`). They cannot be used from Windows, and `py -m venv .venv`
> will fail with `[WinError 183] Cannot create a file when that file
> already exists`. Use **Option A** (separate Windows venv) or **Option B**
> (delete and recreate) below.
>
> Also use `py`, not `python3` — on Windows `python3` is usually the
> Microsoft Store stub.

## 2. Create the virtual environments

Open **PowerShell** in the project root: `cd D:\path\to\ztna-sdp`

### Option A — keep the WSL venv, add a Windows-only one (recommended for dual use)

```powershell
py -m venv IDENTITY_PROVIDER\.venv-win
IDENTITY_PROVIDER\.venv-win\Scripts\python -m pip install -r IDENTITY_PROVIDER\requirements.txt

py -m venv SDP_CLIENT\.venv-win
SDP_CLIENT\.venv-win\Scripts\python -m pip install -r SDP_CLIENT\requirements.txt
```

With Option A, replace `.venv\Scripts\` with `.venv-win\Scripts\` in every
command in the rest of this Windows guide.

### Option B — delete the stale venv and recreate as `.venv`

Only if you no longer need the WSL venv (it regenerates in seconds under WSL).
Close any WSL shell or editor holding the folder open first.

```powershell
Remove-Item -Recurse -Force IDENTITY_PROVIDER\.venv, SDP_CLIENT\.venv

py -m venv IDENTITY_PROVIDER\.venv
IDENTITY_PROVIDER\.venv\Scripts\python -m pip install -r IDENTITY_PROVIDER\requirements.txt

py -m venv SDP_CLIENT\.venv
SDP_CLIENT\.venv\Scripts\python -m pip install -r SDP_CLIENT\requirements.txt
```

### Verify (adjust the path to `.venv-win` if you chose Option A)

```powershell
IDENTITY_PROVIDER\.venv\Scripts\python -c "import fastapi, uvicorn, fido2, jwt, argon2; print('idp deps OK')"
SDP_CLIENT\.venv\Scripts\python -c "import fido2, cryptography, requests, psutil, dotenv, kyber_py; print('client deps OK')"
```

## 3. Start the IDP  — PowerShell window 1

```powershell
cd D:\path\to\ztna-sdp\IDENTITY_PROVIDER

# one-time: create the account the client will log in as
.venv\Scripts\python admin_cli.py create-user --username alice
# (you will be prompted to set and confirm a password)

# start the server
.venv\Scripts\python main.py
```

Leave it running. First start creates `data\idp.db` and the RS256 keypair
under `certs\`. The `WARNING: IDP_ADMIN_API_KEY is a default value` line is
expected for local dev.

Verify from another PowerShell window:

```powershell
curl.exe http://localhost:9000/healthz
curl.exe http://localhost:9000/.well-known/jwks.json
```

Admin commands:

```powershell
.venv\Scripts\python admin_cli.py list-users
.venv\Scripts\python admin_cli.py disable-user --username alice
.venv\Scripts\python admin_cli.py enable-user  --username alice
```

## 4. Start the Client  — PowerShell window 2

```powershell
cd D:\path\to\ztna-sdp\SDP_CLIENT
.venv\Scripts\python main.py
```

Enter the username (`alice`) and password when prompted, then **touch your
security key** when it asks.

**If the sign-in prompt is skipped** (`=== ZTNA-SDP Client: Sign in ===`
appears and the process exits with no `Username:` line) PowerShell is not
giving Python a console stdin — common when the command is pasted, or run
from the VS Code terminal. Supply credentials non-interactively instead
(CLI flags override environment variables):

```powershell
.venv\Scripts\python main.py --username alice --password 's3cret'
# or
$env:CLIENT_USERNAME = "alice"; $env:CLIENT_PASSWORD = "s3cret"
.venv\Scripts\python main.py
```

To force a fresh registration later:

```powershell
del D:\path\to\ztna-sdp\SDP_CLIENT\certs\credentials\*.bin
```

## 5. Trust anchor on Windows

The Client uses your machine's **onboard TPM**. Windows has no `/dev/tpmrm0`,
no Linux TSS and no `tpm2-tools` build, so it reaches the chip through one of
two Windows interfaces.

Resolution order, aborting if none is found:

1. **Windows Hello** (`SDP_CLIENT/tpm/windows_webauthn.py`) — preferred.
   Windows' own FIDO2 implementation drives the TPM and returns a complete,
   attested credential, which is the only way to prove hardware custody on
   Windows. Requires a Hello PIN (Settings → Accounts → Sign-in options); you
   will be prompted for it, or for face/fingerprint, on each sign-in.
2. **Internal TPM via CNG** (`SDP_CLIENT/tpm/windows_tpm.py`) — fallback when
   Hello is unavailable. The credential key is an ECC P-256 key generated
   inside the TPM and marked non-exportable, stored under a per-user name
   (`ZTNA-SDP-<user>-<hash>`), so nothing is written to disk. It cannot
   produce an attestation, so the IDP will refuse to enrol a new device on
   this path while enforcement is on.
3. **External USB FIDO2 key** — plug one in and touch it when prompted.
4. Otherwise: abort.

Confirm your TPM is usable in an elevated PowerShell:

```powershell
Get-Tpm            # expect TpmPresent : True and TpmReady : True
```

If `TpmReady` is False, enable/clear the TPM in BIOS/UEFI first.

The startup log names the backend that served the anchor:
`Trust anchor selected: internal_tpm | backend=windows-webauthn | simulated=False`.

## 6. Other notes for Windows

- **Posture snapshot** — `main.py` briefly shells out to `ufw` / `iptables`, which do not exist on Windows. This is wrapped in a try/except, never blocks authentication, and only prints a harmless "posture snapshot failed (ignored)" line.
- **Reaching an IDP that runs elsewhere** — if the IDP runs in WSL2 or on another host, set `IDP_BASE_URL` before starting the Client:
  ```powershell
  $env:IDP_BASE_URL = "http://<idp-host-ip>:9000"
  .venv\Scripts\python main.py
  ```

---

## Cross-environment matrix

| Client location | IDP location | `IDP_BASE_URL` | Internal TPM | USB key usable? |
|-----------------|--------------|----------------|--------------|-----------------|
| Native Windows | Native Windows | `http://localhost:9000` (default) | Yes — CNG Platform Crypto Provider | Yes |
| Native Linux | Native Linux | `http://localhost:9000` (default) | Yes — `tpm2-tools` on `/dev/tpmrm0` | Yes |
| WSL2 | Same WSL2 distro | `http://localhost:9000` (default) | No physical TPM; **software TPM (`swtpm`)** | No (unless `usbipd-win`) |
| WSL2 | Windows host | `http://<windows-host-ip>:9000` | No physical TPM; **software TPM (`swtpm`)** | No (unless `usbipd-win`) |
| Native Windows | WSL2 | `http://<wsl2-ip>:9000` | Yes — CNG Platform Crypto Provider | Yes |

`RP_ID` never needs a hosts-file entry: the IDP only string-compares the
WebAuthn origin, and the Client connects using `IDP_BASE_URL`, not `RP_ID`.

---

## Running the tests

Tests live per component and need `pytest`, which is not a runtime dependency:

```bash
cd IDENTITY_PROVIDER    && .venv/bin/pip install pytest && .venv/bin/python -m pytest tests/ -q
cd SDP_CLIENT && .venv/bin/pip install pytest && .venv/bin/python -m pytest tests/ -q
```

The IDP suite covers hardware-attestation enforcement, including an end-to-end
registration against a temporary database. It builds the TPM structures in
software (`IDENTITY_PROVIDER/tests/tpm_fake.py`), so it runs anywhere — no TPM needed —
and every rejection case differs from the valid one in exactly one respect.
The client suite covers what can be checked without a chip: the AK certificate
it issues, the unmarshalling of what `tpm2-tools` writes, and the ceremony
binding. Neither suite substitutes for running the client against a real TPM
or `swtpm`, which has not been done yet.

---

## Troubleshooting

| Symptom | Cause / fix |
|---------|-------------|
| `ModuleNotFoundError` on start | Wrong interpreter — call the venv Python explicitly (`.venv/bin/python` / `.venv\Scripts\python`), or recreate the venv. |
| IDP writes `data/` and `certs/` into the project root | You started it from the wrong directory — always `cd IDENTITY_PROVIDER` first. |
| Client: `No hardware trust anchor available - refusing to connect` | Neither an internal TPM nor a USB key was reachable. Windows: check `Get-Tpm`. Linux: `sudo apt install tpm2-tools` and join the `tss` group. WSL2: start `swtpm` (see the Linux trust-anchor section). Or plug in a USB FIDO2 key. |
| Client: `tpm2-tools not installed - internal TPM path unavailable` | Expected on Windows (the CNG backend is used instead) and on any Linux host without `tpm2-tools`. Only a problem if you meant to use a Linux TPM. |
| Windows: `No internal TPM available through CNG` | The Platform Crypto Provider could not open — TPM absent, disabled in BIOS/UEFI, or not ready. Verify with `Get-Tpm`. |
| Client: `IDP rejected first-factor login` | The account does not exist or is disabled — run `admin_cli.py create-user` / `enable-user`. |
| IDP: `attestation rejected: hardware attestation required` | The client could not prove hardware key custody. Linux/WSL: install tpm2-tools 5.0+ (`tpm2_certify` builds the proof). **Windows: expected** — Windows does not attest to ordinary applications, so grant the device [an exception](#devices-that-cannot-prove-custody) or use a USB security key. |
| Windows: `No Windows Hello platform authenticator on this machine` | Hello is not set up for this user, or the machine has no usable TPM. Add a Hello PIN under Settings → Accounts → Sign-in options. Without it the client falls back to CNG, which cannot prove custody. |
| Windows: `Windows Hello returned NO attestation` | The machine has no TPM, so Hello stored the key in software. The IDP will refuse it, correctly — this device has no hardware root of trust. |
| Windows Security popup: `Something went wrong — There was a problem signing in with your passkey` | Windows Hello was asked to sign for a credential it does not hold, normally one enrolled earlier through the CNG backend. The client now detects this and re-enrols automatically; if you are on an older build, delete `SDP_CLIENT\certs\credentials\*` and run again. |
| IDP: `attestation rejected: untrusted TPM attestation key` | This device already enrolled with a different TPM, or vendor roots are configured and the attestation does not chain to one. If the machine's TPM was genuinely replaced or cleared, delete that device's credentials from the IDP so it can pin the new key. |
| Client: `TPM ATTESTATION FAILED - falling back to a self-attested credential` | `tpm2_certify` errored; its message follows on the same line. The registration that follows will be refused while enforcement is on — fix the TPM error rather than disabling enforcement. |
| Client: sign-in prompt is skipped / exits right after `=== Sign in ===` | No console stdin (pasted command, VS Code terminal, redirected input). Pass `--username` / `--password`, or set `CLIENT_USERNAME` / `CLIENT_PASSWORD`. |
| Client: connection refused to `localhost:9000` | IDP not running, or it is on a different host — set `IDP_BASE_URL`. |
| Client: origin / RP mismatch during the ceremony | `RP_ID` differs between the two processes — keep the same `.env` for both. |
| `WARNING: IDP_ADMIN_API_KEY is a default value` | Expected for local dev; set `IDP_ADMIN_API_KEY` in `.env` for anything real. |
