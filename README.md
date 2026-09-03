# ZTNA-SDP — Running the IDP and the Client

This guide covers running the two components involved in the **FIDO2
registration / authentication** flow:

| Component | Directory | What it is |
|-----------|-----------|------------|
| **IDP** (Identity Provider) | `sdp-idp/` | FastAPI service. Owns accounts, runs the WebAuthn ceremony, issues JWTs. Listens on port **9000**. |
| **Client** (device agent) | `sdp-client/` | CLI agent. Does first-factor login, selects a hardware trust anchor, runs the FIDO2 ceremony against the IDP. |

> The Gateway and Resource Node are **not** needed for this flow and are
> intentionally left out of this guide. The SDP Controller has been removed
> from the project: its FIDO2/IDP responsibilities live in `sdp-idp/`, and
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

---

## Configuration (both OSes)

All configuration is read from environment variables via `python-dotenv`.
A `.env` file already exists at the project root; `.env.example` documents
every key. The defaults that matter here:

| Variable | Default | Meaning |
|----------|---------|---------|
| `IDP_HOST` / `IDP_PORT` | `0.0.0.0` / `9000` | Address the IDP binds to |
| `IDP_BASE_URL` | `http://localhost:9000` | URL the Client uses to reach the IDP |
| `RP_ID` | `ztna.local` | WebAuthn Relying Party ID (Client and IDP must agree; they share this setting, so no change needed) |
| `IDP_DB_PATH` | `./data/idp.db` | SQLite DB, created on first start |
| `IDP_JWT_PRIVATE_KEY_PATH` | `./certs/idp_jwt_private.pem` | RS256 signing key, generated on first start |

Both the IDP server and the admin CLI resolve `./data` and `./certs`
**relative to the current working directory**, so always run them from
inside `sdp-idp/`.

---

# Linux / WSL2

## 1. Prerequisites

- Python 3.11 or newer (`python3 --version`)
- `python3-venv` (`sudo apt install python3-venv` on Debian/Kali/Ubuntu)

A pre-built virtual environment already ships in each component
(`sdp-idp/.venv`, `sdp-client/.venv`). If it works, skip step 2. Verify:

```bash
cd /path/to/ztna-sdp
sdp-idp/.venv/bin/python    -c "import fastapi, uvicorn, fido2, jwt, argon2; print('idp deps OK')"
sdp-client/.venv/bin/python -c "import fido2, cryptography, requests, psutil, dotenv, kyber_py; print('client deps OK')"
```

## 2. (Re)create the virtual environments — only if the check above fails

```bash
cd /path/to/ztna-sdp

python3 -m venv sdp-idp/.venv
sdp-idp/.venv/bin/pip install -r sdp-idp/requirements.txt

python3 -m venv sdp-client/.venv
sdp-client/.venv/bin/pip install -r sdp-client/requirements.txt
```

## 3. Start the IDP  — terminal 1

```bash
cd /path/to/ztna-sdp/sdp-idp

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
cd /path/to/ztna-sdp/sdp-client
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
rm -f /path/to/ztna-sdp/sdp-client/certs/credentials/*.bin
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

> If the repo was ever used under WSL, `sdp-idp\.venv` and
> `sdp-client\.venv` already exist as **Linux** virtual environments
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
py -m venv sdp-idp\.venv-win
sdp-idp\.venv-win\Scripts\python -m pip install -r sdp-idp\requirements.txt

py -m venv sdp-client\.venv-win
sdp-client\.venv-win\Scripts\python -m pip install -r sdp-client\requirements.txt
```

With Option A, replace `.venv\Scripts\` with `.venv-win\Scripts\` in every
command in the rest of this Windows guide.

### Option B — delete the stale venv and recreate as `.venv`

Only if you no longer need the WSL venv (it regenerates in seconds under WSL).
Close any WSL shell or editor holding the folder open first.

```powershell
Remove-Item -Recurse -Force sdp-idp\.venv, sdp-client\.venv

py -m venv sdp-idp\.venv
sdp-idp\.venv\Scripts\python -m pip install -r sdp-idp\requirements.txt

py -m venv sdp-client\.venv
sdp-client\.venv\Scripts\python -m pip install -r sdp-client\requirements.txt
```

### Verify (adjust the path to `.venv-win` if you chose Option A)

```powershell
sdp-idp\.venv\Scripts\python -c "import fastapi, uvicorn, fido2, jwt, argon2; print('idp deps OK')"
sdp-client\.venv\Scripts\python -c "import fido2, cryptography, requests, psutil, dotenv, kyber_py; print('client deps OK')"
```

## 3. Start the IDP  — PowerShell window 1

```powershell
cd D:\path\to\ztna-sdp\sdp-idp

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
cd D:\path\to\ztna-sdp\sdp-client
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
del D:\path\to\ztna-sdp\sdp-client\certs\credentials\*.bin
```

## 5. Trust anchor on Windows

The Client uses your machine's **onboard TPM** directly. Windows has no
`/dev/tpmrm0`, no Linux TSS and no `tpm2-tools` build, so the Client talks
to the chip through CNG's **Microsoft Platform Crypto Provider**
(`sdp-client/tpm/windows_tpm.py`). The credential key is an ECC P-256 key
generated inside the TPM and marked non-exportable — every WebAuthn
signature is produced by the chip, exactly as on Linux.

Resolution order, aborting if none is found:

1. **Internal TPM** via CNG. Confirm yours is usable in an elevated PowerShell:
   ```powershell
   Get-Tpm            # expect TpmPresent : True and TpmReady : True
   ```
   If `TpmReady` is False, enable/clear the TPM in BIOS/UEFI first.
2. **External USB FIDO2 key** — plug one in and touch it when prompted.
3. Otherwise: abort.

The key is stored in the TPM under a per-user name (`ZTNA-SDP-<user>-<hash>`),
so nothing is written to disk and later runs reload the same credential.

The startup log names the backend that served the anchor:
`Trust anchor selected: internal_tpm | backend=windows-cng | simulated=False`.

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

## Troubleshooting

| Symptom | Cause / fix |
|---------|-------------|
| `ModuleNotFoundError` on start | Wrong interpreter — call the venv Python explicitly (`.venv/bin/python` / `.venv\Scripts\python`), or recreate the venv. |
| IDP writes `data/` and `certs/` into the project root | You started it from the wrong directory — always `cd sdp-idp` first. |
| Client: `No hardware trust anchor available - refusing to connect` | Neither an internal TPM nor a USB key was reachable. Windows: check `Get-Tpm`. Linux: `sudo apt install tpm2-tools` and join the `tss` group. WSL2: start `swtpm` (see the Linux trust-anchor section). Or plug in a USB FIDO2 key. |
| Client: `tpm2-tools not installed - internal TPM path unavailable` | Expected on Windows (the CNG backend is used instead) and on any Linux host without `tpm2-tools`. Only a problem if you meant to use a Linux TPM. |
| Windows: `No internal TPM available through CNG` | The Platform Crypto Provider could not open — TPM absent, disabled in BIOS/UEFI, or not ready. Verify with `Get-Tpm`. |
| Client: `IDP rejected first-factor login` | The account does not exist or is disabled — run `admin_cli.py create-user` / `enable-user`. |
| Client: sign-in prompt is skipped / exits right after `=== Sign in ===` | No console stdin (pasted command, VS Code terminal, redirected input). Pass `--username` / `--password`, or set `CLIENT_USERNAME` / `CLIENT_PASSWORD`. |
| Client: connection refused to `localhost:9000` | IDP not running, or it is on a different host — set `IDP_BASE_URL`. |
| Client: origin / RP mismatch during the ceremony | `RP_ID` differs between the two processes — keep the same `.env` for both. |
| `WARNING: IDP_ADMIN_API_KEY is a default value` | Expected for local dev; set `IDP_ADMIN_API_KEY` in `.env` for anything real. |
