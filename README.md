# cpa-codex-auth

Configure an OpenAI account, complete Codex OAuth, and save an add-or-replace CPA credential JSON with WebSocket support enabled.

## Usage

```powershell
.\cpa-codex-auth.exe --email user@example.com --password "current-password" --totpsecret "CURRENT_TOTP_SECRET"
```

`--password` and `--totpsecret` are optional. Missing values are requested interactively when the account requires them.

Additional flags:

- `--proxy`: HTTP or SOCKS proxy URL used by authentication and the headless Sentinel fallback.
- `--output`, `-o`: credential output directory. Defaults to the current directory.
- `--rotate`: disable the current authenticator, reset the password through email OTP, enroll a new TOTP secret, print both generated values, and finish OAuth with them.

The saved filename is stable (`codex-<email>-plus.json`), so running the command again replaces the existing CPA credential atomically.

## Build

```powershell
go build -o cpa-codex-auth.exe .
```

Every push to `main` uses GoReleaser to replace the `snapshot` prerelease with archives for Windows, macOS, and Linux on amd64 and arm64. The release also includes `checksums.txt`, and the `snapshot` tag always points to the commit used for the latest build.
