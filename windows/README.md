# Leshy Windows package

Builds and installs Leshy on Windows as a native service.

## Artifacts

`windows/build-package.ps1` produces:

- `windows/dist/leshy-<version>-x64-setup.exe` — NSIS installer (wizard,
  registers the service, creates the uninstaller);
- `windows/dist/leshy-<version>-windows-x64-portable.zip` — same payload for
  scripted/portable installs via `install-service.ps1`.

## Build

```powershell
./windows/build-package.ps1          # cargo build --release + makensis + zip
./windows/build-package.ps1 -MakensisPath C:\path\to\makensis.exe
```

`makensis.exe` is looked up in PATH and the standard NSIS locations. Without
admin rights on the build machine, use the portable NSIS distribution:

```powershell
curl.exe -L --ssl-no-revoke -o nsis.zip https://prdownloads.sourceforge.net/nsis/nsis-3.11.zip
Expand-Archive nsis.zip .
./nsis-3.11/makensis.exe /VERSION ...   # or pass -MakensisPath to build-package.ps1
```

## Install

```powershell
./leshy-<version>-x64-setup.exe          # wizard, elevated
# or portable:
Expand-Archive leshy-<version>-windows-x64-portable.zip C:\leshy
cd C:\leshy
./install-service.ps1                    # elevated
sc.exe start leshy
```

## File layout after install

| Path | Purpose |
|------|---------|
| `C:\Program Files\leshy\leshy.exe` | binary (installer) |
| `C:\ProgramData\leshy\config.toml` | machine config (kept on upgrade/uninstall) |
| `C:\ProgramData\leshy\run\*.dev` | device files written by the orchestrator |
| `C:\ProgramData\leshy\logs\leshy.log` | service-mode logs, daily rotation |

Uninstall: `uninstall.exe` (installer) or `uninstall-service.ps1` (portable) —
both stop and remove the `leshy` service; `C:\ProgramData\leshy` is kept.

## Service behavior

The service runs as LocalSystem, starts automatically at boot, restarts 5
seconds after a failure, and logs to `C:\ProgramData\leshy\logs\leshy.log`
(stdout is invisible under the Service Control Manager). Point the system DNS
at `127.0.0.1:53053` (see the shipped `config.toml`) and write device files
into `C:\ProgramData\leshy\run\` as VPNs connect — see [docs/windows.md](../docs/windows.md).
