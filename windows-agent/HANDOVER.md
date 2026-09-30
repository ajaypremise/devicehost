# WindowsProtect setup handover (0.5.6-test)

New setup registers the PC once and starts the WindowsProtect service in **pending** mode. Pending mode reports telemetry and keeps the approved support agent available; it does not run remote-tool blocking or change the security baseline.

The installer keeps its progress bar moving while DeviceHost:

1. Authenticates the device token and reads this device's recently reported node ID.
2. Opens an authenticated, TLS-verified MeshCentral desktop tunnel.
3. Requires desktop dimensions and a JPEG tile, not just relay pairing or online status. Screen bytes are discarded and are not returned to the device or stored.
4. Sends a fixed PowerShell command through approved support to write a fresh 256-bit challenge in the administrator-only setup directory.

The installer requires both server desktop verification and the exact fresh local challenge file. It then persists activation in HKLM and requests a service check. The service applies the baseline, blocks listed unauthorized remote tools, and writes the activation acknowledgment. Only then does setup display **Installation complete - Protected**.

Support verification has a 60-second budget; service activation confirmation has a separate 45-second budget. If support verification fails, protection remains pending and the existing remote tool remains available. **Retry support check** resumes this checkpoint without redeeming a new code, registering another device or reinstalling components. Reopening setup also reuses registration, although it runs component repair before verification.

Once activation is persisted, a lost support connection or failed final acknowledgment never changes it back to pending. Retry then finishes acknowledgment. Existing protected legacy PCs are migrated to active; updates preserve active state. A pending installation is never inferred to be active just because its service already exists.

Verification in CI:

- Windows checks: real correct/wrong passwords, blank fields, no credential write on rejection, layout, persistent pending/active state across initialization, legacy migration, and rejection of absent/stale local proof or missing desktop verification.
- App checks: real WebSocket protocol fixtures, fragmented/jumbo desktop frames, relay-only and size-only failures, denied commands, TLS requirements, device-token authentication, and stale/missing device support identity.

An actual installation on the disposable Windows test PC is still required to exercise the live deployed support server and endpoint together. The automated probe proves desktop streaming and command execution at activation time; it cannot guarantee future network availability.

Protocol references: MeshCentral's `meshctrl.js`, `public/scripts/agent-redir-ws-0.1.1.js` and `public/scripts/agent-desktop-0.0.2.js` in https://github.com/Ylianst/MeshCentral.
