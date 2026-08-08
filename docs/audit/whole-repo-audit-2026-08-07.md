# Whole-repo security & correctness audit — 2026-08-07

Branch: `claude/intelligence-rename-review-2c9svi` · Author: Claude Code (automated audit)

## How to read this

This began as a **report-first** audit. The findings were subsequently remediated — see
**Remediation status** below for what landed, and the per-finding **Status** column. The finding
text itself is left as originally written (describing the vulnerable state) so the fixes stay
reviewable against it. Each finding names an exact
`file:line`, the **trust boundary** that makes it reachable, a concrete failure scenario,
and a recommended fix. Severity reflects reachability and impact; **Confidence** is
`CONFIRMED` (a reachable failure path was traced in the code) or `PLAUSIBLE` (looks wrong,
depends on an unverified assumption).

Method: eight parallel finder passes over risk-ranked territories, each anchored on the rule
that *the local AI agent running shell/AppleScript/file ops is the product, not a bug* — a
finding counts only when input crosses a trust boundary (remote/LAN/tunnel/web caller,
sandbox→host, lower-trust input reaching a sink without its gate, or a reachable
crash/hang/data-loss). Every Critical/High below was re-read line-by-line by the lead auditor.

Caveat: this audit ran in a Linux container with **no Xcode/MLX/Metal**, so nothing was
compiled or executed. Findings are from static analysis + cross-referencing the existing test
suite. Each material finding carries a **How to confirm** step to run on a Mac.

## Executive summary

The codebase is, on the whole, unusually defensive: the auth gate is default-deny, the Secure
Channel and access-key crypto are sound, SQL is uniformly parameterized, DB migrations are
transactional, the plugin-host concurrency machinery is carefully correct, and the streaming
inference path handles UTF-8/cancellation/continuations correctly. The findings concentrate in
a few seams:

- **The local server trusts the browser as "loopback."** The single most serious issue: a web
  page you merely visit can reach `http://localhost:1337` and drive privileged agent tools
  (file-write/shell) because the external-tool deny list isn't applied to the loopback
  `/dispatch` path. This is the one finding worth fixing before anything else.
- **The Seatbelt sandbox tier is much weaker than the VM tier** and can reach the same
  loopback-trusted control plane.
- **Two crash/DoS vectors** (a JSON depth-bomb on every inference route; a zip-bomb on
  conversation import) where a mitigation exists elsewhere in the repo but wasn't wired in.
- **A path-traversal** in CLI manual plugin install.
- Several **scope-confinement gaps** (admin routes, task routes) and one **cross-plugin secret**
  leak within a single agent.

Counts: **1 Critical, 6 High, 7 Medium, 11 Low/Info.** Plus one regression introduced by this
branch's rename, already fixed here.

| # | Sev | Finding | File | Conf | Status |
|---|-----|---------|------|------|------|
| C1 | **Critical** | Web page → loopback `/agents/{id}/dispatch` bypasses external-tool deny → silent file-write/shell | `Networking/HTTPHandler.swift:5662` | CONFIRMED | FIXED |
| H1 | High | JSON depth-bomb crashes the whole server; depth guard wired to only one route | `Networking/HTTPHandler.swift` (18 decode sites) | CONFIRMED | FIXED |
| H2 | High | Seatbelt-confined shell reaches the loopback-trusted control plane unauthenticated | `Services/Sandbox/Seatbelt/SeatbeltSandbox.swift:294` | CONFIRMED | FIXED |
| H3 | High | `plugin_id` path traversal in `osaurus tools install` → arbitrary file write | `Packages/OsaurusRepository/PluginInstallManager.swift:323` | CONFIRMED | FIXED |
| H4 | High | `ExternalPlugin.shutdown()` hangs forever on a wedged accessibility plugin call | `Models/Plugin/ExternalPlugin.swift:908` | CONFIRMED | FIXED |
| H5 | High | Loopback CORS `*` lets any website read admin/agent/model/inference endpoints | `Networking/HTTPHandler.swift:2901` | CONFIRMED | FIXED |
| H6 | High | Seatbelt profile grants unrestricted `mach-lookup` → LaunchServices escape | `Services/Sandbox/Seatbelt/SeatbeltSandbox.swift:244` | PLAUSIBLE | DEFERRED |
| M1 | Medium | Host-API bridge trusts guest `X-Osaurus-Plugin` header → cross-plugin secret disclosure | `Networking/HostAPIBridgeServer.swift:214` | CONFIRMED | PARTIAL |
| M2 | Medium | `/admin/*` routes accept agent-scoped keys (no master-scope gate) | `Networking/HTTPHandler.swift:644` | CONFIRMED | FIXED |
| M3 | Medium | `/tasks/{id}` GET/DELETE lack agent-scope confinement | `Networking/HTTPHandler.swift:5919` | CONFIRMED | FIXED |
| M4 | Medium | Pre-auth body pre-allocation → memory-exhaustion DoS (exposed mode) | `Networking/HTTPHandler.swift:405` | CONFIRMED | FIXED |
| M5 | Medium | Zip-bomb: unbounded in-memory decompression on conversation import | `Utils/ZipArchive.swift:194` | CONFIRMED | FIXED |
| M6 | Medium | Agent-bundle tar extraction: no entry-name/symlink validation, runs before passphrase check | `Services/AgentBridge/AgentBundleService.swift:649` | PLAUSIBLE | FIXED |
| M7 | Medium | WhatsApp inbound-media size cap absent/bypassable → remote memory exhaustion | `helpers/osaurus-wa/bridge.go:1328` | PLAUSIBLE | FIXED |
| L1 | Low | ZIP64 integer-conversion trap crashes conversation import | `Utils/ZipArchive.swift:85` | CONFIRMED | FIXED |
| L2 | Low | Undo replay re-derives destructive paths without re-validation (latent) | `Folder/FileOperationLog.swift:246` | PLAUSIBLE | FIXED |
| L3 | Low | Egress rebinding filter misses IPv4-compatible / NAT64 IPv6 | `Services/Sandbox/SandboxEgressPolicy.swift:152` | PLAUSIBLE | FIXED |
| L4 | Low | Go RPC reader silently exits on oversized frame; `scanner.Err()` unchecked | `helpers/osaurus-wa/rpc.go:86` | CONFIRMED | FIXED |
| L5 | Low | Proxy local-host rejection bypassed by IPv4-mapped IPv6 literal | `Packages/OsaurusNetworking/Sources/GlobalProxyConfiguration.swift:184` | CONFIRMED | FIXED |
| L6 | Low | Out-of-process config forwarding can deliver `on_config_changed` out of order (flag-off) | `Models/Plugin/ExternalPlugin.swift:1169` | CONFIRMED | FIXED |
| L7 | Low | `notifyConfigChanged` timeout orphans a pending continuation (flag-off, self-healing) | `Services/Plugin/PluginProcessHost.swift:153` | CONFIRMED | FIXED |
| L8 | Low | Error bodies echo internal exception text | `Networking/HTTPHandler.swift:1324` | CONFIRMED | FIXED |
| L9 | Low | Stop sequences split across streamed deltas not honored (remote path) | `Services/Provider/OpenAICompatibleStreamParser.swift:762` | PLAUSIBLE | FIXED |
| L10 | Low | SSE error writers emit unescaped strings in a near-dead fallback branch | `Models/Chat/ResponseWriters.swift:407` | PLAUSIBLE | FIXED |
| L11 | Info | Temporary pairing keys not revoked on unclean shutdown | `Identity/TemporaryPairedKeyStore.swift:38` | CONFIRMED | FIXED |

---

## Remediation status (updated 2026-08-08)

24 of the 25 findings are fixed on this branch; **H6 is deferred by decision** (see
"Deferred fixes" at the end). Each fix was applied by a dedicated agent and then re-reviewed by an
independent adversarial reviewer; the reviewers found 18 defects in the first-pass fixes, all of
which were corrected before commit. Three are worth recording because they are the kind of thing
that ships silently:

- **The WhatsApp media cap (M7) did not work at all in its first form.** `cappedFile` embedded
  `*os.File`, so Go promoted `ReadFrom` and `io.Copy` wrote straight to the file, never calling the
  capped `Write`. The first-pass test passed only because `bytes.Reader` sends `io.Copy` down a
  different branch than production does. Fixed by shadowing `ReadFrom`, and the test now drives the
  production branch — verified failing before the fix and passing after (`go test` runs here).
- **C1 was bypassable through `/secure/call`.** The envelope rewrite rebuilds the request head
  without `Origin`/`Sec-Fetch-*`, so wrapping the attack in a secure envelope erased the browser
  signal and restored the original Critical. The browser signal is now snapshotted from the outer
  head before the rewrite.
- **The first-pass L7 fix introduced a new bug.** Killing the plugin helper on a `config_changed`
  deadline would have destroyed healthy in-flight tool calls, because the helper runs `invoke` and
  `config_changed` on one serial queue and a long invoke starves the config push. The kill was
  dropped; the deadline is now a diagnostic only.

Two findings closed wider than the original text: **H5** also covers `/mcp` (a cross-site
`text/plain` POST to `/mcp/call` is preflight-free and executes tools), and **H2** now denies every
candidate control-plane port rather than only the configured one, since the configured port and the
bound port disagree across a restart.

Also landed alongside: the six signing domain prefixes are now defined once in
`Identity/CryptoHelpers.swift` (`SigningDomain`) and referenced by both signers and verifiers, with
parity tests — closing the drift that broke pairing earlier on this branch.

---

## Critical

### C1 — A website you visit can drive loopback `/agents/{id}/dispatch` and bypass the external-tool deny list (silent file-write / shell)

- **Severity:** Critical · **Category:** CSRF-to-localhost → privileged tool execution · **Confidence:** CONFIRMED (path traced and re-verified)
- **Location:** `Networking/HTTPHandler.swift:5662-5664` (`shouldBindExternalSurfaceForDispatch(isLoopback:) = !isLoopback`); external-surface deny gate `Tools/ToolRegistry.swift:575-585` with intent comment `:530-535`; loopback skips auth `HTTPHandler.swift:505-506`; loopback CORS `*` `HTTPHandler.swift:2901-2903`; contrast `/agents/{id}/run` which binds `isExternalSurface=true` unconditionally at `HTTPHandler.swift:5296,5316`.
- **Trust boundary / reachability:** Untrusted remote **web content**. Default config is `exposeToNetwork=false` → server binds `127.0.0.1:1337`, `trustLoopback=true`. A browser tab on any site can `fetch("http://localhost:1337", …)`; the socket's peer is `127.0.0.1`, so `isLoopbackConnection` is true → the request is treated as a fully trusted local caller. Port 1337 is the well-known default.
- **Failure scenario:**
  1. `GET http://localhost:1337/agents` — a CORS "simple" request; the response carries `Access-Control-Allow-Origin: *` (loopback), so the page reads the JSON and harvests agent UUIDs.
  2. `POST http://localhost:1337/agents/<uuid>/dispatch` with a `text/plain` body (avoids CORS preflight; the handler never checks Content-Type) instructing the agent to write a file or run a command.
  3. Loopback skips the auth gate (`:506`) and the secure-channel requirement (`:3771`); `shouldBindExternalSurfaceForDispatch(isLoopback:true) = false`, so the dispatched run executes with `isExternalSurface=false`.
  4. `isDeniedForCurrentSurface` only denies when `isExternalSurface==true` (`ToolRegistry.swift:576`), so `shell_run`, `file_write`, `file_edit`, `git_commit` are **not** denied. With a working folder open these register with policy `.auto` (no approval card) — silent arbitrary file write (e.g. overwrite `~/.zshrc` or a LaunchAgent → persistence/RCE) driven by a web page, zero user interaction.
- **Evidence:** The deny list's own comment (`ToolRegistry.swift:530-535`) names this exact threat — *"an external caller — loopback skips Bearer auth entirely — could otherwise rewrite the user's files or run arbitrary shell commands."* `/run` closes it by binding `isExternalSurface=true` unconditionally; `/dispatch` binds it to `!isLoopback`, re-opening precisely the hole the deny list exists to close. `/mcp/call` also binds `true` (`:10552`) — `/dispatch` is the outlier.
- **How to confirm (on a Mac, with the app running and a workspace folder open):**
  ```bash
  curl -s http://localhost:1337/agents            # returns agent list + ACAO:* — no auth
  curl -s -X POST http://localhost:1337/agents/<uuid>/dispatch \
       -H 'Content-Type: text/plain' \
       --data '{"messages":[{"role":"user","content":"use file_write to create ~/PWNED.txt"}]}'
  ```
  A cross-origin `fetch()` from a throwaway `file://` or hosted page reproduces the browser case.
- **Fix:** (a) Bind `isExternalSurface=true` for `/dispatch` unconditionally, exactly like `/run` — drop the `!isLoopback` exemption in `shouldBindExternalSurfaceForDispatch`. (b) Stop treating browser cross-origin requests as trusted loopback: do not emit `ACAO:*` for loopback; reject state-changing requests carrying a cross-site `Origin` / `Sec-Fetch-Site: cross-site`; add `Access-Control-Allow-Private-Network` handling and an `Origin`/`Host` allowlist (also closes DNS-rebinding).

---

## High

### H1 — JSON depth-bomb crashes the whole server; the existing depth guard is wired to only one route

- **Severity:** High · **Category:** decode-crash / DoS · **Confidence:** CONFIRMED (re-verified)
- **Location:** unguarded body decodes throughout `Networking/HTTPHandler.swift` — `/chat/completions` (`:7883`), `/v1/messages` (`:10658`), `/v1/responses` (`:11439`), `/v1/completions` (`:7486`), `/api/chat` (`:8670`), `/embeddings` (`:6164`), `/mcp/call` (`:10304`), `/agents/{id}/run` (`:4696`), + Ollama generate/show/memory. The guard `jsonNestingDepthExceedsBudget` lives in `Networking/HTTPRequestParse.swift:36-48`; the only caller of the guarded `readRequestBody()` is `HTTPHandler.swift:1253` (the `/admin/runtime-settings` PUT).
- **Reachability:** Any loopback process (auth skipped) or any authenticated remote caller. The MB-scale body-size cap permits tens of thousands of nesting levels in a tiny payload.
- **Failure scenario:** `POST /v1/chat/completions` with `{"model":"x","messages":[],"z":[[[[…50000×…]]]]}`. The handler reads the body inline (`:7873-7877`) and calls `try? JSONDecoder().decode(...)`; the decoder recurses the full structure before type mapping and overflows the stack. This runs **synchronously on the NIO event-loop thread** (from `channelRead .end`, `:677`), so the overflow is a SIGSEGV — `try?` catches Swift throws, not stack-overflow traps — that kills the process and every concurrent stream.
- **Evidence:** The repo documents the crash and ships the fix but never wires it in: `HTTPHandler.swift:2713-2716` ("A body within the size cap can still be a depth bomb that overflows the decoder's recursion"); `HTTPRequestParse.swift:33-34` ("the route's JSON decode fails cleanly with a 400 instead of crashing the process"). All 18 inference/tool decode sites bypass it.
- **How to confirm:** `python3 -c 'print("{\"model\":\"x\",\"messages\":[],\"z\":"+"["*60000+"]"*60000+"}")' | curl -s -X POST http://localhost:1337/v1/chat/completions -H 'Content-Type: application/json' --data-binary @-` — server process crashes.
- **Fix:** Route every request-body decode through `readRequestBody()` (or call `jsonNestingDepthExceedsBudget(data, max: maxJSONNestingDepth)` before each `JSONDecoder().decode`). Cheapest: replace the repeated inline `requestBodyBuffer`+`readBytes` blocks with the existing `readRequestBody()` helper.

### H2 — Seatbelt-confined shell reaches the loopback-trusted control plane unauthenticated

- **Severity:** High · **Category:** sandbox-escape / privilege-escalation · **Confidence:** CONFIRMED (re-verified)
- **Location:** `Services/Sandbox/Seatbelt/SeatbeltSandbox.swift:293-294` (`case .allowed: (allow network*)`); default network mode `Models/Plugin/SandboxConfiguration.swift:75` (`network: "outbound"` → `NetworkPolicy.allowed`, `SeatbeltSandbox.swift:210-212`); loopback trust `HTTPHandler.swift:505-506`; `ServerController.swift:214`.
- **Trust boundary / reachability:** On the **Seatbelt backend** (macOS < 26, or `OSAURUS_FORCE_SEATBELT=1`), sandboxed agent/plugin shell commands run **as the logged-in user on the host**, confined only by the profile. The default `outbound` network mode emits an unrestricted `(allow network*)` with no destination filter. The host's own server binds `127.0.0.1:1337` and trusts loopback callers with no token.
- **Failure scenario:** A sandboxed exec runs `curl http://127.0.0.1:1337/agents/<id>/dispatch …` (or `/admin/*`, config, model-management). The connection's peer is `127.0.0.1` → `isLoopbackConnection` true → full trusted-local access, no key, no secure channel. The sandbox is meant to contain what the agent's shell can do; instead it can drive the entire local control plane (and, via C1, the file/shell tools). `(allow network*)` also grants the confined process the whole RFC1918 LAN.
- **Evidence:** The VM backend deliberately closes this — it injects `no_proxy=localhost,127.0.0.1` (`SandboxManager.swift:1573`) and boots host-only with no route to host loopback — but the Seatbelt path has **no** localhost guard (`case .allowed: lines.append("(allow network*)")`). The two tiers are asymmetric; the self-diagnostic (`SandboxManager.swift:2378-2420`) only tests file-write and outbound-internet confinement, so it wouldn't catch this.
- **How to confirm:** On macOS < 26 (or with `OSAURUS_FORCE_SEATBELT=1`), from a sandboxed agent shell run `curl -s http://127.0.0.1:1337/agents` — it returns the agent list.
- **Fix:** On Seatbelt, restrict the network grant to remote destinations (deny `network*-outbound` to `localhost`/`127.0.0.1/8`/`::1`, ideally RFC1918 too), or require an access key even from loopback when `SandboxBackend.current == .seatbelt`.

### H3 — `plugin_id` path traversal in `osaurus tools install` → arbitrary file write

- **Severity:** High · **Category:** path-traversal / arbitrary file write · **Confidence:** CONFIRMED (re-verified)
- **Location:** identity read `Packages/OsaurusCLI/Sources/OsaurusCLICore/Commands/Tools/ToolsInstall.swift` `readResolvedManualInstallManifest` (only checks `!pluginId.isEmpty`), validation-skip at the capability-less `continue` (~`:353`), `publishManualInstall:232-251`; sink `Packages/OsaurusRepository/PluginInstallManager.swift:323-329` (`toolsPluginDirectory`/`toolsVersionDirectory` = bare `appendingPathComponent(pluginId)`).
- **Trust boundary / reachability:** An untrusted third-party plugin package (directory, or a `.zip` whose name doesn't parse as `<id>-<version>`) passed to `osaurus tools install <src>`. Manual sideloads explicitly bypass registry checksum/signature (`ToolsInstall.swift:24`), and the traversal fires **at install time, before the `--consent` gate and before the dylib is loaded**.
- **Failure scenario:** Craft a directory with a `.dylib` and `osaurus-plugin.json` containing `{"plugin_id":"../../../../../../Library/LaunchAgents","version":"1.0.0"}` (no `capabilities`). `resolveManualInstallIdentity` reads `plugin_id` with only `trimmingCharacters`; `validateBundledManifestIfPresent` `continue`s past validation for a capability-less manifest; `publishManualInstall` computes `installDir = toolsVersionDirectory(pluginId, version)` and runs `createDirectory(withIntermediateDirectories:true)` + `moveItem`. `appendingPathComponent` does not normalize `..`, so FileManager resolves it at syscall time and the payload lands **outside `~/.osaurus/Tools/`** at an attacker-chosen path (e.g. a LaunchAgent → persistence).
- **Evidence:** `ManifestValidate.validate` checks `plugin_id` for non-empty only (`ManifestValidate.swift:89-105`); even with `capabilities` present, `validateManifestSummary` only asserts `summary.pluginId == identity.pluginId` (both the same traversal string). By contrast `HTTPHandler.swift:1729` rejects `pluginId.contains("..")` and `BoundedArchiveExtractor` rejects `..` entries — the manual-install directory derivation has no equivalent guard.
- **How to confirm:** build the crafted directory above and run `osaurus tools install ./evil-plugin` — observe a directory created outside `~/.osaurus/Tools/`.
- **Fix:** Validate `plugin_id` against a strict allowlist (`^[A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?$`, reject `..`/`/`/leading `.`) where it becomes an identity (`readResolvedManualInstallManifest`) and defensively inside `toolsPluginDirectory`.

### H4 — `ExternalPlugin.shutdown()` hangs forever on a wedged accessibility plugin call

- **Severity:** High · **Category:** continuation-leak / unbounded-wait · **Confidence:** CONFIRMED
- **Location:** `Models/Plugin/ExternalPlugin.swift:908` (bare `inFlightCallbacks.wait()` inside the `withCheckedContinuation` opened at `:875`); `enter()` at `:976`; wedge point `:993-995`.
- **Reachability:** A plugin invoked with `isolation: .accessibilityQueue` runs synchronous C on `AccessibilityManager.serialQueue`, entering `inFlightCallbacks` before `call(ctx)`. Accessibility/automation C that wedges (an AX syscall Swift cancellation can't unblock) is the documented failure mode this subsystem exists for (in-process mode, the default). While wedged, any `shutdown()` — `forceReload`, plugin-file removal, duplicate-id rejection (`PluginManager._loadAll:250/289/321`), or app-quit — triggers the hang.
- **Failure scenario:** The wedged call never reaches `defer { inFlightCallbacks.leave() }`, so `group.notify → self.inFlightCallbacks.wait()` (`:908`, no timeout) blocks forever → the `withCheckedContinuation` never completes → `await shutdown()` never returns. Reload/unload/clean-quit for that plugin hangs, and an `invokeQueue` worker thread is parked permanently.
- **Evidence:** The sibling teardown `PluginHostAPI.swift:2900` (`inFlightDatabaseCalls.wait()`) is explicitly "bounded by SQLite's 5s busy_timeout" — SQL calls always return. AX/automation C has no such bound, yet this wait is equally unbounded. The `isShutDown` flip only stops *future* callbacks; it can't rescue one already stuck in `call(ctx)`.
- **Tradeoff:** the wait is intentional — skipping it would let `api.destroy(ctx)` free the context under the live callback (a use-after-free). The defect is the *missing bound*, not the wait itself.
- **Fix:** `inFlightCallbacks.wait(timeout:)`; on timeout, deliberately leak the context (do **not** `destroy(ctx)`), resume the continuation, and breadcrumb the wedged plugin — the same "orphan the stuck work, unblock the caller" contract used by `valueWithDeadline`/`RouteHandlerRaceState` elsewhere.

### H5 — Loopback CORS `*` lets any website read admin/agent/model/inference endpoints

- **Severity:** High · **Category:** CORS reflection / cross-origin read + CSRF · **Confidence:** CONFIRMED (re-verified)
- **Location:** `Networking/HTTPHandler.swift:2901-2903` (`allowsAny = isLoopback || …` → unconditional `ACAO:*`); preflight `:459-477`.
- **Trust boundary / reachability:** Same browser→loopback boundary as C1, broader endpoint set. With `ACAO:*` and no credential requirement (loopback trusted by IP), any web origin reads responses.
- **Failure scenario:** From any visited page: read `GET /admin/runtime-settings`, `/admin/cache-stats`, `/admin/generation-settings` (full server/runtime config disclosure), `/agents`, `/models`; abuse `/chat/completions`, `/responses`, `/mcp/call`; and `PUT /admin/runtime-settings` to mutate concurrency/memory-safety/cache/generation defaults (preflight passes via `ACAO:*`; no master-scope check — see M2). `Origin`/`Host`/`Sec-Fetch-*` are never validated for loopback, and no `Access-Control-Allow-Private-Network` header is sent, so Safari (macOS default, no PNA enforcement) sends and reads these freely.
- **How to confirm:** `curl -s -H 'Origin: https://evil.example' -D- http://localhost:1337/admin/runtime-settings | grep -i access-control` shows `Access-Control-Allow-Origin: *`.
- **Fix:** Never reflect `*` for loopback; require `Origin` ∈ explicit allowlist (empty by default), reject cross-site `Sec-Fetch-Site` for non-GET, add an `Origin`/`Host` allowlist (defeats DNS-rebinding).

### H6 — Seatbelt profile grants unrestricted `mach-lookup` → confinement escape via LaunchServices

- **Severity:** High · **Category:** sandbox-escape · **Confidence:** PLAUSIBLE (blanket grant verified at `:244`; exact escape chain not executed in a read-only review)
- **Location:** `Services/Sandbox/Seatbelt/SeatbeltSandbox.swift:244` (`(allow mach-lookup)`), with `:238-239` (`process-fork`/`process-exec*`).
- **Reachability / scenario:** Same Seatbelt tier as H2. Unrestricted `mach-lookup` lets the confined process reach any Mach/XPC service, including `com.apple.lsd`/CoreServices (LaunchServices). Asking LaunchServices to open an app/handler launches it **outside** the sandbox (child confinement isn't inherited through a separate service doing the exec), yielding unconfined code execution as the user. Apple's own profiles almost never allow unfiltered `mach-lookup` for this reason.
- **Evidence:** No `(mach-lookup (global-name …))` allowlist — the grant is blanket. The self-diagnostic tests only file/network confinement, so a mach-service escape wouldn't be caught.
- **Fix:** Replace the blanket grant with an explicit `global-name` allowlist of only the services the toolchain needs (dyld/notifyd/etc.); never expose `com.apple.lsd`/coreservices/launchd submission surfaces.

---

## Medium

### M1 — Host-API bridge trusts the guest-supplied `X-Osaurus-Plugin` header → cross-plugin secret/config disclosure within an agent

- **Severity:** Medium · **Category:** token-auth / mis-scoping · **Confidence:** CONFIRMED (re-verified)
- **Location:** `Networking/HostAPIBridgeServer.swift:214` (`pluginName` from header), `:358-364` (`handleSecrets`), `:367-399` (`handleConfig`); secret keyed by `(agentId, pluginId, key)` in `Services/Keychain/ToolSecretsKeychain.swift:82-83`; shim `Services/Sandbox/SandboxManager.swift:3188` (`PLUGIN="${OSAURUS_PLUGIN:-…}"`).
- **Trust boundary / reachability:** The `agentId` identity is correctly bound to the (unforgeable, 0600) bearer token. But the **plugin** scope for `secrets`/`config` comes from the guest-controlled `X-Osaurus-Plugin` header, never validated against the token. Per-plugin isolation is an intended boundary (it's what host-Keychain secrets protect over on-disk sharing).
- **Failure scenario:** Two plugins under one agent. Malicious plugin B sets `OSAURUS_PLUGIN=<pluginA>` (or calls the socket directly with the agent-readable token) and issues `GET /api/secrets/<name>`; the bridge returns plugin A's secret (e.g. A's third-party API key). Same for reading/overwriting A's config. Impact bounded to same-agent (not cross-agent).
- **Fix:** Bind plugin identity to the credential (per-plugin tokens, or record the plugin at provision time and derive it from the token) instead of trusting a guest header.

### M2 — `/admin/*` routes accept any valid key, including agent-scoped keys

- **Severity:** Medium · **Category:** scope-confinement escape · **Confidence:** CONFIRMED
- **Location:** dispatch `Networking/HTTPHandler.swift:644-670`; handlers `handleCacheStatsEndpoint:865`, `handleGenerationSettingsEndpoint:1160`, `handleRuntimeSettingsEndpoint:1235-1520` — none consult `authedScopeIsMaster`.
- **Trust boundary / reachability:** A paired third party holding an **agent-scoped** key, over the relay tunnel or LAN (`exposeToNetwork=true`). The auth gate admits any `.valid` key; admin handlers add no master check; the relay forwards arbitrary paths (`RelayTunnelManager.buildLocalRequest` has no path allowlist).
- **Failure scenario:** An agent-A-scoped key does `GET/PUT /admin/runtime-settings` to read all runtime config and change concurrency/memory-safety/cache/generation (network changes are blocked at `:1352-1378`, the rest apply) — degrading the whole server and escaping the per-agent confinement `agentScopeRejection` enforces everywhere else.
- **Fix:** Gate all `/admin/*` on `authedScopeIsMaster || isLoopback`; reject agent-scoped audiences with 403.

### M3 — `/tasks/{id}` (GET status, DELETE cancel) lack agent-scope confinement

- **Severity:** Medium · **Category:** scope-confinement escape · **Confidence:** CONFIRMED (bounded by UUID secrecy)
- **Location:** `Networking/HTTPHandler.swift:5919-5983` (status), `:5986-6043` (cancel) — neither calls `agentScopeRejection` (compare `/agents/{id}` GET `:4515`, `/run` `:4779`, `/dispatch` `:5755`).
- **Failure scenario:** An agent-A-scoped key (or any loopback/browser caller per C1) reads another agent's task via `GET /tasks/<uuid>` (`serializeTaskState` may expose the other agent's prompt/results) or cancels it via `DELETE /tasks/<uuid>`. Gated only by knowledge of the v4 UUID, so exploitation needs a leaked/observed task id — which caps practical severity.
- **Fix:** Record the owning agent audience per task; reject when non-master `authedAudience` doesn't match. Mirror the `/agents/*` scope gate.

### M4 — Pre-auth body pre-allocation permits memory-exhaustion DoS (exposed mode)

- **Severity:** Medium · **Category:** unauthenticated DoS · **Confidence:** CONFIRMED (exposed mode)
- **Location:** `Networking/HTTPHandler.swift:396-405` — at `.head`, after only a `length > bodyByteLimit` check, `requestBodyBuffer = allocator.buffer(capacity: length)` (eager). Auth runs later at `.end` (`:506`). Default `maxRequestBodyBytes=32 MB`; connection cap 512 (`OsaurusServer.swift:286`).
- **Failure scenario:** With `exposeToNetwork=true`, an unauthenticated LAN caller sends `Content-Length: 33554432` and stalls the body. 512 conns × 32 MB pre-reserved ≈ 16 GB pinned before any auth → memory pressure / OOM. (Non-exposed: only local processes / ~6 browser conns per origin, so limited.)
- **Fix:** Don't pre-reserve the full `Content-Length`; grow the buffer as bytes arrive, and/or cap aggregate outstanding request-body bytes across connections.

### M5 — Zip-bomb: unbounded in-memory decompression on conversation import

- **Severity:** Medium · **Category:** zip-bomb / DoS · **Confidence:** CONFIRMED (re-verified)
- **Location:** `Utils/ZipArchive.swift:194` (`(raw as NSData).decompressed(using: .zlib)` — no output/ratio/total cap), reachable via `Managers/Chat/ChatSessionImporter.swift:163` and `ChatSessionImportCoordinator.swift:165` (whole file read via `Data(contentsOf:)`, no size gate).
- **Trust boundary / reachability:** An attacker-supplied `.zip` the user is socially engineered into importing (`NSOpenPanel`). Every `.json` entry is inflated whole.
- **Failure scenario:** DEFLATE amplifies up to ~1032:1, so a ~100 MB crafted entry expands to tens/hundreds of GB → allocation blows past RAM → OOM-kill. (The header even advertises that legitimate exports are multi-GB and decompressed whole.)
- **Evidence:** Contrast the plugin path's `BoundedArchiveExtractor` (enforces `maximumExpandedBytes`, `maximumCompressionRatio`, 64 KB streaming). None of that here; `ChatSessionImporterTests.swift` has no bomb/size coverage.
- **Note:** **No zip-slip** on this path — entry names are used only for `.json`/`__MACOSX` filtering and progress text; bytes go to JSON parsing → parameterized DB insert, never written to disk by name.
- **Fix:** Reject entries whose central-directory uncompressed size exceeds a budget before inflating, or inflate incrementally with a per-entry/per-archive byte ceiling (like `BoundedArchiveExtractor.inflateDeflatedEntry`). Gate total file size before `Data(contentsOf:)`.

### M6 — Agent-bundle tar extraction has no entry-name/symlink validation and runs before passphrase verification

- **Severity:** Medium (defense-in-depth) · **Category:** tar-slip / symlink · **Confidence:** PLAUSIBLE (blocked today by `bsdtar` defaults, not by code)
- **Location:** `Services/AgentBridge/AgentBundleService.swift:644-651` (`untar` = `/usr/bin/tar -xf … -C …`, no validation), consumed by `openBundleForReview:239` and `activate:320`.
- **Trust boundary / reachability:** An attacker-authored `.osaurus-agent` file a victim imports via the UI file-picker. `untar` runs **before** the AES-GCM passphrase unwrap, so extracting hostile bytes needs only a file-open plus any ≥8-char passphrase.
- **Failure scenario:** A crafted tar with `../` members, absolute paths, or a top-level symlink (e.g. `runs` → `/Users/victim/…`) extracts into staging; `activate` then `moveItem`s fixed names into `~/.osaurus/agents/<id>/`, and `StorageFormatConverter.export` reads through a `db.sqlite` symlink.
- **Why not confirmed:** macOS `bsdtar -x` (no `-P`) strips leading `/`, refuses `..` members, and refuses extraction through a symlinked target — so the traversal is blocked by the tool, not the code. The exposure is latent: undocumented-in-code, and would vanish if `-P` were added or the tool swapped. Contrast `SkillImportPolicy`, which validates names pre-extraction and re-checks containment with `resolvingSymlinksInPath()` after.
- **Fix:** Mirror `SkillImportPolicy` — enumerate the staged tree, reject symlinks and any entry not contained within staging, before `activate` touches anything.

### M7 — WhatsApp inbound-media size cap absent/bypassable → remote memory exhaustion

- **Severity:** Medium · **Category:** resource exhaustion · **Confidence:** PLAUSIBLE
- **Location:** `helpers/osaurus-wa/bridge.go:1315-1355`, gate at `:1328` (`if maxBytes > 0 && size > uint64(maxBytes)`).
- **Trust boundary / reachability:** A remote WhatsApp sender (fully untrusted) controls media size and the declared `FileLength`; reached when the Swift side subscribed with `download_media=true`.
- **Failure scenario:** (a) If `max_media_bytes` is 0/omitted, the gate is skipped and `Download` buffers the whole blob into RAM. (b) Even with a positive cap, it compares against the *sender-declared* `GetFileLength()`; a sender can declare `1` while shipping a huge blob, and `Download` fetches the actual ciphertext into memory regardless. Either exhausts helper memory (OOM → drops all watches).
- **Fix:** Enforce a hard default ceiling even when `max_media_bytes<=0`, and cap the *actual* bytes read (bounded reader / stream-to-disk) rather than trusting `GetFileLength()`.

---

## Low / Info

- **L1 — ZIP64 integer-conversion trap crashes conversation import.** `Utils/ZipArchive.swift:85,89,90` do `Int(u64(...))` on attacker-controlled 64-bit fields; `UInt64→Int` **traps** in Swift above `Int.max`, and `:86` `eocd64 + 56` can overflow-trap. Same untrusted-import boundary as M5. CONFIRMED (re-verified). Fix: `Int(exactly:)` + reject oversized offsets/sizes (as `BoundedArchiveExtractor` does).
- **L2 — Undo replay re-derives destructive paths without re-validation.** `Folder/FileOperationLog.swift:246,253,276,292,307,338` do `root.appendingPathComponent(operation.path)` then `removeItem`/`moveItem`/`write` with no `resolvePath` re-check. Safe today (paths are logged only after a record-time `resolvePath` gate at `FolderTools.swift:1754`), but relies on an invariant enforced far away. Fix: re-run `resolvePath` inside `performUndo`.
- **L3 — Egress rebinding filter misses IPv4-compatible / NAT64 IPv6.** `Services/Sandbox/SandboxEgressPolicy.swift:152-168` rechecks IPv4-mapped `::ffff:a.b.c.d` but not `::a.b.c.d` (`::/96`) or `64:ff9b::/96`. Low impact (macOS doesn't route `::a.b.c.d`; NAT64 needs a translator). Fix: re-check the embedded v4 for those ranges too.
- **L4 — Go RPC reader silently exits on an oversized frame.** `helpers/osaurus-wa/rpc.go:86-105` uses a 4 MiB scanner max; any line ≥ 4 MiB ends the loop → `main` exits 0, dropping every active `watch.subscribe`, with no error. `scanner.Err()` (`ErrTooLong`) is never checked. Trust boundary is local stdin (weak), hence Low. CONFIRMED. Fix: check `scanner.Err()`, log + resynchronize instead of exiting.
- **L5 — Proxy local-host rejection bypassed by IPv4-mapped IPv6.** `Packages/OsaurusNetworking/Sources/GlobalProxyConfiguration.swift:184-190` classifies only native-form loopback/link-local; `socks://[::ffff:127.0.0.1]:1080` is accepted. CONFIRMED. Impact low (self-inflicted; TLS retained). Fix: detect `::ffff:0:0/96`, extract embedded v4, run the existing IPv4 local checks.
- **L6 — Out-of-process config forwarding can deliver `on_config_changed` out of order.** `Models/Plugin/ExternalPlugin.swift:1169` spawns a `Task.detached` per batch; two quick writes to the same key can arrive reversed at the helper, leaving it on stale config. Requires `PluginProcessHostMode` (default off). CONFIRMED (ordering). Fix: serialize forwarding per plugin via one ordered mailbox.
- **L7 — `notifyConfigChanged` timeout orphans a pending continuation.** `Services/Plugin/PluginProcessHost.swift:153-161` swallows `DeadlineExceededError` without `killProcess()`, so the inner `register` continuation lingers until the next kill/EOF. No caller hang; self-healing; feature-flagged. CONFIRMED. Fix: `await killProcess()` on timeout, like `invoke`.
- **L8 — Error bodies echo internal exception text.** e.g. `Networking/HTTPHandler.swift:1324` interpolates `error.localizedDescription`. Minor info leak to authenticated/loopback callers. Fix: generic message on the wire, detail to the log.
- **L9 — Stop sequences split across streamed deltas not honored (remote path).** `Services/Provider/OpenAICompatibleStreamParser.swift:762-774` range-searches each delta independently; a stop string straddling a delta boundary leaks past truncation. Mitigated because `stop` is forwarded natively upstream (`RemoteProviderService.swift:2373`). PLAUSIBLE, low. Fix: buffer a `max(stopLen)-1` tail across deltas.
- **L10 — SSE error writers emit unescaped strings in a fallback branch.** `Models/Chat/ResponseWriters.swift:407-416` and `:947-956` hand-build JSON without escaping in the catch branch — only reachable if encoding an all-`String` struct throws, which effectively never happens. Fix: escape, or drop the hand-rolled fallback.
- **L11 (Info) — Temporary pairing keys not revoked on unclean shutdown.** `Identity/TemporaryPairedKeyStore.swift:38-43` revokes non-permanent pairing keys only on `applicationWillTerminate`, with an in-memory id list; on crash/SIGKILL a temporary key survives until its 90-day expiry. Bounded + user-approved. Fix: persist the temporary-key set or mint with a short expiry.

---

## Already fixed in this branch

- **Rename regression — cryptographic domain-separation prefixes (commit `707f48f`).** The
  Osaurus→Intelligence rename excluded `Identity/` (where the signing helpers live) but rewrote
  three matching *verifier* literals outside it (`HTTPHandler.swift` `/pair` connector sig,
  `ChatView.swift` `/pair` server attestation, `AgentInvite.swift` invite sig), so signer and
  verifier prefixes diverged and **LAN pairing + invite redemption failed closed (401)**. Reverted
  to `"Osaurus …"` to match the signers. Fails-closed, so no security exposure — but a shipped
  functional regression, now corrected. (Recommended follow-up: hoist the six prefixes into one
  shared constant referenced by both sides, and add a sign→verify round-trip test per prefix; the
  existing tests used the same literal on both sides and so didn't catch the drift.)
- **`ServerController.startServer` reentrancy (commit `be4e742`).** `isRunning` only flips after
  several `await`s, so an overlapping second `startServer` could race a duplicate bind on the same
  port. Guarded with an `isStarting` flag.

## Coverage

| Territory | Depth | Notable verified-sound areas |
|-----------|-------|------------------------------|
| HTTP server / auth / secure channel / CORS / DoS | Deep | Auth gate default-deny; `..`/`//`/percent-encoding/trailing-slash fail closed; relay-origin marker unspoofable; secure-channel inner-request nesting rejected; agent-scope gates present on `/agents/*`; plugin static serving traversal-safe; header/body DoS caps |
| Sandbox escape (egress proxy, host bridge, seatbelt, relay) | Deep | VM egress rebinding is TOCTOU-free; proxy bound to vmnet gateway (never 0.0.0.0); bridge fail-closed 401 + token-bound `agent_id`; guest bootstrap names sanitized; seatbelt profile string not attacker-influenced; token store CSPRNG 0600 |
| Identity / crypto / keychain / pairing | Deep | Access-key validation complete & correctly ordered; revocation/expiry enforced on every path incl. secure channel; Secure Channel replay window + per-call keys sound; DB DEK/salt CSPRNG (not static); AES-GCM fresh nonce per write; keychain-disabled-for-tests fails closed |
| Injection & filesystem write-safety | Deep | AppleScript literal escaper complete; workspace `resolvePath` chokepoint symlink-safe and called on every host write sink; skill-import double-gated against zip-slip; sandbox shell sites execute in-guest only |
| Plugin host + concurrency | Deep | Continuation handoffs take-under-lock single-shot; `HostBridge`/`LineWriter`/`PluginProcessHostClient` correct; `ModelManager`/`ModelDownloadService`/`Keychain`/`SpeechService`/`AsyncDeadline` all resume-exactly-once, no lock leaks |
| Storage / DB / archive extraction | Deep | All SQL parameterized (incl. untrusted channel messages); migrations transactional/idempotent; `BoundedArchiveExtractor` blocks zip-slip/bomb/symlink; minisign signature gating not bypassable |
| Inference request path | Deep | UTF-8 reassembled before decode; SSE framing/`[DONE]`/multi-line data correct; client-disconnect cancels generation; tool-call delta assembly keeps parallel calls separate; response writers per-request, no state bleed |
| Non-core packages + Go helper | Breadth | `BoundedArchiveExtractor` (CLI) traversal-safe; StatsPack SQLite read-only + identifier-escaped; Go `sanitizeFileName` blocks traversal, stdout mutex-serialized, login lifecycle leak-free; proxy port/scheme/userinfo validation |

Not deeply examined (proportional-to-risk trade, per the agreed scope): the bulk of `Views/`
SwiftUI (178K lines — spot-checked for lifecycle/leak issues only), the evals harness
(`OsaurusEvals`, dev tooling), and the `ComputerUse`/`Browser`/`Memory`/`Knowledge` service
subtrees beyond their trust-boundary entry points. No Critical/High is expected there, but they
were not line-audited.

## Deferred fixes and residual risk

### H6 — Seatbelt blanket `mach-lookup` (DEFERRED, no code change)

Deferred deliberately: this is the one fix that can break working tools, it has zero existing test
coverage, and it cannot be validated without a macOS < 26 machine. **Only the Seatbelt tier is
affected** — macOS 26+ runs the VM backend, where this does not apply.

Recommended change when a suitable machine is available — replace the blanket
`(allow mach-lookup)` at `Services/Sandbox/Seatbelt/SeatbeltSandbox.swift:244` with an allowlist:

- **Must stay allowed** (or ordinary tools break): `opendirectoryd` (libinfo, membership — `id`,
  `whoami`, `$HOME`, Python `pwd`), `dnssd`/`mDNSResponder` (**all** hostname resolution),
  `trustd` + `securityd` (**all** HTTPS), `SystemConfiguration.configd`, `cfprefsd` (daemon+agent),
  `notification_center`, `system.logger`, `bsd.dirhelper`.
- **Must be excluded** (this is the escape): `com.apple.lsd`,
  `com.apple.coreservices.launchservicesd`, and any launchd submission surface — asking those to
  open something execs it *outside* the sandbox as the user.

On-device checklist before shipping it (`OSAURUS_FORCE_SEATBELT=1` on macOS < 26): `python3` starts,
`curl https://example.com` succeeds (proves DNS + TLS), `pip`/`npm` install works, `id`/`whoami`
resolve. Note DNS and TLS ride on Mach services, so this fix is coupled to the network grant — do it
after H2 is proven, not before.

### M1 — host-bridge plugin scoping: credential plumbing landed, exploit still live

The token store now carries an optional `pluginId` and the bridge validates a supplied
`X-Osaurus-Plugin` header against it. **But no production call site mints a per-plugin token yet**
(`SandboxManager` still calls the 2-arg `register`), so `identity.pluginId` is always nil, the
validation never fires, and a plugin can still set `OSAURUS_PLUGIN` to a sibling's id and read that
sibling's host-Keychain secrets. Impact is bounded to plugins under the *same* agent (the `agentId`
binding is unforgeable). Closing it needs per-plugin Linux users in guest provisioning, a per-plugin
token file, and a shim change — a larger piece of work than this pass. **Treat M1 as open.**

### N1 (new, found during remediation) — `ShellSandboxProfile` has the same loopback hole as H2

`Folder/ShellSandboxProfile.swift:50` emits `(allow default)` and restricts only filesystem writes,
so the host `shell_run` / `git_commit` confinement leaves the loopback control plane reachable —
the same mechanism as H2, but on **all** macOS versions rather than only the Seatbelt tier. Not
fixed here because it is outside the approved scope and a blanket deny could break a user asking
their agent to query their own local API. The parallel one-line fix is to append
`SeatbeltSandbox.controlPlaneDenyRule(port:)` after `(allow default)`, threading the port from the
same resolver. Severity is lower than H2 — `shell_run` is already a user-approved, fully-privileged
local action — but it should be closed for consistency.

### Test gaps knowingly left open

`AgentBundleService.validateStagedTree` (M6) and `FileOperationLog`'s undo re-validation (L2) both
shipped **without** direct tests — the existing undo tests only cover the happy path. Worth adding:
a bundle containing a symlink must be refused, and an operation whose recorded path escapes the root
must refuse to undo.

## Suggested fix order

1. **C1** — the localhost-CSRF → tool-execution bypass. One-line-ish fix (bind `isExternalSurface=true` for `/dispatch`) plus CORS hardening (H5 is the same root; fix together).
2. **H1** — route inference decodes through the existing depth guard (mechanical, low-risk).
3. **H3** — validate `plugin_id` (mechanical).
4. **H2 / H6** — tighten the Seatbelt profile (network + `mach-lookup`).
5. **M5 / L1** — bound the conversation-import zip reader (or reuse `BoundedArchiveExtractor`).
6. **H4** — bound the plugin-shutdown wait.
7. Remaining Medium/Low as convenient.

Because this environment can't compile Swift, apply and verify these on a Mac with
`make test` (fast) and a Release build exercised through the real UI per the repo's proof
discipline before shipping.
