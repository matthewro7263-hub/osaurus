//
//  CORSHandlerTests.swift
//  OsaurusCoreTests
//
//  End-to-end CORS regression tests covering the user-reported scenario in
//  GitHub issue #952: an Obsidian plugin (Origin: app://obsidian.md) hitting
//  http://127.0.0.1:1337/api/tags receives "No 'Access-Control-Allow-Origin'
//  header" even with `*` configured.
//
//  These tests boot a real NIO server with `HTTPHandler` end-to-end so we
//  exercise the full path: `.head` → `computeCORSHeaders` →
//  `stateRef.value.corsHeaders` → response writer.
//
//  Two test families:
//  - "loopback_*" use `trustLoopback: true` (production default). They
//    cover the new auto-trust contract: any request whose connection
//    arrives via 127.0.0.1 / ::1 is treated as a trusted local caller
//    and gets `Access-Control-Allow-Origin: *` regardless of the
//    configured allowlist. Same posture as LM Studio / Ollama.
//  - "nonLoopback_*" use `trustLoopback: false` so the auto-trust
//    short-circuit doesn't fire even though the bind address is
//    loopback. They lock down the explicit-allowlist mode used by
//    `exposeToNetwork=true` / hardened deployments.
//
//  The auto-trust covers the OPEN API only (health, models, tags, show,
//  inference, mcp). Control-plane routes (`/agents*`, `/admin*`, `/tasks*`)
//  are excluded: loopback trust is granted by peer IP, which any web page's
//  `fetch("http://localhost:1337/…")` also satisfies, so `*` there would hand
//  every website the local control plane. The "controlPlane_*" tests below
//  lock that split down in both directions.
//

import Foundation
import NIOCore
import NIOHTTP1
import NIOPosix
import Testing

@testable import OsaurusCore

@Suite("CORS handler")
struct CORSHandlerTests {

    // MARK: - Loopback auto-trust (production default)

    /// Reproduces the exact request shape from the Obsidian plugin: a simple
    /// `GET /api/tags` cross-origin request from `app://obsidian.md` against a
    /// server configured with the wildcard origin. Must return
    /// `Access-Control-Allow-Origin: *` so the browser does not block the
    /// response.
    @Test func wildcardOrigin_GET_apiTags_fromObsidian_returnsAllowOriginStar() async throws {
        var config = ServerConfiguration.default
        config.allowedOrigins = ["*"]
        let server = try await startCORSTestServer(config: config)
        defer { Task { await server.shutdown() } }

        var request = URLRequest(
            url: URL(string: "http://\(server.host):\(server.port)/api/tags")!
        )
        request.httpMethod = "GET"
        request.setValue("app://obsidian.md", forHTTPHeaderField: "Origin")

        let (_, resp) = try await URLSession.shared.data(for: request)
        let http = resp as? HTTPURLResponse
        let acao = http?.value(forHTTPHeaderField: "Access-Control-Allow-Origin")

        #expect(http?.statusCode == 200)
        #expect(acao == "*")
    }

    /// The CORS preflight that Chromium-based clients (including Electron and
    /// Obsidian) emit for non-simple cross-origin requests. Must return 204
    /// with the full set of preflight headers; the browser otherwise blocks
    /// the follow-up request.
    @Test func wildcardOrigin_OPTIONS_apiTags_returnsFullPreflight() async throws {
        var config = ServerConfiguration.default
        config.allowedOrigins = ["*"]
        let server = try await startCORSTestServer(config: config)
        defer { Task { await server.shutdown() } }

        var request = URLRequest(
            url: URL(string: "http://\(server.host):\(server.port)/api/tags")!
        )
        request.httpMethod = "OPTIONS"
        request.setValue("app://obsidian.md", forHTTPHeaderField: "Origin")
        request.setValue("GET", forHTTPHeaderField: "Access-Control-Request-Method")
        request.setValue("Content-Type, Authorization", forHTTPHeaderField: "Access-Control-Request-Headers")

        let (_, resp) = try await URLSession.shared.data(for: request)
        let http = resp as? HTTPURLResponse

        #expect(http?.statusCode == 204)
        #expect(http?.value(forHTTPHeaderField: "Access-Control-Allow-Origin") == "*")
        let allowMethods = http?.value(forHTTPHeaderField: "Access-Control-Allow-Methods") ?? ""
        #expect(allowMethods.contains("GET"))
        let allowHeaders = http?.value(forHTTPHeaderField: "Access-Control-Allow-Headers") ?? ""
        #expect(allowHeaders.lowercased().contains("content-type"))
        #expect(allowHeaders.lowercased().contains("authorization"))
        #expect(http?.value(forHTTPHeaderField: "Access-Control-Max-Age") == "600")
    }

    /// The actual fix for #952: with the default empty allowlist, a loopback
    /// caller still gets `Access-Control-Allow-Origin: *`. This is the
    /// zero-config UX win — Obsidian and any other local app integration
    /// works without the user having to find and configure CORS settings.
    @Test func loopback_emptyAllowlist_returnsAllowOriginStar() async throws {
        var config = ServerConfiguration.default
        config.allowedOrigins = []
        let server = try await startCORSTestServer(config: config)
        defer { Task { await server.shutdown() } }

        var request = URLRequest(
            url: URL(string: "http://\(server.host):\(server.port)/api/tags")!
        )
        request.httpMethod = "GET"
        request.setValue("app://obsidian.md", forHTTPHeaderField: "Origin")

        let (_, resp) = try await URLSession.shared.data(for: request)
        let http = resp as? HTTPURLResponse

        #expect(http?.statusCode == 200)
        #expect(http?.value(forHTTPHeaderField: "Access-Control-Allow-Origin") == "*")
    }

    /// Loopback overrides allowlist mismatch — the local-machine trust
    /// boundary applies regardless of what allowlist the user configured for
    /// non-loopback callers. A power user who set `["http://localhost:3000"]`
    /// for LAN apps still gets their own loopback callers (Obsidian, etc.)
    /// served zero-config.
    @Test func loopback_specificOriginMismatch_stillReturnsAllowOriginStar() async throws {
        var config = ServerConfiguration.default
        config.allowedOrigins = ["http://localhost:3000"]
        let server = try await startCORSTestServer(config: config)
        defer { Task { await server.shutdown() } }

        var request = URLRequest(
            url: URL(string: "http://\(server.host):\(server.port)/api/tags")!
        )
        request.httpMethod = "GET"
        request.setValue("app://obsidian.md", forHTTPHeaderField: "Origin")

        let (_, resp) = try await URLSession.shared.data(for: request)
        let http = resp as? HTTPURLResponse

        #expect(http?.statusCode == 200)
        #expect(http?.value(forHTTPHeaderField: "Access-Control-Allow-Origin") == "*")
    }

    /// Loopback preflight with empty allowlist still returns the full CORS
    /// preflight envelope. Without this, browsers would 200 OK the preflight
    /// but reject the follow-up GET because the preflight lacked the methods
    /// / headers / max-age headers.
    @Test func loopback_emptyAllowlist_OPTIONS_preflight_returnsFullEnvelope()
        async throws
    {
        var config = ServerConfiguration.default
        config.allowedOrigins = []
        let server = try await startCORSTestServer(config: config)
        defer { Task { await server.shutdown() } }

        var request = URLRequest(
            url: URL(string: "http://\(server.host):\(server.port)/api/tags")!
        )
        request.httpMethod = "OPTIONS"
        request.setValue("app://obsidian.md", forHTTPHeaderField: "Origin")
        request.setValue("GET", forHTTPHeaderField: "Access-Control-Request-Method")
        request.setValue("Content-Type", forHTTPHeaderField: "Access-Control-Request-Headers")

        let (_, resp) = try await URLSession.shared.data(for: request)
        let http = resp as? HTTPURLResponse

        #expect(http?.statusCode == 204)
        #expect(http?.value(forHTTPHeaderField: "Access-Control-Allow-Origin") == "*")
        let allowMethods = http?.value(forHTTPHeaderField: "Access-Control-Allow-Methods") ?? ""
        #expect(allowMethods.contains("GET"))
        #expect(http?.value(forHTTPHeaderField: "Access-Control-Max-Age") == "600")
    }

    /// Exact origin match must echo the origin (NOT `*`) and add `Vary: Origin`
    /// so caches don't poison cross-origin responses. Even when loopback
    /// auto-trust is active, the loopback path *does* short-circuit to `*`,
    /// so this test verifies the wire shape that production loopback callers
    /// see when they happen to also be in the allowlist (they get `*`,
    /// not the echo). The exact-echo + Vary path is covered by
    /// `nonLoopback_specificOrigin_match_*` below.
    @Test func loopback_specificOrigin_match_returnsAllowOriginStar() async throws {
        var config = ServerConfiguration.default
        config.allowedOrigins = ["http://localhost:3000"]
        let server = try await startCORSTestServer(config: config)
        defer { Task { await server.shutdown() } }

        var request = URLRequest(
            url: URL(string: "http://\(server.host):\(server.port)/api/tags")!
        )
        request.httpMethod = "GET"
        request.setValue("http://localhost:3000", forHTTPHeaderField: "Origin")

        let (_, resp) = try await URLSession.shared.data(for: request)
        let http = resp as? HTTPURLResponse

        #expect(http?.statusCode == 200)
        // Loopback auto-trust short-circuits BEFORE the exact-origin echo
        // branch, so loopback callers always see "*" (not the echoed
        // origin + Vary). This is intentional: the wildcard branch is
        // strictly more permissive.
        #expect(http?.value(forHTTPHeaderField: "Access-Control-Allow-Origin") == "*")
    }

    // MARK: - Control plane (loopback auto-trust does NOT apply)

    /// A website doing `fetch("http://localhost:1337/admin/runtime-settings")`
    /// arrives over loopback like any local app, so the auto-trust `*` would
    /// make the server's full runtime configuration cross-origin readable.
    /// Control-plane routes must therefore emit no `*` for an unlisted origin.
    @Test func loopback_controlPlane_emptyAllowlist_returnsNoAllowOriginStar() async throws {
        var config = ServerConfiguration.default
        config.allowedOrigins = []
        let server = try await startCORSTestServer(config: config)
        defer { Task { await server.shutdown() } }

        var request = URLRequest(
            url: URL(string: "http://\(server.host):\(server.port)/admin/runtime-settings")!
        )
        request.httpMethod = "GET"
        request.setValue("https://evil.example", forHTTPHeaderField: "Origin")

        let (_, resp) = try await URLSession.shared.data(for: request)
        let http = resp as? HTTPURLResponse

        #expect(http?.value(forHTTPHeaderField: "Access-Control-Allow-Origin") == nil)
    }

    /// The same exclusion applies to the other control-plane prefixes; a
    /// task id is enough to read another run's prompt and results.
    @Test func loopback_controlPlane_tasks_emptyAllowlist_returnsNoAllowOriginStar() async throws {
        var config = ServerConfiguration.default
        config.allowedOrigins = []
        let server = try await startCORSTestServer(config: config)
        defer { Task { await server.shutdown() } }

        var request = URLRequest(
            url: URL(string: "http://\(server.host):\(server.port)/v1/tasks/\(UUID().uuidString)")!
        )
        request.httpMethod = "GET"
        request.setValue("https://evil.example", forHTTPHeaderField: "Origin")

        let (_, resp) = try await URLSession.shared.data(for: request)
        let http = resp as? HTTPURLResponse

        #expect(http?.value(forHTTPHeaderField: "Access-Control-Allow-Origin") == nil)
    }

    /// The control-plane preflight must fail closed too: without CORS headers
    /// on the 204, the browser never sends the follow-up PUT.
    @Test func loopback_controlPlane_OPTIONS_emptyAllowlist_returnsNoCORSHeaders() async throws {
        var config = ServerConfiguration.default
        config.allowedOrigins = []
        let server = try await startCORSTestServer(config: config)
        defer { Task { await server.shutdown() } }

        var request = URLRequest(
            url: URL(string: "http://\(server.host):\(server.port)/admin/runtime-settings")!
        )
        request.httpMethod = "OPTIONS"
        request.setValue("https://evil.example", forHTTPHeaderField: "Origin")
        request.setValue("PUT", forHTTPHeaderField: "Access-Control-Request-Method")

        let (_, resp) = try await URLSession.shared.data(for: request)
        let http = resp as? HTTPURLResponse

        #expect(http?.value(forHTTPHeaderField: "Access-Control-Allow-Origin") == nil)
    }

    /// Opting an origin in explicitly still works for the control plane: the
    /// origin is echoed (never `*`) with `Vary: Origin`, the same shape the
    /// non-loopback allowlist path uses.
    @Test func loopback_controlPlane_allowlistedOrigin_echoesOriginAndVary() async throws {
        var config = ServerConfiguration.default
        config.allowedOrigins = ["http://localhost:3000"]
        let server = try await startCORSTestServer(config: config)
        defer { Task { await server.shutdown() } }

        var request = URLRequest(
            url: URL(string: "http://\(server.host):\(server.port)/admin/runtime-settings")!
        )
        request.httpMethod = "GET"
        request.setValue("http://localhost:3000", forHTTPHeaderField: "Origin")

        let (_, resp) = try await URLSession.shared.data(for: request)
        let http = resp as? HTTPURLResponse

        #expect(
            http?.value(forHTTPHeaderField: "Access-Control-Allow-Origin") == "http://localhost:3000"
        )
        let vary = http?.value(forHTTPHeaderField: "Vary") ?? ""
        #expect(vary.contains("Origin"))
    }

    /// Beyond hiding the response, a control-plane request the browser marks
    /// cross-site is refused outright — this is what stops the "blind" CSRF
    /// shapes (`text/plain` POST) that never need to read a response.
    @Test func loopback_controlPlane_crossSiteFetch_isRejectedWith403() async throws {
        var config = ServerConfiguration.default
        config.allowedOrigins = []
        let server = try await startCORSTestServer(config: config)
        defer { Task { await server.shutdown() } }

        var request = URLRequest(
            url: URL(string: "http://\(server.host):\(server.port)/agents/\(UUID().uuidString)/dispatch")!
        )
        request.httpMethod = "POST"
        request.setValue("text/plain", forHTTPHeaderField: "Content-Type")
        request.setValue("https://evil.example", forHTTPHeaderField: "Origin")
        request.setValue("cross-site", forHTTPHeaderField: "Sec-Fetch-Site")
        request.httpBody = Data(#"{"prompt":"write a file"}"#.utf8)

        let (data, resp) = try await URLSession.shared.data(for: request)
        let status = (resp as? HTTPURLResponse)?.statusCode ?? -1
        let body = String(decoding: data, as: UTF8.self)

        #expect(status == 403)
        #expect(body.contains("cross_site_denied"))
    }

    /// ...and the gate is scoped to the control plane: the issue-#952 clients
    /// (Obsidian and friends) are cross-site by construction and must keep
    /// working against the open API.
    @Test func loopback_openAPI_crossSiteFetch_stillReturnsAllowOriginStar() async throws {
        var config = ServerConfiguration.default
        config.allowedOrigins = []
        let server = try await startCORSTestServer(config: config)
        defer { Task { await server.shutdown() } }

        var request = URLRequest(
            url: URL(string: "http://\(server.host):\(server.port)/api/tags")!
        )
        request.httpMethod = "GET"
        request.setValue("app://obsidian.md", forHTTPHeaderField: "Origin")
        request.setValue("cross-site", forHTTPHeaderField: "Sec-Fetch-Site")

        let (_, resp) = try await URLSession.shared.data(for: request)
        let http = resp as? HTTPURLResponse

        #expect(http?.statusCode == 200)
        #expect(http?.value(forHTTPHeaderField: "Access-Control-Allow-Origin") == "*")
    }

    /// A native loopback caller (no `Sec-Fetch-*`, no `Origin`) is untouched
    /// by the gate — the CLI and the live-proof scripts drive these routes.
    @Test func loopback_controlPlane_nativeCaller_isNotRejected() async throws {
        var config = ServerConfiguration.default
        config.allowedOrigins = []
        let server = try await startCORSTestServer(config: config)
        defer { Task { await server.shutdown() } }

        var request = URLRequest(
            url: URL(string: "http://\(server.host):\(server.port)/admin/runtime-settings")!
        )
        request.httpMethod = "GET"

        let (_, resp) = try await URLSession.shared.data(for: request)
        #expect((resp as? HTTPURLResponse)?.statusCode == 200)
    }

    /// The path classifier itself: prefix matching must not leak into
    /// similarly-named open-API routes.
    @Test func controlPlanePath_classification() {
        #expect(HTTPHandler.isControlPlanePath("/agents"))
        #expect(HTTPHandler.isControlPlanePath("/agents/123/dispatch"))
        #expect(HTTPHandler.isControlPlanePath("/admin/runtime-settings"))
        #expect(HTTPHandler.isControlPlanePath("/tasks/abc"))
        #expect(!HTTPHandler.isControlPlanePath("/tags"))
        #expect(!HTTPHandler.isControlPlanePath("/models"))
        #expect(!HTTPHandler.isControlPlanePath("/chat/completions"))
        #expect(!HTTPHandler.isControlPlanePath("/mcp/call"))
        #expect(!HTTPHandler.isControlPlanePath("/agentsx"))
    }

    /// `/mcp` is not control-plane for CORS purposes (same-site local MCP
    /// tooling keeps reading responses) but IS cross-site protected, because
    /// `/mcp/call` executes tools and a `text/plain` POST ships preflight-free.
    @Test func crossSiteProtectedPath_classification() {
        #expect(HTTPHandler.isCrossSiteProtectedPath("/mcp"))
        #expect(HTTPHandler.isCrossSiteProtectedPath("/mcp/call"))
        #expect(HTTPHandler.isCrossSiteProtectedPath("/agents/123/dispatch"))
        #expect(HTTPHandler.isCrossSiteProtectedPath("/admin/runtime-settings"))
        #expect(!HTTPHandler.isCrossSiteProtectedPath("/mcpx"))
        #expect(!HTTPHandler.isCrossSiteProtectedPath("/api/tags"))
        #expect(!HTTPHandler.isCrossSiteProtectedPath("/chat/completions"))
    }

    /// A website may not invoke MCP tools. `/mcp/call` already binds the
    /// external surface (so shell/file tools are denied), but every other
    /// registered tool would otherwise be reachable from any tab.
    @Test func loopback_mcpCall_crossSiteFetch_isRejectedWith403() async throws {
        var config = ServerConfiguration.default
        config.allowedOrigins = []
        let server = try await startCORSTestServer(config: config)
        defer { Task { await server.shutdown() } }

        var request = URLRequest(
            url: URL(string: "http://\(server.host):\(server.port)/mcp/call")!
        )
        request.httpMethod = "POST"
        request.setValue("text/plain", forHTTPHeaderField: "Content-Type")
        request.setValue("https://evil.example", forHTTPHeaderField: "Origin")
        request.setValue("cross-site", forHTTPHeaderField: "Sec-Fetch-Site")
        request.httpBody = Data(#"{"name":"memory_store","arguments":{}}"#.utf8)

        let (data, resp) = try await URLSession.shared.data(for: request)
        #expect((resp as? HTTPURLResponse)?.statusCode == 403)
        #expect(String(decoding: data, as: UTF8.self).contains("cross_site_denied"))
    }

    /// Same-site local tooling (an MCP inspector on another localhost port) is
    /// NOT cross-site, so it keeps both access and its readable `ACAO: *`.
    @Test func loopback_mcpTools_sameSiteFetch_stillReturnsAllowOriginStar() async throws {
        var config = ServerConfiguration.default
        config.allowedOrigins = []
        let server = try await startCORSTestServer(config: config)
        defer { Task { await server.shutdown() } }

        var request = URLRequest(
            url: URL(string: "http://\(server.host):\(server.port)/mcp/health")!
        )
        request.httpMethod = "GET"
        request.setValue("http://localhost:3000", forHTTPHeaderField: "Origin")
        request.setValue("same-site", forHTTPHeaderField: "Sec-Fetch-Site")

        let (_, resp) = try await URLSession.shared.data(for: request)
        let http = resp as? HTTPURLResponse
        #expect(http?.statusCode == 200)
        #expect(http?.value(forHTTPHeaderField: "Access-Control-Allow-Origin") == "*")
    }

    // MARK: - Non-loopback (explicit allowlist mode)

    /// Hardened-deployment posture: `trustLoopback: false` disables the
    /// auto-trust short-circuit. With an empty allowlist the server must
    /// not advertise CORS, so cross-origin browser callers get blocked.
    /// Locks down the explicit-allowlist contract for users who run
    /// Intelligence under reverse proxies / strict environments.
    @Test func nonLoopback_emptyAllowlist_returnsNoCORSHeaders() async throws {
        var config = ServerConfiguration.default
        config.allowedOrigins = []
        let server = try await startCORSTestServer(config: config, trustLoopback: false)
        defer { Task { await server.shutdown() } }

        var request = URLRequest(
            url: URL(string: "http://\(server.host):\(server.port)/api/tags")!
        )
        request.httpMethod = "GET"
        request.setValue("app://obsidian.md", forHTTPHeaderField: "Origin")

        // /api/tags is not a public path; with trustLoopback off and no
        // access keys configured the auth gate returns 401. CORS headers
        // must still be omitted (the auth-failure response is not
        // cross-origin readable either way).
        let (_, resp) = try await URLSession.shared.data(for: request)
        let http = resp as? HTTPURLResponse

        #expect(http?.value(forHTTPHeaderField: "Access-Control-Allow-Origin") == nil)
    }

    /// Non-loopback wildcard is the explicit "I want CORS open to anyone"
    /// opt-in (e.g. for LAN-shared Intelligence instances). Must still emit `*`.
    @Test func nonLoopback_wildcardAllowlist_returnsAllowOriginStar() async throws {
        var config = ServerConfiguration.default
        config.allowedOrigins = ["*"]
        let server = try await startCORSTestServer(config: config, trustLoopback: false)
        defer { Task { await server.shutdown() } }

        var request = URLRequest(
            url: URL(string: "http://\(server.host):\(server.port)/api/tags")!
        )
        request.httpMethod = "GET"
        request.setValue("app://obsidian.md", forHTTPHeaderField: "Origin")

        let (_, resp) = try await URLSession.shared.data(for: request)
        let http = resp as? HTTPURLResponse

        #expect(http?.value(forHTTPHeaderField: "Access-Control-Allow-Origin") == "*")
    }

    /// Exact origin match must echo the origin (NOT `*`) and add `Vary: Origin`
    /// so caches don't poison cross-origin responses. This is the
    /// allowlist-with-credentials shape, only reachable on the non-loopback
    /// path now that loopback auto-trusts to `*`.
    @Test func nonLoopback_specificOrigin_match_returnsAllowOriginAndVary() async throws {
        var config = ServerConfiguration.default
        config.allowedOrigins = ["http://localhost:3000"]
        let server = try await startCORSTestServer(config: config, trustLoopback: false)
        defer { Task { await server.shutdown() } }

        var request = URLRequest(
            url: URL(string: "http://\(server.host):\(server.port)/api/tags")!
        )
        request.httpMethod = "GET"
        request.setValue("http://localhost:3000", forHTTPHeaderField: "Origin")

        let (_, resp) = try await URLSession.shared.data(for: request)
        let http = resp as? HTTPURLResponse

        #expect(http?.value(forHTTPHeaderField: "Access-Control-Allow-Origin") == "http://localhost:3000")
        let vary = http?.value(forHTTPHeaderField: "Vary") ?? ""
        #expect(vary.contains("Origin"))
    }
}

// MARK: - Bootstrap

private struct CORSTestServer {
    let group: MultiThreadedEventLoopGroup
    let channel: Channel
    let lease: HTTPServerTestLease
    let host: String
    let port: Int

    func shutdown() async {
        _ = try? await channel.close()
        await withCheckedContinuation { (cont: CheckedContinuation<Void, Never>) in
            group.shutdownGracefully { _ in cont.resume() }
        }
        await lease.release()
    }
}

/// Boots a NIO server bound to a random loopback port. `trustLoopback`
/// defaults to `true` (production default for local clients like Obsidian
/// and browser plugins, which exercise the new loopback auto-trust). Pass
/// `trustLoopback: false` to exercise the explicit-allowlist path even
/// though the connection still arrives via 127.0.0.1.
private func startCORSTestServer(
    config: ServerConfiguration,
    trustLoopback: Bool = true
) async throws -> CORSTestServer {
    let lease = await HTTPServerTestLock.shared.acquire()
    let group = MultiThreadedEventLoopGroup(numberOfThreads: 1)
    do {
        let bootstrap = ServerBootstrap(group: group)
            .serverChannelOption(ChannelOptions.backlog, value: 256)
            .serverChannelOption(ChannelOptions.socketOption(.so_reuseaddr), value: 1)
            .childChannelInitializer { channel in
                channel.pipeline.configureHTTPServerPipeline().flatMap {
                    channel.pipeline.addHandler(
                        HTTPHandler(
                            configuration: config,
                            apiKeyValidator: .empty,
                            eventLoop: channel.eventLoop,
                            trustLoopback: trustLoopback
                        )
                    )
                }
            }
            .childChannelOption(ChannelOptions.socketOption(.so_reuseaddr), value: 1)
            .childChannelOption(ChannelOptions.socketOption(.tcp_nodelay), value: 1)
            .childChannelOption(ChannelOptions.maxMessagesPerRead, value: 16)
            .childChannelOption(ChannelOptions.recvAllocator, value: AdaptiveRecvByteBufferAllocator())

        let ch = try await bootstrap.bind(host: "127.0.0.1", port: 0).get()
        let port = ch.localAddress?.port ?? 0
        return CORSTestServer(group: group, channel: ch, lease: lease, host: "127.0.0.1", port: port)
    } catch {
        await withCheckedContinuation { (cont: CheckedContinuation<Void, Never>) in
            group.shutdownGracefully { _ in cont.resume() }
        }
        await lease.release()
        throw error
    }
}
