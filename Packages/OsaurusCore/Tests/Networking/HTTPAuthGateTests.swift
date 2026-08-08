//
//  HTTPAuthGateTests.swift
//  OsaurusCoreTests
//
//  HTTP-level tests for the access key authentication gate.
//  Each test boots a real NIO server and makes URLSession requests
//  to verify the auth behavior end-to-end.
//

import Foundation
import NIOCore
import NIOHTTP1
import NIOPosix
import Testing

@testable import OsaurusCore

struct HTTPAuthGateTests {

    // MARK: - Public Paths Bypass Auth

    @Test func publicPath_root_returns200_withoutToken() async throws {
        let server = try await startAuthTestServer(validator: .empty)
        defer { Task { await server.shutdown() } }

        let (_, resp) = try await URLSession.shared.data(
            from: URL(string: "http://\(server.host):\(server.port)/")!
        )
        #expect((resp as? HTTPURLResponse)?.statusCode == 200)
    }

    @Test func publicPath_health_returns200_withoutToken() async throws {
        let server = try await startAuthTestServer(validator: .empty)
        defer { Task { await server.shutdown() } }

        let (data, resp) = try await URLSession.shared.data(
            from: URL(string: "http://\(server.host):\(server.port)/health")!
        )
        #expect((resp as? HTTPURLResponse)?.statusCode == 200)
        let body = String(decoding: data, as: UTF8.self)
        #expect(body.contains("healthy"))
    }

    // MARK: - No Token → 401

    @Test func protectedPath_noToken_noKeys_returns401() async throws {
        let server = try await startAuthTestServer(validator: .empty)
        defer { Task { await server.shutdown() } }

        let (data, resp) = try await URLSession.shared.data(
            from: URL(string: "http://\(server.host):\(server.port)/v1/models")!
        )
        let status = (resp as? HTTPURLResponse)?.statusCode ?? -1
        let body = String(decoding: data, as: UTF8.self)
        #expect(status == 401)
        #expect(body.contains("No access keys configured"))
    }

    @Test func protectedPath_noToken_hasKeys_returns401() async throws {
        let validator = APIKeyValidator.forAlice(hasKeys: true)
        let server = try await startAuthTestServer(validator: validator)
        defer { Task { await server.shutdown() } }

        let (data, resp) = try await URLSession.shared.data(
            from: URL(string: "http://\(server.host):\(server.port)/v1/models")!
        )
        let status = (resp as? HTTPURLResponse)?.statusCode ?? -1
        let body = String(decoding: data, as: UTF8.self)
        #expect(status == 401)
        #expect(body.contains("Invalid access key"))
    }

    // MARK: - Valid Token → Passthrough

    @Test func protectedPath_validBearerToken_returns200() async throws {
        let validator = APIKeyValidator.forAlice()
        let server = try await startAuthTestServer(validator: validator)
        defer { Task { await server.shutdown() } }

        let token = try TokenBuilder.build(
            privateKey: TestKeys.alicePrivateKey,
            iss: TestKeys.aliceAddress,
            aud: TestKeys.aliceAddress
        )

        var request = URLRequest(
            url: URL(string: "http://\(server.host):\(server.port)/v1/models")!
        )
        request.setValue("Bearer \(token)", forHTTPHeaderField: "Authorization")

        let (_, resp) = try await URLSession.shared.data(for: request)
        #expect((resp as? HTTPURLResponse)?.statusCode == 200)
    }

    // MARK: - Inbound Attribution (host-side Remote Connections)

    /// A valid inbound request must stamp the matched access key's nonce +
    /// audience + transport onto its `RequestLog`, so the host's Remote
    /// Connections view can attribute `.httpAPI` traffic to a specific paired
    /// peer. Drives a real authed `GET /v1/models` and asserts the resulting
    /// Insights log carries the attribution. The token nonce is unique per run
    /// so we can find our own row in the shared ring buffer.
    @Test func validInboundRequest_stampsAccessKeyAndAudienceOntoLog() async throws {
        let validator = APIKeyValidator.forAlice()
        let server = try await startAuthTestServer(validator: validator)
        defer { Task { await server.shutdown() } }

        let nonce = "inbound-attribution-\(UUID().uuidString)"
        let token = try TokenBuilder.build(
            privateKey: TestKeys.alicePrivateKey,
            iss: TestKeys.aliceAddress,
            aud: TestKeys.aliceAddress,
            nonce: nonce
        )

        var request = URLRequest(
            url: URL(string: "http://\(server.host):\(server.port)/v1/models")!
        )
        request.setValue("Bearer \(token)", forHTTPHeaderField: "Authorization")

        let (_, resp) = try await URLSession.shared.data(for: request)
        #expect((resp as? HTTPURLResponse)?.statusCode == 200)

        // The request log is appended via an async main-actor hop, so poll the
        // shared buffer briefly for our uniquely-nonced row.
        let log = await Self.findInboundLog(accessKeyId: nonce)
        let found = try #require(
            log,
            "inbound request did not stamp accessKeyId=\(nonce) onto a RequestLog"
        )
        #expect(found.source == .httpAPI)
        #expect(found.connection?.accessKeyId == nonce)
        #expect(found.connection?.audience == TestKeys.aliceAddress.lowercased())
        // Plain HTTP (no Secure Channel handshake) is attributed as direct.
        #expect(found.connection?.transport == .direct)
    }

    /// Polls `InsightsService` (main-actor) for an inbound log stamped with the
    /// given access-key nonce. Returns nil if it never appears within ~1s.
    private static func findInboundLog(accessKeyId: String) async -> RequestLog? {
        for _ in 0 ..< 40 {
            let match = await MainActor.run {
                InsightsService.shared.logs.first {
                    $0.connection?.accessKeyId == accessKeyId
                }
            }
            if let match { return match }
            try? await Task.sleep(nanoseconds: 25_000_000)
        }
        return nil
    }

    // MARK: - Expired Token → 401

    @Test func protectedPath_expiredToken_returns401() async throws {
        let validator = APIKeyValidator.forAlice()
        let server = try await startAuthTestServer(validator: validator)
        defer { Task { await server.shutdown() } }

        let token = try TokenBuilder.build(
            privateKey: TestKeys.alicePrivateKey,
            iss: TestKeys.aliceAddress,
            aud: TestKeys.aliceAddress,
            exp: Int(Date().timeIntervalSince1970) - 3600
        )

        var request = URLRequest(
            url: URL(string: "http://\(server.host):\(server.port)/v1/models")!
        )
        request.setValue("Bearer \(token)", forHTTPHeaderField: "Authorization")

        let (data, resp) = try await URLSession.shared.data(for: request)
        let status = (resp as? HTTPURLResponse)?.statusCode ?? -1
        let body = String(decoding: data, as: UTF8.self)
        #expect(status == 401)
        #expect(body.contains("expired"))
    }

    // MARK: - Revoked Token → 401

    @Test func protectedPath_revokedToken_returns401() async throws {
        let nonce = "http_revoked_nonce"
        let revokedKey = RevocationSnapshot.revocationKey(address: TestKeys.aliceAddress, nonce: nonce)
        let snapshot = RevocationSnapshot(revokedKeys: [revokedKey], counterThresholds: [:])
        let validator = APIKeyValidator.forAlice(revocations: snapshot)
        let server = try await startAuthTestServer(validator: validator)
        defer { Task { await server.shutdown() } }

        let token = try TokenBuilder.build(
            privateKey: TestKeys.alicePrivateKey,
            iss: TestKeys.aliceAddress,
            aud: TestKeys.aliceAddress,
            nonce: nonce
        )

        var request = URLRequest(
            url: URL(string: "http://\(server.host):\(server.port)/v1/models")!
        )
        request.setValue("Bearer \(token)", forHTTPHeaderField: "Authorization")

        let (data, resp) = try await URLSession.shared.data(for: request)
        let status = (resp as? HTTPURLResponse)?.statusCode ?? -1
        let body = String(decoding: data, as: UTF8.self)
        #expect(status == 401)
        #expect(body.contains("revoked"))
    }

    // MARK: - Tampered Token → 401

    @Test func protectedPath_tamperedToken_returns401() async throws {
        let validator = APIKeyValidator.forAlice()
        let server = try await startAuthTestServer(validator: validator)
        defer { Task { await server.shutdown() } }

        let token = try TokenBuilder.build(
            privateKey: TestKeys.alicePrivateKey,
            iss: TestKeys.aliceAddress,
            aud: TestKeys.aliceAddress
        )
        let parts = token.split(separator: ".", maxSplits: 2)
        var sigChars = Array(String(parts[2]))
        sigChars[10] = sigChars[10] == "a" ? "b" : "a"
        let tampered = "osk-v1.\(parts[1]).\(String(sigChars))"

        var request = URLRequest(
            url: URL(string: "http://\(server.host):\(server.port)/v1/models")!
        )
        request.setValue("Bearer \(tampered)", forHTTPHeaderField: "Authorization")

        let (data, resp) = try await URLSession.shared.data(for: request)
        let status = (resp as? HTTPURLResponse)?.statusCode ?? -1
        let body = String(decoding: data, as: UTF8.self)
        #expect(status == 401)
        #expect(body.contains("Invalid access key"))
    }

    // MARK: - Relay Loopback Bypass Regression

    /// Baseline: with loopback trust enabled, a plain local request needs no token.
    @Test func loopbackTrusted_noToken_returns200() async throws {
        let server = try await startAuthTestServer(validator: .empty, trustLoopback: true)
        defer { Task { await server.shutdown() } }

        let (_, resp) = try await URLSession.shared.data(
            from: URL(string: "http://\(server.host):\(server.port)/v1/models")!
        )
        #expect((resp as? HTTPURLResponse)?.statusCode == 200)
    }

    /// Regression for the relay loopback auth bypass: traffic proxied by
    /// `RelayTunnelManager` arrives over 127.0.0.1 but carries the relay-origin
    /// marker, so it must NOT inherit loopback trust — a request without a
    /// Bearer token has to 401 even when `trustLoopback` is on.
    @Test func relayOriginHeader_disablesLoopbackTrust_returns401() async throws {
        let server = try await startAuthTestServer(validator: .empty, trustLoopback: true)
        defer { Task { await server.shutdown() } }

        var request = URLRequest(
            url: URL(string: "http://\(server.host):\(server.port)/v1/models")!
        )
        request.setValue("1", forHTTPHeaderField: HTTPHandler.relayOriginHeaderName)

        let (_, resp) = try await URLSession.shared.data(for: request)
        #expect((resp as? HTTPURLResponse)?.statusCode == 401)
    }

    /// Relayed traffic with a valid Bearer token still passes the gate.
    @Test func relayOriginHeader_withValidToken_returns200() async throws {
        let server = try await startAuthTestServer(validator: .forAlice(), trustLoopback: true)
        defer { Task { await server.shutdown() } }

        var request = URLRequest(
            url: URL(string: "http://\(server.host):\(server.port)/v1/models")!
        )
        request.setValue("1", forHTTPHeaderField: HTTPHandler.relayOriginHeaderName)
        request.authenticate()

        let (_, resp) = try await URLSession.shared.data(for: request)
        #expect((resp as? HTTPURLResponse)?.statusCode == 200)
    }

    // MARK: - JSON Depth Bomb

    /// A body well inside the size cap can still nest thousands of levels
    /// deep. `JSONDecoder` recurses the whole structure on the NIO event-loop
    /// thread, and a stack overflow there is a SIGSEGV — `try?` catches Swift
    /// throws, not traps — so it would take the process and every concurrent
    /// stream down. The structural depth guard must turn it into a plain 400.
    @Test func deeplyNestedJSONBody_returns400_insteadOfCrashing() async throws {
        let server = try await startAuthTestServer(validator: .empty, trustLoopback: true)
        defer { Task { await server.shutdown() } }

        let depth = 5_000
        let payload =
            #"{"model":"x","messages":[],"z":"#
            + String(repeating: "[", count: depth)
            + String(repeating: "]", count: depth)
            + "}"

        var request = URLRequest(
            url: URL(string: "http://\(server.host):\(server.port)/v1/chat/completions")!
        )
        request.httpMethod = "POST"
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        request.httpBody = Data(payload.utf8)

        let (_, resp) = try await URLSession.shared.data(for: request)
        #expect((resp as? HTTPURLResponse)?.statusCode == 400)

        // The server is still alive and serving after the depth bomb.
        let (_, healthResp) = try await URLSession.shared.data(
            from: URL(string: "http://\(server.host):\(server.port)/health")!
        )
        #expect((healthResp as? HTTPURLResponse)?.statusCode == 200)
    }

    // MARK: - Admin Scope Confinement

    /// `/admin/*` is server-global. A key minted for a single agent (a paired
    /// relay/LAN peer) must not read or mutate the whole server's runtime
    /// settings — that would escape the per-agent confinement enforced on
    /// every other addressing route.
    @Test func adminRoute_agentScopedKey_returns403() async throws {
        // Alice is master; Bob is the agent audience, so a Bob-audience token
        // validates but is NOT master-scoped.
        let validator = APIKeyValidator.forAlice(agentAddress: TestKeys.bobAddress)
        let server = try await startAuthTestServer(validator: validator, trustLoopback: false)
        defer { Task { await server.shutdown() } }

        let token = try TokenBuilder.build(
            privateKey: TestKeys.alicePrivateKey,
            iss: TestKeys.aliceAddress,
            aud: TestKeys.bobAddress
        )

        var request = URLRequest(
            url: URL(string: "http://\(server.host):\(server.port)/admin/runtime-settings")!
        )
        request.setValue("Bearer \(token)", forHTTPHeaderField: "Authorization")

        let (data, resp) = try await URLSession.shared.data(for: request)
        let status = (resp as? HTTPURLResponse)?.statusCode ?? -1
        let body = String(decoding: data, as: UTF8.self)
        #expect(status == 403)
        #expect(body.contains("admin_scope_denied"))
    }

    /// A master-scoped key keeps full admin access — the gate confines agent
    /// keys only.
    @Test func adminRoute_masterScopedKey_returns200() async throws {
        let server = try await startAuthTestServer(validator: .forAlice(), trustLoopback: false)
        defer { Task { await server.shutdown() } }

        var request = URLRequest(
            url: URL(string: "http://\(server.host):\(server.port)/admin/runtime-settings")!
        )
        request.authenticate()

        let (_, resp) = try await URLSession.shared.data(for: request)
        #expect((resp as? HTTPURLResponse)?.statusCode == 200)
    }

    /// Loopback callers never populate `authedScopeIsMaster` (they skip the
    /// auth gate entirely), so the gate has to admit them explicitly — the CLI
    /// and the local automation scripts drive these endpoints unauthenticated.
    @Test func adminRoute_loopbackCaller_returns200() async throws {
        let server = try await startAuthTestServer(validator: .empty, trustLoopback: true)
        defer { Task { await server.shutdown() } }

        let (_, resp) = try await URLSession.shared.data(
            from: URL(string: "http://\(server.host):\(server.port)/admin/runtime-settings")!
        )
        #expect((resp as? HTTPURLResponse)?.statusCode == 200)
    }
}

// MARK: - Test Server Bootstrap

private struct AuthTestServer {
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

private func startAuthTestServer(
    validator: APIKeyValidator,
    trustLoopback: Bool = false
) async throws -> AuthTestServer {
    let config = ServerConfiguration.default

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
                            apiKeyValidator: validator,
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
        return AuthTestServer(group: group, channel: ch, lease: lease, host: "127.0.0.1", port: port)
    } catch {
        await withCheckedContinuation { (cont: CheckedContinuation<Void, Never>) in
            group.shutdownGracefully { _ in cont.resume() }
        }
        await lease.release()
        throw error
    }
}
