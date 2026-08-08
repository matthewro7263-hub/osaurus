//
//  SandboxBridgeTokenStoreTests.swift
//  OsaurusCoreTests
//
//  Verifies the per-agent bridge token store: tokens are unique per user,
//  registration is idempotent for the same Linux user, unknown tokens fail
//  closed, and revocation removes both lookup directions.
//

import Foundation
import Testing

@testable import OsaurusCore

@Suite("SandboxBridgeTokenStore")
struct SandboxBridgeTokenStoreTests {

    @Test
    func register_returnsStableTokenForSameUser() async {
        let store = SandboxBridgeTokenStore()
        let agent = UUID()
        let t1 = await store.register(agentId: agent, linuxName: "agent-test")
        let t2 = await store.register(agentId: agent, linuxName: "agent-test")
        #expect(t1 == t2)
    }

    @Test
    func register_returnsDistinctTokensPerUser() async {
        let store = SandboxBridgeTokenStore()
        let t1 = await store.register(agentId: UUID(), linuxName: "agent-a")
        let t2 = await store.register(agentId: UUID(), linuxName: "agent-b")
        #expect(t1 != t2)
    }

    @Test
    func resolve_returnsBoundIdentity() async {
        let store = SandboxBridgeTokenStore()
        let agent = UUID()
        let token = await store.register(agentId: agent, linuxName: "agent-test")
        let resolved = await store.resolve(token: token)
        #expect(resolved?.agentId == agent)
        #expect(resolved?.linuxName == "agent-test")
    }

    @Test
    func resolve_unknownToken_returnsNil() async {
        let store = SandboxBridgeTokenStore()
        _ = await store.register(agentId: UUID(), linuxName: "agent-a")
        let resolved = await store.resolve(token: "this-is-not-a-real-token")
        #expect(resolved == nil)
    }

    @Test
    func resolve_emptyToken_returnsNil() async {
        let store = SandboxBridgeTokenStore()
        _ = await store.register(agentId: UUID(), linuxName: "agent-a")
        let resolved = await store.resolve(token: "")
        #expect(resolved == nil)
    }

    @Test
    func revoke_dropsToken() async {
        let store = SandboxBridgeTokenStore()
        let agent = UUID()
        let token = await store.register(agentId: agent, linuxName: "agent-x")
        let removed = await store.revoke(linuxName: "agent-x")
        #expect(removed == true)
        let resolved = await store.resolve(token: token)
        #expect(resolved == nil)
    }

    @Test
    func revoke_unknownUser_returnsFalse() async {
        let store = SandboxBridgeTokenStore()
        let removed = await store.revoke(linuxName: "agent-never-registered")
        #expect(removed == false)
    }

    @Test
    func revokeAll_clearsEverything() async {
        let store = SandboxBridgeTokenStore()
        let t1 = await store.register(agentId: UUID(), linuxName: "agent-a")
        let t2 = await store.register(agentId: UUID(), linuxName: "agent-b")
        await store.revokeAll()
        let r1 = await store.resolve(token: t1)
        let r2 = await store.resolve(token: t2)
        #expect(r1 == nil)
        #expect(r2 == nil)
        let count = await store.tokenCount()
        #expect(count == 0)
    }

    // MARK: - Plugin-scoped credentials

    @Test
    func register_agentScopedIdentityCarriesNoPlugin() async {
        let store = SandboxBridgeTokenStore()
        let token = await store.register(agentId: UUID(), linuxName: "agent-test")
        let resolved = await store.resolve(token: token)
        #expect(resolved?.pluginId == nil)
    }

    @Test
    func registerWithPlugin_bindsPluginToTheCredential() async {
        let store = SandboxBridgeTokenStore()
        let agent = UUID()
        let token = await store.register(
            agentId: agent, linuxName: "agent-test", pluginId: "weather")
        let resolved = await store.resolve(token: token)
        #expect(resolved?.agentId == agent)
        #expect(resolved?.linuxName == "agent-test")
        #expect(resolved?.pluginId == "weather")
    }

    @Test
    func registerWithPlugin_isIdempotentPerPluginAndDistinctAcrossPlugins() async {
        let store = SandboxBridgeTokenStore()
        let agent = UUID()
        let a1 = await store.register(agentId: agent, linuxName: "agent-x", pluginId: "weather")
        let a2 = await store.register(agentId: agent, linuxName: "agent-x", pluginId: "weather")
        let b = await store.register(agentId: agent, linuxName: "agent-x", pluginId: "billing")
        #expect(a1 == a2)
        #expect(a1 != b)
        // Same plugin id under a different Linux user is a different credential.
        let other = await store.register(agentId: UUID(), linuxName: "agent-y", pluginId: "weather")
        #expect(other != a1)
    }

    @Test
    func registerWithPlugin_doesNotDisplaceTheAgentScopedToken() async {
        // The shim reads the agent-scoped token from disk and the egress
        // proxy attaches it to `http_proxy`; minting a plugin credential
        // must leave it untouched.
        let store = SandboxBridgeTokenStore()
        let agent = UUID()
        let agentToken = await store.register(agentId: agent, linuxName: "agent-x")
        let pluginToken = await store.register(
            agentId: agent, linuxName: "agent-x", pluginId: "weather")
        let proxyToken = await store.token(forLinuxName: "agent-x")
        let agentIdentity = await store.resolve(token: agentToken)
        #expect(agentToken != pluginToken)
        #expect(proxyToken == agentToken)
        #expect(agentIdentity?.pluginId == nil)
    }

    @Test
    func revoke_alsoDropsPluginScopedCredentialsForThatUser() async {
        let store = SandboxBridgeTokenStore()
        let agent = UUID()
        let agentToken = await store.register(agentId: agent, linuxName: "agent-x")
        let pluginToken = await store.register(
            agentId: agent, linuxName: "agent-x", pluginId: "weather")
        // A different user whose credentials must survive the revoke.
        let survivor = await store.register(agentId: UUID(), linuxName: "agent-y", pluginId: "w")

        let removed = await store.revoke(linuxName: "agent-x")
        let resolvedAgent = await store.resolve(token: agentToken)
        let resolvedPlugin = await store.resolve(token: pluginToken)
        let resolvedSurvivor = await store.resolve(token: survivor)
        #expect(removed == true)
        #expect(resolvedAgent == nil)
        #expect(resolvedPlugin == nil)
        #expect(resolvedSurvivor != nil)
    }

    @Test
    func revokeAll_clearsPluginScopedCredentialsToo() async {
        let store = SandboxBridgeTokenStore()
        let token = await store.register(
            agentId: UUID(), linuxName: "agent-x", pluginId: "weather")
        await store.revokeAll()
        let resolved = await store.resolve(token: token)
        let count = await store.tokenCount()
        #expect(resolved == nil)
        #expect(count == 0)
    }

    @Test
    func tokens_areLongEnoughToBeUnpredictable() async {
        // 256 bits of entropy → base64url is at least 43 chars (no padding).
        let store = SandboxBridgeTokenStore()
        let token = await store.register(agentId: UUID(), linuxName: "agent-len")
        #expect(token.count >= 43)
        // base64url alphabet only.
        let allowed = Set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_")
        for ch in token {
            #expect(allowed.contains(ch))
        }
    }
}
