//
//  SandboxBridgeTokenStore.swift
//  osaurus
//
//  Mints, resolves, and revokes per-agent shared secrets used by the sandbox
//  host bridge to authenticate guest requests. The token is written to a
//  per-user file inside the guest VM (mode 0600, owned by the agent's Linux
//  user) — kernel file permissions are what bind a token to a single agent
//  identity. Without the right token in `Authorization: Bearer`, the bridge
//  fails closed.
//

import Foundation

public actor SandboxBridgeTokenStore {
    public static let shared = SandboxBridgeTokenStore()

    public struct Identity: Sendable, Equatable {
        public let agentId: UUID
        public let linuxName: String
        /// Plugin this credential was minted for, when it is scoped to a
        /// single one. `nil` means agent-scoped — every plugin running as
        /// that Linux user shares the token, so the bridge cannot derive a
        /// plugin identity from it. See `HostAPIBridgeServer`'s handling of
        /// `X-Osaurus-Plugin`.
        public let pluginId: String?

        init(agentId: UUID, linuxName: String, pluginId: String? = nil) {
            self.agentId = agentId
            self.linuxName = linuxName
            self.pluginId = pluginId
        }
    }

    /// token (base64url) -> identity
    private var byToken: [String: Identity] = [:]
    /// linuxName -> agent-scoped token (so subsequent registers for the same agent are idempotent)
    private var byLinuxName: [String: String] = [:]
    /// `linuxName\0pluginId` -> plugin-scoped token. Deliberately a separate
    /// index from `byLinuxName`: the agent-scoped credential is what the
    /// guest shim reads from disk and what the egress proxy attaches to
    /// `http_proxy`, so minting a plugin credential must never displace it.
    private var byPluginCredential: [String: String] = [:]

    /// Internal for tests so they can spin up an isolated store without
    /// reaching into the global singleton. Production code uses
    /// `SandboxBridgeTokenStore.shared`.
    init() {}

    /// Generate (or return the existing) bridge token for the given agent's Linux user.
    /// Idempotent per `linuxName`: subsequent calls with the same user return the same token.
    public func register(agentId: UUID, linuxName: String) -> String {
        if let existing = byLinuxName[linuxName] {
            return existing
        }
        let token = Self.generateToken()
        byToken[token] = Identity(agentId: agentId, linuxName: linuxName)
        byLinuxName[linuxName] = token
        return token
    }

    /// Generate (or return the existing) bridge token scoped to ONE plugin of
    /// the given agent. Idempotent per `(linuxName, pluginId)`.
    ///
    /// The resulting `Identity` carries `pluginId`, which the bridge treats as
    /// the authoritative plugin scope instead of the guest-supplied
    /// `X-Osaurus-Plugin` header. Nothing in the guest provisioning path mints
    /// one yet (all plugins of an agent share a single Linux user and a single
    /// 0600 token file, so a per-plugin file would be readable by every
    /// sibling); this is the credential side of that staged tightening.
    public func register(agentId: UUID, linuxName: String, pluginId: String) -> String {
        let key = Self.pluginCredentialKey(linuxName: linuxName, pluginId: pluginId)
        if let existing = byPluginCredential[key] {
            return existing
        }
        let token = Self.generateToken()
        byToken[token] = Identity(agentId: agentId, linuxName: linuxName, pluginId: pluginId)
        byPluginCredential[key] = token
        return token
    }

    /// Resolve the identity behind a bearer token, or `nil` if unknown.
    public func resolve(token: String) -> Identity? {
        byToken[token]
    }

    /// The token minted for a Linux user, if any. Used by the egress
    /// proxy env injection to attach the caller's own credential to
    /// `http_proxy` — never someone else's.
    public func token(forLinuxName linuxName: String) -> String? {
        byLinuxName[linuxName]
    }

    /// Revoke a token for a Linux user — used when the agent is unprovisioned.
    /// Any plugin-scoped credentials minted for that same user go with it:
    /// leaving one live would keep a revoked agent authenticated.
    @discardableResult
    public func revoke(linuxName: String) -> Bool {
        var removedAny = false
        if let token = byLinuxName.removeValue(forKey: linuxName) {
            byToken.removeValue(forKey: token)
            removedAny = true
        }
        let prefix = Self.pluginCredentialKey(linuxName: linuxName, pluginId: "")
        for key in byPluginCredential.keys.filter({ $0.hasPrefix(prefix) }) {
            if let token = byPluginCredential.removeValue(forKey: key) {
                byToken.removeValue(forKey: token)
                removedAny = true
            }
        }
        return removedAny
    }

    /// Wipe all tokens — used when the container is fully reset, so a fresh
    /// boot does not accept old in-memory tokens that no longer correspond to
    /// what is on disk inside the guest.
    public func revokeAll() {
        byToken.removeAll()
        byLinuxName.removeAll()
        byPluginCredential.removeAll()
    }

    public func tokenCount() -> Int {
        byToken.count
    }

    // MARK: - Generation

    /// Index key for a plugin-scoped credential. NUL separates the two parts
    /// so no `(linuxName, pluginId)` pair can collide with another, and so
    /// `revoke(linuxName:)` can prefix-match one user's plugin credentials
    /// without matching a different user whose name shares a prefix.
    private static func pluginCredentialKey(linuxName: String, pluginId: String) -> String {
        "\(linuxName)\u{0}\(pluginId)"
    }

    /// Produce a 256-bit cryptographically random token, base64url-encoded.
    private static func generateToken() -> String {
        var bytes = [UInt8](repeating: 0, count: 32)
        let status = SecRandomCopyBytes(kSecRandomDefault, bytes.count, &bytes)
        if status != errSecSuccess {
            // Fall back to UUID stitching on the (extremely unlikely) failure
            // of the system RNG. We still want to fail closed rather than
            // mint a predictable token, so encode two UUIDs worth of entropy.
            let a = UUID().uuid
            let b = UUID().uuid
            withUnsafeBytes(of: a) { ptr in bytes.replaceSubrange(0 ..< 16, with: ptr) }
            withUnsafeBytes(of: b) { ptr in bytes.replaceSubrange(16 ..< 32, with: ptr) }
        }
        return Data(bytes).base64URLEncodedString()
    }
}

// MARK: - Base64URL helper

private extension Data {
    func base64URLEncodedString() -> String {
        var s = base64EncodedString()
        s = s.replacingOccurrences(of: "+", with: "-")
        s = s.replacingOccurrences(of: "/", with: "_")
        s = s.replacingOccurrences(of: "=", with: "")
        return s
    }
}
