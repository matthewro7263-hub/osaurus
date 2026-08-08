//
//  TemporaryPairedKeyStore.swift
//  osaurus
//
//  Tracks API keys generated for temporary (non-permanent) Bonjour pairings.
//  On app termination, all tracked keys are revoked and removed from APIKeyManager
//  so they cannot be reused in future sessions.
//
//  Ids are also mirrored to UserDefaults as they are minted, because a crash
//  or SIGKILL never delivers `applicationWillTerminate`: without the mirror a
//  temporary key would survive the unclean exit and stay valid for its full
//  90-day expiry. Anything still on disk at launch is an orphan from a
//  previous run and gets revoked then.
//

import AppKit
import Foundation

public final class TemporaryPairedKeyStore: @unchecked Sendable {
    public static let shared = TemporaryPairedKeyStore()

    private let queue = DispatchQueue(label: "com.osaurus.temporary-paired-keys")
    private var keyIds: [UUID] = []

    /// Mirror of `keyIds` that survives process death. Holds only key ids —
    /// the key material lives in the Keychain, and `APIKeyManager` already
    /// persists these same ids in its metadata.
    private static let pendingIdsDefaultsKey = "com.osaurus.temporary-paired-keys.pending"

    private init() {
        NotificationCenter.default.addObserver(
            self,
            selector: #selector(applicationWillTerminate),
            name: NSApplication.willTerminateNotification,
            object: nil
        )
        // Runs before this session can register anything (the singleton is
        // built on first touch), so only genuine orphans are ever revoked.
        revokeOrphansFromPreviousLaunch()
    }

    public func register(keyId: UUID) {
        queue.sync(flags: .barrier) {
            keyIds.append(keyId)
            Self.persist(keyIds)
        }
    }

    public func isTemporary(id: UUID) -> Bool {
        queue.sync { keyIds.contains(id) }
    }

    @objc private func applicationWillTerminate() {
        let ids = queue.sync { keyIds }
        for id in ids {
            APIKeyManager.shared.delete(id: id)
        }
        // The clean path revoked everything, so leave no orphans behind for
        // the next launch to sweep.
        UserDefaults.standard.removeObject(forKey: Self.pendingIdsDefaultsKey)
    }

    /// Revoke temporary keys left behind by an unclean shutdown. The record is
    /// cleared first so a failure here cannot make every later launch retry the
    /// same ids forever.
    private func revokeOrphansFromPreviousLaunch() {
        let defaults = UserDefaults.standard
        let orphans = (defaults.stringArray(forKey: Self.pendingIdsDefaultsKey) ?? [])
            .compactMap(UUID.init(uuidString:))
        guard !orphans.isEmpty else { return }
        defaults.removeObject(forKey: Self.pendingIdsDefaultsKey)
        // Keychain and revocation-store work must not run on whichever thread
        // first touched this singleton — often the server event loop.
        DispatchQueue.global(qos: .utility).async {
            for id in orphans {
                APIKeyManager.shared.delete(id: id)
            }
        }
    }

    private static func persist(_ ids: [UUID]) {
        UserDefaults.standard.set(ids.map(\.uuidString), forKey: pendingIdsDefaultsKey)
    }
}
