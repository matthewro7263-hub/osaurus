// Copyright 2026 Intelligence AI. All rights reserved.

import Foundation

/// Decoded output from `scripts/live-proof/classify-runtime-proof-summary.py`.
///
/// The classifier owns live-artifact parsing. This type intentionally models
/// only the fields needed for the read-only matrix so the UI/docs layer cannot
/// invent new proof claims from raw harness data.
public struct RuntimeProofClassificationReport: Codable, Sendable, Equatable {
    public var generatedAt: String?
    public var summaryPath: String?
    public var manifestPath: String?
    public var artifactRoot: String?
    public var verdictCounts: [String: Int]
    public var requiredRowsNotProven: [String]
    public var passed: Bool
    public var rows: [RuntimeProofClassificationRow]
    public var issueCoverage: [String: RuntimeProofIssueCoverage]

    public init(
        generatedAt: String? = nil,
        summaryPath: String? = nil,
        manifestPath: String? = nil,
        artifactRoot: String? = nil,
        verdictCounts: [String: Int] = [:],
        requiredRowsNotProven: [String] = [],
        passed: Bool = false,
        rows: [RuntimeProofClassificationRow] = [],
        issueCoverage: [String: RuntimeProofIssueCoverage] = [:]
    ) {
        self.generatedAt = generatedAt
        self.summaryPath = summaryPath
        self.manifestPath = manifestPath
        self.artifactRoot = artifactRoot
        self.verdictCounts = verdictCounts
        self.requiredRowsNotProven = requiredRowsNotProven
        self.passed = passed
        self.rows = rows
        self.issueCoverage = issueCoverage
    }

    private enum CodingKeys: String, CodingKey {
        case generatedAt = "generated_at"
        case summaryPath = "summary_path"
        case manifestPath = "manifest_path"
        case artifactRoot = "artifact_root"
        case verdictCounts = "verdict_counts"
        case requiredRowsNotProven = "required_rows_not_proven"
        case passed
        case rows
        case issueCoverage = "issue_coverage"
    }
}

public struct RuntimeProofClassificationRow: Codable, Sendable, Equatable {
    public var id: String
    public var model: String?
    public var family: String?
    public var priority: String?
    public var requirements: [String]
    public var artifactPaths: [String]
    public var summaryPath: String?
    public var verdict: RuntimeProofVerdict
    public var acceptableForProvenClaim: Bool
    public var blockers: [RuntimeProofMatrixMessage]
    public var warnings: [RuntimeProofMatrixMessage]
    public var failedChecks: [String]

    public init(
        id: String,
        model: String? = nil,
        family: String? = nil,
        priority: String? = nil,
        requirements: [String] = [],
        artifactPaths: [String] = [],
        summaryPath: String? = nil,
        verdict: RuntimeProofVerdict,
        acceptableForProvenClaim: Bool = false,
        blockers: [RuntimeProofMatrixMessage] = [],
        warnings: [RuntimeProofMatrixMessage] = [],
        failedChecks: [String] = []
    ) {
        self.id = id
        self.model = model
        self.family = family
        self.priority = priority
        self.requirements = requirements
        self.artifactPaths = artifactPaths
        self.summaryPath = summaryPath
        self.verdict = verdict
        self.acceptableForProvenClaim = acceptableForProvenClaim
        self.blockers = blockers
        self.warnings = warnings
        self.failedChecks = failedChecks
    }

    private enum CodingKeys: String, CodingKey {
        case id
        case model
        case family
        case priority
        case requirements
        case artifactPaths = "artifact_paths"
        case summaryPath = "summary_path"
        case verdict
        case acceptableForProvenClaim = "acceptable_for_proven_claim"
        case blockers
        case warnings
        case failedChecks = "failed_checks"
    }
}

public struct RuntimeProofIssueCoverage: Codable, Sendable, Equatable {
    public var verdict: RuntimeProofVerdict
    public var note: String
    public var rows: [String]
    public var requiredRowsNotProven: [String]

    public init(
        verdict: RuntimeProofVerdict,
        note: String,
        rows: [String] = [],
        requiredRowsNotProven: [String] = []
    ) {
        self.verdict = verdict
        self.note = note
        self.rows = rows
        self.requiredRowsNotProven = requiredRowsNotProven
    }

    private enum CodingKeys: String, CodingKey {
        case verdict
        case note
        case rows
        case requiredRowsNotProven = "required_rows_not_proven"
    }

    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        self.verdict = try container.decode(RuntimeProofVerdict.self, forKey: .verdict)
        self.note = try container.decodeIfPresent(String.self, forKey: .note) ?? ""
        self.rows = try container.decodeIfPresent([String].self, forKey: .rows) ?? []
        self.requiredRowsNotProven =
            try container.decodeIfPresent([String].self, forKey: .requiredRowsNotProven) ?? []
    }
}

public struct RuntimeProofMatrixMessage: Codable, Sendable, Equatable {
    public var requirement: String?
    public var message: String

    public init(requirement: String? = nil, message: String) {
        self.requirement = requirement
        self.message = message
    }
}

public struct RuntimeProofMatrixRow: Codable, Sendable, Equatable {
    public var id: String
    public var model: String
    public var family: String
    public var priority: String
    public var verdict: RuntimeProofVerdict
    public var requirements: [String]
    public var evidencePointers: [String]
    public var blockers: [String]
    public var isSchemaOnly: Bool

    public init(
        id: String,
        model: String,
        family: String,
        priority: String,
        verdict: RuntimeProofVerdict,
        requirements: [String],
        evidencePointers: [String],
        blockers: [String],
        isSchemaOnly: Bool = false
    ) {
        self.id = id
        self.model = model
        self.family = family
        self.priority = priority
        self.verdict = verdict
        self.requirements = requirements
        self.evidencePointers = evidencePointers
        self.blockers = blockers
        self.isSchemaOnly = isSchemaOnly
    }
}

public struct RuntimeProofMatrixSurface: Codable, Sendable, Equatable {
    public var generatedAt: String
    public var sourceClassificationPath: String?
    public var artifactRoot: String?
    public var verdictCounts: [String: Int]
    public var rows: [RuntimeProofMatrixRow]
    public var issueCoverage: [String: RuntimeProofIssueCoverage]

    public init(
        generatedAt: String,
        sourceClassificationPath: String?,
        artifactRoot: String?,
        verdictCounts: [String: Int],
        rows: [RuntimeProofMatrixRow],
        issueCoverage: [String: RuntimeProofIssueCoverage]
    ) {
        self.generatedAt = generatedAt
        self.sourceClassificationPath = sourceClassificationPath
        self.artifactRoot = artifactRoot
        self.verdictCounts = verdictCounts
        self.rows = rows
        self.issueCoverage = issueCoverage
    }
}

public enum RuntimeProofMatrixReporter {
    public static let markdownBeginMarker = "<!-- BEGIN RUNTIME PROOF MATRIX -->"
    public static let markdownEndMarker = "<!-- END RUNTIME PROOF MATRIX -->"

    public static func decodeClassification(data: Data) throws -> RuntimeProofClassificationReport {
        let decoder = JSONDecoder()
        return try decoder.decode(RuntimeProofClassificationReport.self, from: data)
    }

    public static func surface(
        from report: RuntimeProofClassificationReport,
        sourceClassificationPath: String? = nil,
        generatedAt: String? = nil
    ) -> RuntimeProofMatrixSurface {
        let rows = matrixRows(from: report)
        return RuntimeProofMatrixSurface(
            generatedAt: generatedAt ?? report.generatedAt ?? "unknown",
            sourceClassificationPath: sourceClassificationPath,
            artifactRoot: report.artifactRoot,
            verdictCounts: verdictCounts(for: rows),
            rows: rows,
            issueCoverage: report.issueCoverage
        )
    }

    public static func matrixRows(from report: RuntimeProofClassificationReport) -> [RuntimeProofMatrixRow] {
        let liveRows = report.rows.map(matrixRow(from:))
        let existing = Set(liveRows.map(\.id))
        let schemaRows = requiredSchemaRows.filter { !existing.contains($0.id) }
        return (liveRows + schemaRows).sorted(by: rowSort)
    }

    public static func markdownMatrix(
        from report: RuntimeProofClassificationReport,
        sourceClassificationPath: String? = nil,
        generatedAt: String? = nil
    ) -> String {
        let surface = surface(
            from: report,
            sourceClassificationPath: sourceClassificationPath,
            generatedAt: generatedAt
        )
        var lines: [String] = [
            markdownBeginMarker,
            "",
            "Generated from \(escapeMarkdown(surface.sourceClassificationPath ?? report.summaryPath ?? "PROOF_CLASSIFICATION.json")) at \(escapeMarkdown(surface.generatedAt)).",
            "",
            "| Row | Model | Family | Verdict | Requirements | Evidence | Blockers |",
            "|---|---|---|---|---|---|---|",
        ]
        for row in surface.rows {
            lines.append(
                [
                    row.id,
                    row.model,
                    row.family,
                    row.verdict.rawValue,
                    row.requirements.joined(separator: ", "),
                    row.evidencePointers.isEmpty ? "none" : row.evidencePointers.joined(separator: "<br>"),
                    row.blockers.isEmpty ? "none" : row.blockers.joined(separator: "<br>"),
                ]
                .map(escapeMarkdown)
                .joined(separator: " | ")
                .withMarkdownTablePipes()
            )
        }
        lines.append("")
        lines.append(markdownEndMarker)
        return lines.joined(separator: "\n") + "\n"
    }

    public static func replaceMarkedMatrix(in document: String, with matrixMarkdown: String) -> String {
        guard
            let begin = document.range(of: markdownBeginMarker),
            let end = document.range(of: markdownEndMarker, range: begin.upperBound ..< document.endIndex)
        else {
            let separator = document.hasSuffix("\n") ? "\n" : "\n\n"
            return document + separator + matrixMarkdown
        }
        return String(document[..<begin.lowerBound]) + matrixMarkdown + String(document[end.upperBound...])
    }

    private static func matrixRow(from row: RuntimeProofClassificationRow) -> RuntimeProofMatrixRow {
        let evidence = uniqueNonEmpty([row.summaryPath].compactMap { $0 } + row.artifactPaths)
        let blockers = row.blockers.map { message in
            if let requirement = message.requirement, !requirement.isEmpty {
                return "\(requirement): \(message.message)"
            }
            return message.message
        }
        return RuntimeProofMatrixRow(
            id: row.id,
            model: row.model ?? row.id,
            family: row.family ?? "unknown",
            priority: row.priority ?? "unspecified",
            verdict: row.verdict,
            requirements: normalizedRequirements(row.requirements),
            evidencePointers: evidence,
            blockers: blockers,
            isSchemaOnly: false
        )
    }

    private static let requiredSchemaRows: [RuntimeProofMatrixRow] = [
        RuntimeProofMatrixRow(
            id: "issue-903-system-prompt-injection-schema",
            model: "all local chat runtimes",
            family: "cross-family",
            priority: "schema-required",
            verdict: .unproven,
            requirements: [
                "visible_output",
                "tokens_per_second",
                "no_parser_marker_leak",
                "multi_turn_coherency",
                "system_prompt_injection",
            ],
            evidencePointers: [],
            blockers: [
                "requires a live artifact with an explicit system-prompt injection probe, visible output, token/s, multi-turn coherency, and no parser marker leakage"
            ],
            isSchemaOnly: true
        ),
        RuntimeProofMatrixRow(
            id: "issue-1163-hy3-harmony-retro-validation-schema",
            model: "Hy3/harmony local rows",
            family: "hy3",
            priority: "schema-required",
            verdict: .unproven,
            requirements: [
                "visible_output",
                "tokens_per_second",
                "no_parser_marker_leak",
                "multi_turn_coherency",
            ],
            evidencePointers: [],
            blockers: [
                "requires a Hy3/harmony live artifact; sibling model rows or source-only parser checks do not prove this issue"
            ],
            isSchemaOnly: true
        ),
    ]

    private static func normalizedRequirements(_ requirements: [String]) -> [String] {
        requirements
            .map { $0.trimmingCharacters(in: .whitespacesAndNewlines) }
            .filter { !$0.isEmpty }
            .sorted()
    }

    private static func uniqueNonEmpty(_ values: [String]) -> [String] {
        var seen: Set<String> = []
        var result: [String] = []
        for value in values where !value.isEmpty && !seen.contains(value) {
            seen.insert(value)
            result.append(value)
        }
        return result
    }

    private static func verdictCounts(for rows: [RuntimeProofMatrixRow]) -> [String: Int] {
        Dictionary(grouping: rows, by: { $0.verdict.rawValue })
            .mapValues(\.count)
            .merging(
                Dictionary(uniqueKeysWithValues: RuntimeProofVerdict.allCases.map { ($0.rawValue, 0) }),
                uniquingKeysWith: { lhs, _ in lhs }
            )
    }

    private static func rowSort(_ lhs: RuntimeProofMatrixRow, _ rhs: RuntimeProofMatrixRow) -> Bool {
        let left = [lhs.family, lhs.model, lhs.id]
        let right = [rhs.family, rhs.model, rhs.id]
        return left.lexicographicallyPrecedes(right)
    }

    private static func escapeMarkdown(_ value: String) -> String {
        value
            .replacingOccurrences(of: "\n", with: "<br>")
            .replacingOccurrences(of: "|", with: "\\|")
    }
}

extension String {
    fileprivate func withMarkdownTablePipes() -> String {
        "| \(self) |"
    }
}
