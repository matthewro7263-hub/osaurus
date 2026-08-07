// Copyright 2026 Intelligence AI. All rights reserved.

import Foundation
import Testing

@testable import OsaurusCore

@Suite("Runtime proof matrix reporter")
struct RuntimeProofMatrixTests {
    @Test("markdown matrix renders deterministically from classification JSON")
    func markdownMatrixIsDeterministic() throws {
        let report = try RuntimeProofMatrixReporter.decodeClassification(data: Self.fixtureData)

        let first = RuntimeProofMatrixReporter.markdownMatrix(
            from: report,
            sourceClassificationPath: "/tmp/runtime/PROOF_CLASSIFICATION.json",
            generatedAt: "2026-06-11T00:00:00Z"
        )
        let second = RuntimeProofMatrixReporter.markdownMatrix(
            from: report,
            sourceClassificationPath: "/tmp/runtime/PROOF_CLASSIFICATION.json",
            generatedAt: "2026-06-11T00:00:00Z"
        )

        #expect(first == second)
        #expect(first.contains("| gemma4-text-required | Gemma4 text | gemma4 | proven |"))
        #expect(first.contains("issue-903-system-prompt-injection-schema"))
        #expect(first.contains("issue-1163-hy3-harmony-retro-validation-schema"))
        #expect(
            first.contains(
                "| issue-903-system-prompt-injection-schema | all local chat runtimes | cross-family | unproven |"
            )
        )
    }

    @Test("schema-only issue rows stay unproven and require evidence fields")
    func schemaRowsRemainUnproven() throws {
        let report = try RuntimeProofMatrixReporter.decodeClassification(data: Self.fixtureData)
        let rows = RuntimeProofMatrixReporter.matrixRows(from: report)

        let promptInjection = try #require(rows.first { $0.id == "issue-903-system-prompt-injection-schema" })
        #expect(promptInjection.verdict == .unproven)
        #expect(promptInjection.isSchemaOnly)
        #expect(promptInjection.requirements.contains("system_prompt_injection"))
        #expect(promptInjection.requirements.contains("tokens_per_second"))
        #expect(promptInjection.requirements.contains("no_parser_marker_leak"))
        #expect(promptInjection.evidencePointers.isEmpty)

        let hy3 = try #require(rows.first { $0.id == "issue-1163-hy3-harmony-retro-validation-schema" })
        #expect(hy3.verdict == .unproven)
        #expect(hy3.family == "hy3")
        #expect(hy3.blockers.contains { $0.contains("sibling model rows") })
    }

    @Test("surface recomputes counts including schema rows")
    func surfaceIncludesSchemaCounts() throws {
        let report = try RuntimeProofMatrixReporter.decodeClassification(data: Self.fixtureData)
        let surface = RuntimeProofMatrixReporter.surface(
            from: report,
            sourceClassificationPath: "/tmp/runtime/PROOF_CLASSIFICATION.json",
            generatedAt: "2026-06-11T00:00:00Z"
        )

        #expect(surface.generatedAt == "2026-06-11T00:00:00Z")
        #expect(surface.verdictCounts["proven"] == 1)
        #expect(surface.verdictCounts["partial"] == 1)
        #expect(surface.verdictCounts["failed"] == 0)
        #expect(surface.verdictCounts["unproven"] == 2)
        #expect(surface.issueCoverage["#903"]?.verdict == .unproven)
        #expect(surface.rows.count == 4)
    }

    @Test("marked matrix replacement only replaces the generated block")
    func replaceMarkedMatrix() throws {
        let report = try RuntimeProofMatrixReporter.decodeClassification(data: Self.fixtureData)
        let matrix = RuntimeProofMatrixReporter.markdownMatrix(
            from: report,
            generatedAt: "2026-06-11T00:00:00Z"
        )
        let original = """
            # Runtime validation standard

            Keep this intro.

            \(RuntimeProofMatrixReporter.markdownBeginMarker)
            stale
            \(RuntimeProofMatrixReporter.markdownEndMarker)

            Keep this footer.
            """

        let updated = RuntimeProofMatrixReporter.replaceMarkedMatrix(in: original, with: matrix)

        #expect(updated.contains("Keep this intro."))
        #expect(updated.contains("Keep this footer."))
        #expect(!updated.contains("stale"))
        #expect(updated.contains("gemma4-text-required"))
    }

    private static let fixtureData = Data(
        """
        {
          "generated_at": "2026-06-11T00:00:00Z",
          "summary_path": "/tmp/runtime/SUMMARY.json",
          "manifest_path": "scripts/live-proof/family-runtime-chat-matrix.json",
          "artifact_root": "/tmp/runtime",
          "verdict_counts": {
            "proven": 1,
            "partial": 1,
            "failed": 0,
            "unproven": 0
          },
          "required_rows_not_proven": [
            "qwen-cache-partial"
          ],
          "passed": false,
          "rows": [
            {
              "id": "qwen-cache-partial",
              "model": "Qwen cache",
              "family": "qwen",
              "priority": "required",
              "requirements": [
                "tokens_per_second",
                "cache_hit"
              ],
              "artifact_paths": [
                "/tmp/runtime/qwen/SUMMARY.json"
              ],
              "summary_path": "/tmp/runtime/qwen/SUMMARY.json",
              "verdict": "partial",
              "acceptable_for_proven_claim": false,
              "blockers": [
                {
                  "requirement": "cache_hit",
                  "message": "row lacks required topology-specific cache evidence"
                }
              ],
              "warnings": [],
              "failed_checks": []
            },
            {
              "id": "gemma4-text-required",
              "model": "Gemma4 text",
              "family": "gemma4",
              "priority": "required",
              "requirements": [
                "visible_output",
                "tokens_per_second",
                "no_parser_marker_leak",
                "multi_turn_coherency"
              ],
              "artifact_paths": [
                "/tmp/runtime/gemma4/SUMMARY.json"
              ],
              "summary_path": "/tmp/runtime/gemma4/SUMMARY.json",
              "verdict": "proven",
              "acceptable_for_proven_claim": true,
              "blockers": [],
              "warnings": [],
              "failed_checks": []
            }
          ],
          "issue_coverage": {
            "#903": {
              "verdict": "unproven",
              "note": "system-prompt injection rows are schema-only until live proof exists"
            },
            "#1163": {
              "verdict": "unproven",
              "note": "Hy3/harmony parser closure needs a local Hy3 row, not sibling inference",
              "rows": []
            }
          }
        }
        """.utf8
    )
}
