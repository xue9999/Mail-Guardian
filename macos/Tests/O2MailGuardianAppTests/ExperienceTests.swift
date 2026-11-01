import Darwin
import Testing
@testable import O2MailGuardianApp

extension ProtocolTests {
    @MainActor
    @Test func cancelledOperationCannotReportSuccessOrKeepTrustedReadiness() async {
        let model = GuardianModel()
        let completed = await model.perform {
            throw APIErrorPayload(code: "CANCELLED", severity: "info", message: "Anulowano", recovery: nil)
        }
        #expect(!completed)
        #expect(!model.busy)
        #expect(model.failure == nil)
        #expect(model.snapshotIsStale)
        #expect(model.notice?.contains("Previously completed steps") == true)
    }

    @MainActor
    @Test func skippedOperationCannotReportSuccess() async {
        let model = GuardianModel()
        model.busy = true
        var invoked = false
        let completed = await model.perform { invoked = true; return "Gotowe" }
        #expect(!completed)
        #expect(!invoked)
        #expect(model.busy)
        #expect(model.notice == nil)
    }

    @MainActor
    @Test func operationRequiresSuccessfulStateRefreshBeforeContinuing() async {
        let previous = getenv("GUARDIAN_MOCK_SCENARIO").map { String(cString: $0) }
        defer {
            if let previous { setenv("GUARDIAN_MOCK_SCENARIO", previous, 1) }
            else { unsetenv("GUARDIAN_MOCK_SCENARIO") }
        }
        let model = GuardianModel()
        setenv("GUARDIAN_MOCK_SCENARIO", "offline", 1)
        let unconfirmed = await model.perform { "Zapisano ustawienie" }
        #expect(!unconfirmed)
        #expect(model.snapshotIsStale)
        #expect(model.failure != nil)
        setenv("GUARDIAN_MOCK_SCENARIO", "healthy", 1)
        let confirmed = await model.perform { "Zapisano ustawienie" }
        #expect(confirmed)
        #expect(!model.snapshotIsStale)
        #expect(model.failure == nil)
        #expect(!model.busy)
    }

    @MainActor
    @Test func archiveFailureClearsStaleRowsAndRetryKeepsRequestedPage() async {
        let previous = getenv("GUARDIAN_MOCK_SCENARIO").map { String(cString: $0) }
        defer {
            if let previous { setenv("GUARDIAN_MOCK_SCENARIO", previous, 1) }
            else { unsetenv("GUARDIAN_MOCK_SCENARIO") }
        }
        setenv("GUARDIAN_MOCK_SCENARIO", "healthy", 1)
        let model = GuardianModel()
        await model.loadArchive()
        #expect(!model.archivePage.items.isEmpty)
        setenv("GUARDIAN_MOCK_SCENARIO", "archive-error", 1)
        await model.loadArchive(page: 2)
        #expect(!model.archiveLoaded)
        #expect(model.failure?.code == "ARCHIVE")
        #expect(model.archivePage.items.isEmpty)
        #expect(!model.archivePage.hasNext)
        #expect(model.archivePage.page == 2)
        setenv("GUARDIAN_MOCK_SCENARIO", "healthy", 1)
        await model.loadArchive(page: model.archivePage.page)
        #expect(model.archiveLoaded)
        #expect(model.failure == nil)
        #expect(model.archivePage.page == 2)
    }
    @Test func healthyObserverNeverClaimsActiveSorting() {
        var snapshot = GuardianSnapshot()
        snapshot.configured = true
        snapshot.health = "healthy"
        snapshot.automation = "on"
        snapshot.mode = "protect"
        #expect(ProtectionPresentation(snapshot).title == "Inbox under observation")
        #expect(ProtectionPresentation(snapshot).symbol == "eye.fill")
        snapshot.mode = "active"
        #expect(ProtectionPresentation(snapshot).title == "Cleanup enabled")
        snapshot.automation = "off"
        #expect(ProtectionPresentation(snapshot).title == "Checks on demand")
    }

    @Test func unknownModeAndStaleDataCannotAppearHealthy() {
        var snapshot = GuardianSnapshot()
        snapshot.configured = true
        snapshot.health = "healthy"
        snapshot.automation = "on"
        snapshot.mode = "unexpected"
        #expect(ProtectionPresentation(snapshot).title == "Check protection settings")
        snapshot.mode = "active"
        #expect(ProtectionPresentation(snapshot, stale: true).title == "Cannot confirm status")
        #expect(ProtectionPresentation(snapshot, stale: true).symbol == "questionmark.shield")
        snapshot.health = "critical"
        #expect(ProtectionPresentation(snapshot).title == "Protection needs repair")
        snapshot.health = "attention"
        #expect(ProtectionPresentation(snapshot).title == "Protection needs attention")
    }

    @Test func olderSnapshotsToNotInventActivationReadiness() throws {
        let json = #"{"protocol":1,"ok":true,"data":{"configured":true,"health":"healthy","health_label":"OK","recommendation":"OK","automation":"on","mode":"protect","purge_enabled":false,"summary":{},"trained_spam":200,"trained_ham":200,"required_spam":200,"required_ham":200,"first_dry_run":true,"app_autostart":true,"version":"0.3.0"}}"#
        let snapshot = try ProtocolContract.decodeSnapshot(json).data
        #expect(snapshot?.protection == nil)
    }

    @Test func dryRunReportsTheActualOperationRatherThanDailyTotals() async throws {
        let result: CompletionResult = try await Backend.call(["run", "dry-run"])
        #expect(result.completed)
        #expect(result.summary?.dryRun == true)
        #expect(result.summary?.scanned == 24)
        #expect(result.summary?.review == 6)
        #expect(result.summary?.errors == 0)
    }

    @Test func archiveFilterReachesTheBackend() async throws {
        let result: ArchivePage = try await Backend.call(["archive", "list", "1", "review"])
        #expect(result.items.count == 1)
        #expect(result.items.first?.status == "review")
        #expect(!result.hasNext)
    }

    @MainActor
    @Test func reconfigurationRevokesReadinessAndPreviousScanResult() {
        let model = GuardianModel()
        model.snapshot.protection = ProtectionProgress(requiredDays: 14, remainingDays: 0, periodComplete: true, qualityReady: true, ready: true, message: "ready")
        model.lastScan = ScanOutcome(dryRun: true, scanned: 5, kept: 5, rescued: 0, quarantined: 0, review: 0, errors: 0)
        model.markConfigurationCommitted()
        #expect(model.snapshot.protection == nil)
        #expect(model.lastScan == nil)
        #expect(!model.snapshot.firstDryRun)
    }
    @MainActor
    @Test func archiveDateFilterReachesBackendWithCategory() async {
        let model = GuardianModel()
        model.archiveFilter = "quarantined"
        model.archiveDateRange = ["2026-08-20T00:00:00Z", "2026-08-21T00:00:00Z"]
        await model.loadArchive()
        #expect(model.archiveLoaded)
        #expect(model.archivePage.items.map(\.id) == [103])
        #expect(!model.archivePage.hasNext)
        model.archiveDateRange = ["2026-09-01T00:00:00Z", "2026-09-02T00:00:00Z"]
        await model.loadArchive()
        #expect(model.archiveLoaded)
        #expect(model.archivePage.items.isEmpty)
    }
}
