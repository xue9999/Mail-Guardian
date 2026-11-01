import Foundation
import Testing
@testable import O2MailGuardianApp

@Suite(.serialized)
struct ProtocolTests {
    private final class OperationToken {}

    @Test func setupCommitEncodesBackendFieldNames() throws {
        let data = try Backend.encodeInput(SetupConnectionRequest(
            email: "test@example.org", password: "synthetic", provider: "custom", host: "imap.example.org", port: 993,
            username: "separate-login", spamFolder: "Spam", acceptExistingTraining: true
        ))
        let fields = try #require(JSONSerialization.jsonObject(with: data) as? [String: Any])
        #expect(fields["host"] as? String == "imap.example.org")
        #expect(fields["username"] as? String == "separate-login")
        #expect(fields["auth_method"] as? String == "password")
        #expect(fields["spam_folder"] as? String == "Spam")
        #expect(fields["accept_existing_training"] as? Bool == true)
        #expect(fields["spamFolder"] == nil)
        #expect(fields["acceptExistingTraining"] == nil)
    }

    @Test func snapshotEnvelopeDecodesSnakeCaseWithoutMailContent() throws {
        let json = #"{"protocol":1,"ok":true,"data":{"configured":true,"health":"healthy","health_label":"Everything works","recommendation":"OK","automation":"on","mode":"protect","purge_enabled":false,"summary":{},"trained_spam":2,"trained_ham":3,"required_spam":200,"required_ham":200,"first_dry_run":true,"app_autostart":true,"version":"0.3.0"}}"#
        let envelope = try ProtocolContract.decodeSnapshot(json)
        #expect(envelope.ok)
        #expect(envelope.data?.healthLabel == "Everything works")
        #expect(envelope.data?.trainedHam == 3)
        #expect(envelope.data?.folders.review == "AI-Do-sprawdzenia")
        #expect(envelope.data?.connection == nil)
    }

    @Test func snapshotUsesConfiguredFoldersWithoutSecretMetadata() throws {
        let json = #"{"protocol":1,"ok":true,"data":{"configured":true,"health":"healthy","health_label":"Everything works","recommendation":"OK","automation":"off","mode":"protect","purge_enabled":false,"summary":{},"trained_spam":0,"trained_ham":0,"required_spam":200,"required_ham":200,"first_dry_run":true,"app_autostart":false,"version":"0.7.0","connection":{"email":"fixture@example.org","provider":"custom","host":"imap.example.org","port":1993,"username":"separate-login"},"mailbox_folders":{"quarantine":"Safe/Hold","review":"Safe/Review","train_spam":"Safe/Spam","train_ham":"Safe/Ham"}}}"#
        let snapshot = try #require(ProtocolContract.decodeSnapshot(json).data)
        #expect(snapshot.connection?.host == "imap.example.org")
        #expect(snapshot.connection?.username == "separate-login")
        #expect(snapshot.folders.review == "Safe/Review")
        #expect(snapshot.folders.trainHam == "Safe/Ham")
    }

    @Test func errorEnvelopeToesNotRequireData() throws {
        let json = #"{"protocol":1,"ok":false,"error":{"code":"IMAP_AUTH","severity":"attention","message":"Error","recovery":"Check your password"}}"#
        let envelope = try ProtocolContract.decodeEmpty(json)
        #expect(envelope.error?.code == "IMAP_AUTH")
    }

    @Test func commonFailuresOfferOneUsefulAction() {
        #expect(failureQuickAction(for: "IMAP_AUTH") == .accountSettings)
        #expect(failureQuickAction(for: "RSPAMD_UNAVAILABLE") == .repair)
        #expect(failureQuickAction(for: "SERVICE_STALE") == .repair)
        #expect(failureQuickAction(for: "CONFIG_INVALID") == .none)
        #expect(failureQuickAction(for: nil) == .none)
    }

    @Test func backendOperationsHaveBoundedTimeouts() {
        #expect(Backend.timeoutSeconds(for: ["api", "snapshot"]) == 300)
        #expect(Backend.timeoutSeconds(for: ["api", "run"]) == 1_200)
        #expect(Backend.timeoutSeconds(for: ["api", "qualify"]) == 1_800)
    }

    @Test func embeddedInstallerSelfTestCoversOfflineSafetyContract() throws {
        try AppSelfTest.run()
    }

    @Test func onboardingUnlocksOnlyFromDurableBackendState() {
        var snapshot = GuardianSnapshot()
        #expect(!OnboardingGate.dryRunCompleted(snapshot))
        #expect(!OnboardingGate.automationEnabled(snapshot))

        snapshot.firstDryRun = true
        snapshot.automation = "on"
        #expect(OnboardingGate.dryRunCompleted(snapshot))
        #expect(OnboardingGate.automationEnabled(snapshot))
    }

    @Test func onboardingRequiresExplicitFolderConfirmation() {
        #expect(OnboardingGate.totalSteps == 3)
        #expect(!OnboardingGate.canCommitFolders(folderSelected: false, busy: false))
        #expect(!OnboardingGate.canCommitFolders(folderSelected: true, busy: true))
        #expect(OnboardingGate.canCommitFolders(folderSelected: true, busy: false))
    }

    @Test func onboardingRejectsIncompleteAddressBeforeNetworkProbe() {
        for invalid in ["", "andrzej", "@o2.pl", "andrzej@", "andrzej@o2", "andrzej@.pl", "andrzej@o2."] {
            #expect(!OnboardingGate.emailLooksComplete(invalid))
            #expect(!OnboardingGate.canProbe(email: invalid, password: "test", busy: false))
        }
        #expect(OnboardingGate.canProbe(email: " andrzej@o2.pl ", password: "test", busy: false))
        #expect(!OnboardingGate.canProbe(email: "andrzej@o2.pl", password: "", busy: false))
        #expect(!OnboardingGate.canProbe(email: "andrzej@o2.pl", password: "test", busy: true))
    }

    @Test func initialPresentationKeepsWizardUntilDryRunIsDurable() {
        var snapshot = GuardianSnapshot()
        #expect(InitialPresentationGate.requiresOnboarding(snapshot))

        snapshot.configured = true
        #expect(InitialPresentationGate.requiresOnboarding(snapshot))

        snapshot.firstDryRun = true
        snapshot.automation = "off"
        #expect(!InitialPresentationGate.requiresOnboarding(snapshot))
    }

    @Test func onboardingResumesAtDryRunWithoutAskingForPasswordAgain() {
        var snapshot = GuardianSnapshot()
        #expect(!OnboardingGate.shouldResumeDryRun(snapshot, reconfigure: false))

        snapshot.configured = true
        snapshot.firstDryRun = false
        #expect(OnboardingGate.shouldResumeDryRun(snapshot, reconfigure: false))
        #expect(!OnboardingGate.shouldResumeDryRun(snapshot, reconfigure: true))

        snapshot.firstDryRun = true
        #expect(!OnboardingGate.shouldResumeDryRun(snapshot, reconfigure: false))
    }

    @MainActor
    @Test func reconfigurationImmediatelyRevokesTheOldDryRunInTheGUI() {
        let model = GuardianModel()
        model.snapshot.configured = true
        model.snapshot.firstDryRun = true
        model.snapshot.automation = "on"
        model.snapshot.mode = "active"
        model.snapshot.purgeEnabled = true

        model.markConfigurationCommitted()

        #expect(model.snapshot.configured)
        #expect(!model.snapshot.firstDryRun)
        #expect(model.snapshot.automation == "off")
        #expect(model.snapshot.mode == "protect")
        #expect(!model.snapshot.purgeEnabled)
        #expect(model.onboardingRequired)
    }

    @MainActor
    @Test func initialBackendFailureShowsCriticalDashboardNotAccountWizard() {
        let model = GuardianModel()
        model.applyInitialRefreshFailureForTesting(APIErrorPayload(
            code: "CONFIG_INVALID",
            severity: "critical",
            message: "Konfiguracja jest nieczytelna.",
            recovery: "Run Repair."
        ))

        #expect(model.initialRefreshCompleted)
        #expect(!model.onboardingRequired)
        #expect(model.snapshot.health == "critical")
        #expect(model.snapshot.healthLabel == "Not working")
        #expect(model.snapshot.recommendation == "Run Repair.")
    }

    @MainActor
    @Test func overlappingSnapshotRefreshesAreCoalescedWithoutBusyError() async {
        let model = GuardianModel()
        let first = Task { @MainActor in await model.refresh() }
        await Task.yield()
        await model.refresh()
        await first.value

        #expect(model.initialRefreshCompleted)
        #expect(model.snapshot.configured)
        #expect(model.failure == nil)
        #expect(!model.busy)
    }

    @Test func processControllerRejectsConcurrentOperations() {
        let controller = ProcessController()
        let first = OperationToken()
        let second = OperationToken()
        #expect(controller.begin(first))
        #expect(!controller.begin(second))
        controller.end(first)
        #expect(controller.begin(second))
        controller.end(second)
    }

    @Test func processControllerRecordsCancellation() {
        let controller = ProcessController()
        let operation = OperationToken()
        #expect(controller.begin(operation))
        controller.cancel()
        #expect(controller.cancelled())
        controller.end(operation)
    }

    @Test func dashboardCoversEveryPublishedHealthState() {
        let symbols = [
            "healthy": "checkmark.shield.fill",
            "attention": "exclamationmark.triangle.fill",
            "critical": "exclamationmark.octagon.fill",
            "manual": "pause.circle.fill",
            "unconfigured": "shield",
        ]
        for (health, symbol) in symbols {
            #expect(statusSymbol(health) == symbol)
        }

        var snapshot = GuardianSnapshot()
        snapshot.healthLabel = "Needs attention"
        snapshot.recommendation = "Run Repair."
        #expect(statusAccessibilityLabel(snapshot) == "Protection status: Needs attention. Run Repair.")
    }

    @Test func menuContainsOnlySafeQuickActions() {
        #expect(GuardianQuickAction.allCases.map(\.rawValue) == [
            "openDashboard", "runNow", "repair", "toggleAutomation",
        ])
        #expect(!GuardianQuickAction.allCases.map(\.rawValue).contains("purge"))
        #expect(!GuardianQuickAction.allCases.map(\.rawValue).contains("restore"))
    }

    @Test func dashboardContainsAllOperationalCounters() {
        var snapshot = GuardianSnapshot()
        snapshot.summary.waitingQuarantine = 11
        snapshot.summary.waitingReview = 7
        snapshot.summary.pendingMoves = 3

        #expect(DashboardCounter.allCases.map(\.rawValue) == [
            "quarantine", "review", "pendingMoves",
        ])
        #expect(DashboardCounter.quarantine.value(in: snapshot) == 11)
        #expect(DashboardCounter.review.value(in: snapshot) == 7)
        #expect(DashboardCounter.pendingMoves.value(in: snapshot) == 3)
    }

    @Test func safetyModesUsePlainLanguage() {
        #expect(safetyModeLabel("protect") == "Observation only")
        #expect(safetyModeLabel("active") == "Moves enabled")
        #expect(safetyModeLabel("unexpected") == "Unknown — run Repair")
    }

    @Test func archiveRestoreRequiresPreviewOfTheSameSelection() {
        #expect(!ArchiveRestoreGate.canRestore(selectedID: 7, previewedID: nil, busy: false))
        #expect(!ArchiveRestoreGate.canRestore(selectedID: 7, previewedID: 8, busy: false))
        #expect(!ArchiveRestoreGate.canRestore(selectedID: 7, previewedID: 7, busy: true))
        #expect(ArchiveRestoreGate.canRestore(selectedID: 7, previewedID: 7, busy: false))
    }

    @Test func archiveUsesFriendlyLabelsInsteadOfBackendCodes() {
        #expect(archiveVerdictLabel("ham") == "legitimate")
        #expect(archiveVerdictLabel("uncertain") == "uncertain")
        #expect(archiveStatusLabel("quarantined") == "quarantine")
        #expect(archiveStatusLabel("pending_restore") == "safe reconciliation")
        #expect(archiveStatusLabel("unexpected") == "technical status")
    }

    @Test func localMockExercisesTheRealProcessAndJSONBridge() async throws {
        let snapshot: GuardianSnapshot = try await Backend.call(["snapshot"])
        #expect(snapshot.configured)
        #expect(snapshot.health == "healthy")
        #expect(snapshot.summary.waitingQuarantine == 18)

        let page: ArchivePage = try await Backend.call(["archive", "list", "1"])
        #expect(page.items.count == 3)
        #expect(page.hasNext)

        let preview: ArchivePreview = try await Backend.call(["archive", "preview", "104"])
        #expect(preview.subject == "Sample sanitized subject")
    }
}
