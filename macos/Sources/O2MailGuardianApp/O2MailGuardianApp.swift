import AppKit
import Darwin
import Foundation
import SwiftUI

struct APIErrorPayload: Decodable, Error {
    let code: String
    let severity: String
    let message: String
    let recovery: String?
}

struct APIEnvelope<Value: Decodable>: Decodable {
    let protocolVersion: Int
    let ok: Bool
    let data: Value?
    let error: APIErrorPayload?

    enum CodingKeys: String, CodingKey {
        case protocolVersion = "protocol"
        case ok, data, error
    }
}

struct EmptyPayload: Codable {}

struct RunSummary: Codable {
    var runs = 0
    var dryRuns = 0
    var scanned = 0
    var kept = 0
    var rescued = 0
    var quarantined = 0
    var review = 0
    var learnedSpam = 0
    var learnedHam = 0
    var purged = 0
    var errors = 0
    var waitingQuarantine = 0
    var waitingReview = 0
    var pendingMoves = 0
    var purgeEligible = 0

    init() {}

    init(from decoder: Decoder) throws {
        let values = try decoder.container(keyedBy: CodingKeys.self)
        runs = try values.decodeIfPresent(Int.self, forKey: .runs) ?? 0
        dryRuns = try values.decodeIfPresent(Int.self, forKey: .dryRuns) ?? 0
        scanned = try values.decodeIfPresent(Int.self, forKey: .scanned) ?? 0
        kept = try values.decodeIfPresent(Int.self, forKey: .kept) ?? 0
        rescued = try values.decodeIfPresent(Int.self, forKey: .rescued) ?? 0
        quarantined = try values.decodeIfPresent(Int.self, forKey: .quarantined) ?? 0
        review = try values.decodeIfPresent(Int.self, forKey: .review) ?? 0
        learnedSpam = try values.decodeIfPresent(Int.self, forKey: .learnedSpam) ?? 0
        learnedHam = try values.decodeIfPresent(Int.self, forKey: .learnedHam) ?? 0
        purged = try values.decodeIfPresent(Int.self, forKey: .purged) ?? 0
        errors = try values.decodeIfPresent(Int.self, forKey: .errors) ?? 0
        waitingQuarantine = try values.decodeIfPresent(Int.self, forKey: .waitingQuarantine) ?? 0
        waitingReview = try values.decodeIfPresent(Int.self, forKey: .waitingReview) ?? 0
        pendingMoves = try values.decodeIfPresent(Int.self, forKey: .pendingMoves) ?? 0
        purgeEligible = try values.decodeIfPresent(Int.self, forKey: .purgeEligible) ?? 0
    }
}

struct MailboxConnection: Codable {
    let email, provider, host: String
    let port: Int
    let username: String
}
struct MailboxFolders: Codable {
    var quarantine = "AI-Quarantine"
    var review = "AI-Do-sprawdzenia"
    var trainSpam = "AI-Naucz-spam"
    var trainHam = "AI-Naucz-wazne"
    static let fresh = MailboxFolders(quarantine: "Guardian-Quarantine", review: "Guardian-Review", trainSpam: "Guardian-Train-Spam", trainHam: "Guardian-Train-Ham")
}
struct SetupConnectionRequest: Encodable {
    let email, password, provider, host: String
    let port: Int
    let username: String
    var authMethod = "password"
    var spamFolder: String? = nil
    var acceptExistingTraining: Bool? = nil
    enum CodingKeys: String, CodingKey {
        case email, password, provider, host, port, username
        case authMethod = "auth_method", spamFolder = "spam_folder", acceptExistingTraining = "accept_existing_training"
    }
}
struct GuardianSnapshot: Codable {
    var connection: MailboxConnection?
    var mailboxFolders: MailboxFolders?
    // Old protocol-1 backends used the historical folder names.
    var folders: MailboxFolders { mailboxFolders ?? MailboxFolders() }
    var configured = false
    var health = "unconfigured"
    var healthLabel = "Setup required"
    var recommendation = "Complete first-time setup."
    var automation = "off"
    var mode = "protect"
    var purgeEnabled = false
    var lastAttempt: String?
    var lastSuccess: String?
    var stage: String?
    var errorCode: String?
    var summary = RunSummary()
    var trainedSpam = 0
    var trainedHam = 0
    var requiredSpam = 200
    var requiredHam = 200
    var firstDryRun = false
    var appAutostart = false
    var version = ""
    var protection: ProtectionProgress?
}

struct SetupProbe: Codable {
    let detectedSpam: String
    let folders: [String]
    let safeMove: Bool
    var mailboxFolders: MailboxFolders?
}

struct SetupResult: Codable {
    let configured: Bool
    let spamFolder: String
    let firstDryRunRequired: Bool
}

struct CompletionResult: Codable {
    let completed: Bool
    var summary: ScanOutcome?
}

struct ServiceResult: Codable {
    let automation: String
}

struct AppAutostartResult: Codable {
    let appAutostart: Bool
}

struct DiagnosticsResult: Codable {
    let path: String
}

struct ArchiveItem: Codable, Identifiable, Hashable {
    let id: Int64
    let date: String
    let verdict: String
    let status: String
}

struct ArchivePage: Codable {
    let page: Int
    let items: [ArchiveItem]
    let hasNext: Bool
}

struct ArchivePreview: Codable {
    let from: String
    let subject: String
    let date: String
}

struct RestoreResult: Codable {
    let restored: Bool
    let alreadyPresent: Bool?
}

enum ProtocolContract {
    static func decodeSnapshot(_ json: String) throws -> APIEnvelope<GuardianSnapshot> {
        try decoder().decode(APIEnvelope<GuardianSnapshot>.self, from: Data(json.utf8))
    }

    static func decodeEmpty(_ json: String) throws -> APIEnvelope<EmptyPayload> {
        try decoder().decode(APIEnvelope<EmptyPayload>.self, from: Data(json.utf8))
    }

    private static func decoder() -> JSONDecoder {
        let value = JSONDecoder()
        value.keyDecodingStrategy = .convertFromSnakeCase
        return value
    }
}

enum OnboardingGate {
    static let totalSteps = 3

    static func emailLooksComplete(_ email: String) -> Bool {
        let parts = email.trimmingCharacters(in: .whitespacesAndNewlines).split(separator: "@", omittingEmptySubsequences: false)
        return parts.count == 2 && !parts[0].isEmpty && parts[1].contains(".") && !parts[1].hasPrefix(".") && !parts[1].hasSuffix(".")
    }

    static func canProbe(email: String, password: String, busy: Bool) -> Bool {
        emailLooksComplete(email) && !password.isEmpty && !busy
    }

    static func canCommitFolders(folderSelected: Bool, busy: Bool) -> Bool {
        folderSelected && !busy
    }

    static func dryRunCompleted(_ snapshot: GuardianSnapshot) -> Bool {
        snapshot.firstDryRun
    }

    static func automationEnabled(_ snapshot: GuardianSnapshot) -> Bool {
        snapshot.automation == "on"
    }

    static func shouldResumeDryRun(_ snapshot: GuardianSnapshot, reconfigure: Bool) -> Bool {
        !reconfigure && snapshot.configured && !snapshot.firstDryRun
    }
}

enum InitialPresentationGate {
    static func requiresOnboarding(_ snapshot: GuardianSnapshot) -> Bool {
        !snapshot.configured || !snapshot.firstDryRun
    }
}

enum FailureQuickAction: String {
    case none
    case accountSettings
    case repair
}

func failureQuickAction(for code: String?) -> FailureQuickAction {
    switch code {
    case "IMAP_AUTH": return .accountSettings
    case "RSPAMD_UNAVAILABLE", "SERVICE_STALE": return .repair
    default: return .none
    }
}

enum Backend {
    static func encodeInput(_ input: Encodable) throws -> Data {
        let encoder = JSONEncoder()
        encoder.keyEncodingStrategy = .convertToSnakeCase
        return try encoder.encode(AnyEncodable(input))
    }

    static var executable: String {
        if let override = ProcessInfo.processInfo.environment["GUARDIAN_BIN"], !override.isEmpty {
            return override
        }
        return FileManager.default.homeDirectoryForCurrentUser
            .appendingPathComponent(".local/bin/o2-mail-guardian/guardian").path
    }

    static func call<Value: Decodable>(
        _ arguments: [String],
        input: Encodable? = nil,
        as type: Value.Type = Value.self
    ) async throws -> Value {
        let inputData: Data?
        if let input {
            inputData = try encodeInput(input)
        } else {
            inputData = nil
        }
        let output = try await run(arguments: ["api"] + arguments, input: inputData)
        let decoder = JSONDecoder()
        decoder.keyDecodingStrategy = .convertFromSnakeCase
        let envelope = try decoder.decode(APIEnvelope<Value>.self, from: output)
        guard envelope.protocolVersion == 1 else {
            throw APIErrorPayload(code: "API_VERSION", severity: "critical", message: "Unsupported local API version.", recovery: "Run Install.command again.")
        }
        if !envelope.ok {
            throw envelope.error ?? APIErrorPayload(code: "UNKNOWN", severity: "error", message: "Unknown Guardian error.", recovery: "Run Repair.")
        }
        guard let value = envelope.data else {
            throw APIErrorPayload(code: "EMPTY_RESPONSE", severity: "error", message: "Guardian returned no result.", recovery: "Run Repair.")
        }
        return value
    }

    private static func run(arguments: [String], input: Data?) async throws -> Data {
        let executablePath = executable
        return try await Task.detached(priority: .userInitiated) {
            guard FileManager.default.isExecutableFile(atPath: executablePath) else {
                throw APIErrorPayload(code: "NOT_INSTALLED", severity: "critical", message: "Guardian engine is not installed.", recovery: "Run Install.command.")
            }
            let process = Process()
            process.executableURL = URL(fileURLWithPath: executablePath)
            process.arguments = arguments
            let temporary = FileManager.default.temporaryDirectory.appendingPathComponent("o2-mail-guardian-api-\(UUID().uuidString)", isDirectory: true)
            try FileManager.default.createDirectory(at: temporary, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
            defer { try? FileManager.default.removeItem(at: temporary) }
            let outputURL = temporary.appendingPathComponent("response.json")
            let errorURL = temporary.appendingPathComponent("stderr.txt")
            guard FileManager.default.createFile(atPath: outputURL.path, contents: nil, attributes: [.posixPermissions: 0o600]),
                  FileManager.default.createFile(atPath: errorURL.path, contents: nil, attributes: [.posixPermissions: 0o600]) else {
                throw APIErrorPayload(code: "LOCAL_IO", severity: "error", message: "Could not prepare a private response buffer.", recovery: "Run Repair.")
            }
            let stdout = try FileHandle(forWritingTo: outputURL)
            let stderr = try FileHandle(forWritingTo: errorURL)
            defer { try? stdout.close(); try? stderr.close() }
            process.standardOutput = stdout
            process.standardError = stderr

            let stdinPipe: Pipe?
            if input != nil {
                let pipe = Pipe()
                process.standardInput = pipe
                stdinPipe = pipe
            } else {
                process.standardInput = FileHandle.nullDevice
                stdinPipe = nil
            }
            guard ProcessController.shared.begin(process) else {
                throw APIErrorPayload(code: "GUI_BUSY", severity: "attention", message: "Guardian is already performing another operation.", recovery: "Wait for completion or use Cancel.")
            }
            defer {
                if process.isRunning { process.terminate() }
                ProcessController.shared.end(process)
            }
            try process.run()
            if let input, let stdinPipe {
                stdinPipe.fileHandleForWriting.write(input)
                try stdinPipe.fileHandleForWriting.close()
            }
            let timeout = timeoutSeconds(for: arguments)
            let deadline = Date().addingTimeInterval(timeout)
            while process.isRunning {
                if Task.isCancelled || ProcessController.shared.cancelled() {
                    process.terminate()
                    throw APIErrorPayload(code: "CANCELLED", severity: "info", message: "Operation cancelled.", recovery: "Only previously completed safe steps may have changed data.")
                }
                if Date() >= deadline {
                    process.terminate()
                    throw APIErrorPayload(code: "TIMEOUT", severity: "attention", message: "Operation exceeded its time limit and was stopped.", recovery: "Run Repair; Guardian will reconcile interrupted moves.")
                }
                try await Task.sleep(for: .milliseconds(100))
            }
            if ProcessController.shared.cancelled() {
                throw APIErrorPayload(code: "CANCELLED", severity: "info", message: "Operation cancelled.", recovery: "Only previously completed safe steps may have changed data.")
            }
            try stdout.synchronize()
            let attributes = try FileManager.default.attributesOfItem(atPath: outputURL.path)
            let outputSize = (attributes[.size] as? NSNumber)?.intValue ?? 0
            guard outputSize <= 2 * 1024 * 1024 else {
                throw APIErrorPayload(code: "RESPONSE_TOO_LARGE", severity: "error", message: "Guardian response is too large.", recovery: "Run Repair.")
            }
            guard process.terminationStatus == 0 else {
                throw APIErrorPayload(code: "BACKEND_FAILED", severity: "error", message: "Guardian engine exited with an error.", recovery: "Run Repair.")
            }
            return try Data(contentsOf: outputURL, options: .mappedIfSafe)
        }.value
    }

    static func cancelCurrentOperation() {
        ProcessController.shared.cancel()
    }

    static func timeoutSeconds(for arguments: [String]) -> TimeInterval {
        if arguments.contains("qualify") { return 30 * 60.0 }
        return arguments.contains("run") ? 20 * 60.0 : 5 * 60.0
    }
}

final class ProcessController: @unchecked Sendable {
    static let shared = ProcessController()
    private let lock = NSLock()
    private var operation: AnyObject?
    private var runningProcess: Process?
    private var wasCancelled = false

    func begin(_ operation: AnyObject) -> Bool {
        lock.lock(); defer { lock.unlock() }
        guard self.operation == nil else { return false }
        self.operation = operation
        runningProcess = operation as? Process
        wasCancelled = false
        return true
    }

    func end(_ operation: AnyObject) {
        lock.lock(); defer { lock.unlock() }
        if self.operation === operation {
            self.operation = nil
            runningProcess = nil
        }
    }

    func cancel() {
        lock.lock(); defer { lock.unlock() }
        wasCancelled = true
        if runningProcess?.isRunning == true { runningProcess?.terminate() }
    }

    func cancelled() -> Bool {
        lock.lock(); defer { lock.unlock() }
        return wasCancelled
    }
}

private struct AnyEncodable: Encodable {
    private let encodeValue: (Encoder) throws -> Void
    init(_ value: Encodable) { encodeValue = value.encode }
    func encode(to encoder: Encoder) throws { try encodeValue(encoder) }
}

@MainActor
final class GuardianModel: ObservableObject {
    @Published var snapshot = GuardianSnapshot()
    @Published var busy = false
    @Published var notice: String?
    @Published var failure: APIErrorPayload?
    @Published var archivePage = ArchivePage(page: 1, items: [], hasNext: false)
    @Published var reconfigure = false
    @Published var section: GuardianSection = .overview
    @Published var operationTitle = "Refreshing protection status…"
    @Published var snapshotIsStale = false
    @Published var lastScan: ScanOutcome?
    @Published var archiveLoaded = false
    @Published var archiveFilter = "all"
    @Published var archiveDateRange: [String] = []
    @Published private(set) var initialRefreshCompleted = false
    @Published private(set) var onboardingRequired = true
    private var refreshing = false
    private var noticeTask: Task<Void, Never>?

    let backgroundLaunch = ProcessInfo.processInfo.arguments.contains("--background")
    let previewMode = ProcessInfo.processInfo.environment["GUARDIAN_PREVIEW"] == "1"

    func refresh() async {
        guard !refreshing else { return }
        refreshing = true
        let ownsBusyState = !busy
        if ownsBusyState { operationTitle = "Refreshing protection status…"; busy = true }
        defer {
            refreshing = false
            if ownsBusyState { busy = false }
            initialRefreshCompleted = true
        }
        do {
            let refreshed = try await Backend.call(["snapshot"], as: GuardianSnapshot.self)
            if !initialRefreshCompleted {
                onboardingRequired = InitialPresentationGate.requiresOnboarding(refreshed)
            }
            snapshot = refreshed
            snapshotIsStale = false
            failure = nil
        } catch let error as APIErrorPayload {
            recordRefreshFailure(error)
        } catch {
            recordRefreshFailure(APIErrorPayload(code: "GUI", severity: "error", message: error.localizedDescription, recovery: "Run Repair."))
        }
    }

    private func recordRefreshFailure(_ error: APIErrorPayload) {
        failure = error
        snapshotIsStale = true
        guard !initialRefreshCompleted else { return }
        // A missing config is returned as a valid unconfigured snapshot. Any
        // error here means the state could not be trusted and must not route
        // the user into a credential-changing onboarding flow.
        snapshot.health = "critical"
        snapshot.healthLabel = "Not working"
        snapshot.recommendation = error.recovery ?? "Run Repair."
        onboardingRequired = false
    }

    func applyInitialRefreshFailureForTesting(_ error: APIErrorPayload) {
        recordRefreshFailure(error)
        initialRefreshCompleted = true
    }

    func completeOnboarding() {
        onboardingRequired = false
        reconfigure = false
    }

    func markConfigurationCommitted() {
        // The backend atomically invalidates the previous dry-run and stops the
        // service. Reflect this immediately so cancellation/failure cannot
        // unlock the wizard using a stale snapshot.
        snapshot.configured = true
        snapshot.firstDryRun = false
        snapshot.automation = "off"
        snapshot.mode = "protect"
        snapshot.purgeEnabled = false
        snapshot.protection = nil
        lastScan = nil
        onboardingRequired = true
    }

    @discardableResult
    func perform(_ title: String = "Updating settings…", work: @escaping () async throws -> String?) async -> Bool {
        guard !busy else { return false }
        noticeTask?.cancel()
        notice = nil
        failure = nil
        operationTitle = title
        busy = true
        defer { busy = false }
        do {
            showNotice(try await work())
            failure = nil
            await refresh()
            return failure == nil
        } catch let error as APIErrorPayload {
            if error.code == "CANCELLED" {
                snapshotIsStale = true
                showNotice("Operation cancelled. Previously completed steps may be saved. Refresh protection status.")
            } else {
                failure = error
            }
        } catch {
            failure = APIErrorPayload(code: "GUI", severity: "error", message: error.localizedDescription, recovery: "Run Repair.")
        }
        return false
    }

    func cancel() {
        Backend.cancelCurrentOperation()
    }

    private func showNotice(_ message: String?) {
        noticeTask?.cancel()
        notice = message
        guard let message else { return }
        noticeTask = Task { @MainActor [weak self] in
            try? await Task.sleep(for: .seconds(7))
            guard !Task.isCancelled, self?.notice == message else { return }
            self?.notice = nil
        }
    }

    func runNow(dryRun: Bool = false) async {
        guard !busy else { return }
        lastScan = nil
        await perform(dryRun ? "Analyzing mail without changes…" : "Checking mail and processing corrections…") {
            let args = dryRun ? ["run", "dry-run"] : ["run"]
            let result: CompletionResult = try await Backend.call(args)
            self.lastScan = result.summary
            if let summary = result.summary, summary.errors > 0 { return "Check completed with issues. Review the results." }
            return result.completed ? (dryRun ? "Dry-run completed successfully." : "Mailbox checked.") : nil
        }
    }

    func repair() async {
        await perform("Checking connection and repairing local protection…") {
            let result: CompletionResult = try await Backend.call(["repair"])
            return result.completed ? "Repair completed successfully." : nil
        }
    }

    func qualifyFilter() async {
        await perform("Evaluating filter quality on held-out examples…") {
            let result: CompletionResult = try await Backend.call(["qualify"])
            return result.completed ? "Filter evaluation complete. Cleanup requirements reevaluated." : nil
        }
    }

    func setAutomation(_ enabled: Bool) async {
        await perform {
            let _: ServiceResult = try await Backend.call(["service", enabled ? "enable" : "disable"])
            return enabled ? "Automatic checks are active." : "Manual mode enabled."
        }
    }

    func setAppAutostart(_ enabled: Bool) async {
        await perform {
            let _: AppAutostartResult = try await Backend.call(["app-autostart", enabled ? "enable" : "disable"])
            return enabled ? "Dashboard will start at login." : "Dashboard login start disabled; mail protection runs independently."
        }
    }

    func deepDoctor() async {
        await perform("Checking account, folders and local engine…") {
            let result: CompletionResult = try await Backend.call(["doctor", "deep"])
            return result.completed ? "Full check found no problems." : nil
        }
    }

    func exportDiagnostics() async {
        await perform("Preparing a private diagnostic report…") {
            let result: DiagnosticsResult = try await Backend.call(["diagnostics"])
            return "Safe report saved: \(result.path)"
        }
    }

    func loadArchive(page: Int = 1) async {
        guard !busy else { return }
        operationTitle = "Loading backup list…"
        busy = true
        archiveLoaded = false
        // Keep the attempted page for Retry; old rows and pagination are no
        // longer valid if this request fails or changes the filter.
        archivePage = ArchivePage(page: page, items: [], hasNext: false)
        failure = nil
        defer { busy = false }
        do {
            var arguments = ["archive", "list", String(page)]
            if archiveFilter != "all" || !archiveDateRange.isEmpty { arguments.append(archiveFilter) }
            arguments.append(contentsOf: archiveDateRange)
            archivePage = try await Backend.call(arguments)
            archiveLoaded = true
            failure = nil
        } catch let error as APIErrorPayload {
            failure = error
        } catch {
            failure = APIErrorPayload(code: "ARCHIVE", severity: "error", message: error.localizedDescription, recovery: "Run Repair.")
        }
    }

    func previewArchive(id: Int64) async -> ArchivePreview? {
        guard !busy else { return nil }
        operationTitle = "Loading safe preview…"
        failure = nil
        busy = true
        defer { busy = false }
        do {
            return try await Backend.call(["archive", "preview", String(id)])
        } catch let error as APIErrorPayload {
            failure = error
        } catch {
            failure = APIErrorPayload(code: "ARCHIVE", severity: "error", message: error.localizedDescription, recovery: "Run Repair.")
        }
        return nil
    }

    func restoreArchive(id: Int64) async {
        let completed = await perform("Restoring message to the review folder…") {
            let result: RestoreResult = try await Backend.call(["archive", "restore", String(id)])
            if result.alreadyPresent == true { return "Message still exists; no duplicate created." }
            return result.restored ? "Message restored to the configured review folder." : nil
        }
        if completed { await loadArchive(page: archivePage.page) }
    }
}

struct AppSelfTestFailure: Error, CustomStringConvertible {
    let check: String
    var description: String { "Application self-check failed: \(check)" }
}

enum AppSelfTest {
    static func run() throws {
        let snapshotJSON = #"{"protocol":1,"ok":true,"data":{"configured":true,"health":"healthy","health_label":"Everything works","recommendation":"OK","automation":"on","mode":"protect","purge_enabled":false,"summary":{},"trained_spam":2,"trained_ham":3,"required_spam":200,"required_ham":200,"first_dry_run":true,"app_autostart":true,"version":"0.3.0"}}"#
        let snapshot = try ProtocolContract.decodeSnapshot(snapshotJSON)
        guard snapshot.ok, snapshot.data?.healthLabel == "Everything works", snapshot.data?.trainedHam == 3 else {
            throw AppSelfTestFailure(check: "local JSON protocol decoding")
        }

        let errorJSON = #"{"protocol":1,"ok":false,"error":{"code":"IMAP_AUTH","severity":"attention","message":"Error","recovery":"Check your password"}}"#
        guard try ProtocolContract.decodeEmpty(errorJSON).error?.code == "IMAP_AUTH" else {
            throw AppSelfTestFailure(check: "structured local API errors")
        }
        guard OnboardingGate.totalSteps == 3,
              OnboardingGate.canProbe(email: "test@o2.pl", password: "test", busy: false),
              !OnboardingGate.canProbe(email: "test", password: "test", busy: false),
              OnboardingGate.canCommitFolders(folderSelected: true, busy: false),
              !OnboardingGate.canCommitFolders(folderSelected: false, busy: false) else {
            throw AppSelfTestFailure(check: "first-time setup gates")
        }
        let quickActions = GuardianQuickAction.allCases.map(\.rawValue)
        guard !quickActions.contains("purge"), !quickActions.contains("restore") else {
            throw AppSelfTestFailure(check: "safe menu-bar actions")
        }
    }
}

@main
struct O2MailGuardianApp: App {
    @NSApplicationDelegateAdaptor(AppDelegate.self) private var appDelegate
    @StateObject private var model = GuardianModel()

    init() {
        let arguments = ProcessInfo.processInfo.arguments
        if arguments.contains("--self-test") {
            do {
                try AppSelfTest.run()
                print("Application self-check: OK")
                exit(EXIT_SUCCESS)
            } catch {
                print(String(describing: error))
                exit(EXIT_FAILURE)
            }
        }
    }

    var body: some Scene {
        Window("Mail Guardian", id: "dashboard") {
            RootView(model: model)
                // Isolated preview helper can exercise dark mode without
                // changing the user's macOS appearance or saved preferences.
                .preferredColorScheme(ProcessInfo.processInfo.environment["GUARDIAN_PREVIEW_THEME"] == "dark" ? .dark : nil)
                .frame(minWidth: 860, minHeight: 620)
                .task {
                    await model.refresh()
                    while !Task.isCancelled {
                        try? await Task.sleep(for: .seconds(60))
                        if !Task.isCancelled && !model.busy { await model.refresh() }
                    }
                }
        }
        .defaultSize(width: 1080, height: 780)
        .commands {
            CommandMenu("Go") {
                Group {
                    Button("Overview") { model.section = .overview }.keyboardShortcut("1", modifiers: .command)
                    Button("Training and corrections") { model.section = .learning }.keyboardShortcut("2", modifiers: .command)
                    Button("Recovery") { model.section = .archive }.keyboardShortcut("3", modifiers: .command)
                    Button("Settings") { model.section = .settings }.keyboardShortcut("4", modifiers: .command)
                    Button("Help") { model.section = .help }.keyboardShortcut("5", modifiers: .command)
                }.disabled(!model.initialRefreshCompleted || model.onboardingRequired || model.reconfigure)
            }
        }

        MenuBarExtra {
            GuardianMenu(model: model)
        } label: {
            Label("Mail Guardian — \(ProtectionPresentation(model.snapshot, stale: model.snapshotIsStale).title)", systemImage: ProtectionPresentation(model.snapshot, stale: model.snapshotIsStale).symbol)
        }
    }
}

final class AppDelegate: NSObject, NSApplicationDelegate {
    func applicationShouldHandleReopen(_ sender: NSApplication, hasVisibleWindows flag: Bool) -> Bool {
        sender.setActivationPolicy(.regular)
        sender.windows.forEach { $0.makeKeyAndOrderFront(nil) }
        sender.activate(ignoringOtherApps: true)
        return true
    }
}

func statusSymbol(_ health: String) -> String {
    switch health {
    case "healthy": return "checkmark.shield.fill"
    case "critical": return "exclamationmark.octagon.fill"
    case "attention": return "exclamationmark.triangle.fill"
    case "manual": return "pause.circle.fill"
    default: return "shield"
    }
}

func statusAccessibilityLabel(_ snapshot: GuardianSnapshot) -> String {
    "Protection status: \(snapshot.healthLabel). \(snapshot.recommendation)"
}

enum GuardianQuickAction: String, CaseIterable, Identifiable {
    case openDashboard
    case runNow
    case repair
    case toggleAutomation

    var id: String { rawValue }
}

enum DashboardCounter: String, CaseIterable, Identifiable {
    case quarantine
    case review
    case pendingMoves

    var id: String { rawValue }

    var label: String {
        switch self {
        case .quarantine: return "Quarantined"
        case .review: return "Review"
        case .pendingMoves: return "Unresolved moves"
        }
    }

    func value(in snapshot: GuardianSnapshot) -> Int {
        switch self {
        case .quarantine: return snapshot.summary.waitingQuarantine
        case .review: return snapshot.summary.waitingReview
        case .pendingMoves: return snapshot.summary.pendingMoves
        }
    }
}

func safetyModeLabel(_ mode: String) -> String {
    switch mode {
    case "active": return "Moves enabled"
    case "protect": return "Observation only"
    default: return "Unknown — run Repair"
    }
}

enum ArchiveRestoreGate {
    static func canRestore(selectedID: Int64?, previewedID: Int64?, busy: Bool) -> Bool {
        !busy && selectedID != nil && selectedID == previewedID
    }
}

func friendlyDate(_ value: String?) -> String {
    guard let value else { return "None yet" }
    let parser = ISO8601DateFormatter()
    parser.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
    let date = parser.date(from: value) ?? {
        parser.formatOptions = [.withInternetDateTime]
        return parser.date(from: value)
    }()
    guard let date else { return value }
    let formatter = DateFormatter()
    formatter.locale = Locale(identifier: "en")
    formatter.dateFormat = "d MMM yyyy, HH:mm"
    return formatter.string(from: date)
}

func archiveVerdictLabel(_ verdict: String) -> String {
    switch verdict {
    case "spam": return "spam"
    case "ham": return "legitimate"
    case "uncertain": return "uncertain"
    case "error": return "check error"
    default: return "unrecognized"
    }
}

func archiveStatusLabel(_ status: String) -> String {
    switch status {
    case "quarantined": return "quarantine"
    case "review": return "review"
    case "rescued": return "uratowana"
    case "restored": return "restored"
    case "purged": return "removed after retention"
    case "pending_move", "pending_learn", "pending_restore", "move_ambiguous": return "safe reconciliation"
    case "superseded": return "superseded by a newer correction"
    default: return "technical status"
    }
}

struct RootView: View {
    @ObservedObject var model: GuardianModel
    @Environment(\.openWindow) private var openWindow

    var body: some View {
        Group {
            if !model.initialRefreshCompleted {
                VStack(spacing: 14) {
                    ProgressView().controlSize(.large)
                    Text("Checking protection status…").foregroundStyle(.secondary)
                }
                .frame(maxWidth: .infinity, maxHeight: .infinity)
                .accessibilityElement(children: .combine)
                .accessibilityLabel("Checking protection status")
            } else if model.reconfigure || model.onboardingRequired {
                OnboardingView(model: model)
            } else {
                MainTabs(model: model)
            }
        }
        .tint(GuardianStyle.accent)
        .accentColor(GuardianStyle.accent)
        .safeAreaInset(edge: .top, spacing: 0) {
            if model.previewMode {
                Label("Application preview · sample data · no mailbox connection", systemImage: "play.rectangle")
                    .font(.caption).foregroundStyle(GuardianStyle.accent)
                    .frame(maxWidth: .infinity).padding(8).background(GuardianStyle.accent.opacity(0.08))
            }
        }
        .safeAreaInset(edge: .bottom, spacing: 0) {
            OperationFeedback(model: model)
        }
        .onAppear {
            if model.backgroundLaunch {
                NSApp.setActivationPolicy(.accessory)
                DispatchQueue.main.async { NSApp.windows.forEach { $0.orderOut(nil) } }
            }
        }
    }
}

struct OnboardingView: View {
    @ObservedObject var model: GuardianModel
    @State private var step = 1
    @State private var email = ""
    @State private var provider = "custom"
    @State private var host = ""
    @State private var port = "993"
    @State private var username = ""
    private var connectionValid: Bool { provider == "o2" || (!host.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty && (1...65535).contains(Int(port) ?? 0)) }
    private var setupFolders: MailboxFolders { probe?.mailboxFolders ?? model.snapshot.mailboxFolders ?? .fresh }
    private var connectionRequest: SetupConnectionRequest {
        SetupConnectionRequest(email: email.trimmingCharacters(in: .whitespacesAndNewlines), password: password, provider: provider,
            host: provider == "o2" ? "poczta.o2.pl" : host.trimmingCharacters(in: .whitespacesAndNewlines), port: provider == "o2" ? 993 : (Int(port) ?? 0),
            username: username.isEmpty ? email.trimmingCharacters(in: .whitespacesAndNewlines) : username)
    }
    @State private var password = ""
    @State private var probe: SetupProbe?
    @State private var spamFolder = ""
    private var dryRunDone: Bool { setupCommitted && OnboardingGate.dryRunCompleted(model.snapshot) }
    @State private var setupCommitted = false
    @State private var showFolderChoice = false
    @State private var showAccountPreparation = true
    @FocusState private var accountField: AccountField?
    private enum AccountField { case email, password }

    init(model: GuardianModel) {
        self.model = model
        let resumeDryRun = OnboardingGate.shouldResumeDryRun(model.snapshot, reconfigure: model.reconfigure)
        _step = State(initialValue: resumeDryRun ? 3 : 1)
        _setupCommitted = State(initialValue: resumeDryRun)
        if let connection = model.snapshot.connection {
            _email = State(initialValue: connection.email)
            _provider = State(initialValue: connection.provider)
            _host = State(initialValue: connection.host)
            _port = State(initialValue: String(connection.port))
            _username = State(initialValue: connection.username)
        }
    }

    var body: some View {
        GuardianPage(eyebrow: "Start safely", title: model.reconfigure ? "Account settings" : "Connect your email", subtitle: "Three steps. First we check everything without changing messages.") {
            if model.reconfigure && !setupCommitted {
                Button("Cancel settings change", role: .cancel) { model.reconfigure = false }
            } else if setupCommitted {
                Label("Settings saved; automation stays paused until the wizard completes.", systemImage: "lock.shield")
                    .foregroundStyle(.secondary)
            }
            HStack(spacing: 14) {
                ForEach(1...3, id: \.self) { index in
                    HStack(spacing: 8) {
                        Image(systemName: index < step ? "checkmark.circle.fill" : "\(index).circle.fill")
                        Text(["Account", "Folders", "Safe dry-run"][index - 1]).font(.callout.weight(index == step ? .semibold : .regular))
                    }.foregroundStyle(index <= step ? GuardianStyle.accent : .secondary)
                    if index < 3 { Rectangle().fill(.quaternary).frame(height: 1) }
                }
            }.accessibilityElement(children: .ignore).accessibilityLabel("Step \(step) of 3: \(["Account", "Folders", "Safe dry-run"][step - 1])")
            GuardianCard {
                switch step {
                case 1:
                    VStack(alignment: .leading, spacing: 12) {
                        Text("Account and password").font(.title2.bold())
                        DisclosureGroup("Prepare your email account", isExpanded: $showAccountPreparation) {
                            VStack(alignment: .leading, spacing: 12) {
                                Label("1. Enable IMAP access in your email account settings.", systemImage: "envelope.badge.shield.half.filled")
                                Label("2. Follow your provider's account security instructions.", systemImage: "lock.shield")
                                Label("3. Create a separate Guardian app password where supported.", systemImage: "key")
                                if provider == "o2" {
                                    Link("o2 app-password instructions", destination: URL(string: "https://pomoc.o2.pl/wpkonto/hasla-do-aplikacji-zewnetrznej")!)
                                }
                                Text("Already have the account/app password? Enter it below. No need to repeat preparation.")
                                    .foregroundStyle(.secondary)
                            }.font(.callout).padding(.vertical, 10)
                                .frame(maxWidth: .infinity, alignment: .leading)
                        }
                        Picker("Connection profile", selection: $provider) {
                            Text("Custom IMAP").tag("custom")
                            Text("o2 preset").tag("o2")
                        }.disabled(model.snapshot.configured)
                        if provider == "custom" {
                            TextField("IMAP hostname, e.g. imap.example.com", text: $host).textFieldStyle(.roundedBorder).disabled(model.snapshot.configured)
                            TextField("Implicit TLS port", text: $port).textFieldStyle(.roundedBorder).disabled(model.snapshot.configured)
                        }
                        TextField("IMAP login (defaults to email)", text: $username).textFieldStyle(.roundedBorder).disabled(model.snapshot.configured)
                        if model.snapshot.configured { Text("This installation is bound to its mailbox. Use a separate instance to change servers or accounts.").font(.footnote).foregroundStyle(.secondary) }
                        Text("Email address").font(.callout.weight(.medium))
                        TextField("name@example.com", text: $email)
                            .textFieldStyle(.roundedBorder)
                            .focused($accountField, equals: .email)
                            .accessibilityLabel("Email address")
                            .disabled(model.busy)
                            .onSubmit { accountField = .password }
                            .textContentType(.username)
                            .autocorrectionDisabled()
                        if !email.isEmpty && accountField != .email && !OnboardingGate.emailLooksComplete(email) {
                            Text("Enter a full address, e.g. name@example.com.")
                                .font(.footnote)
                                .foregroundStyle(.orange)
                        }
                        Text("Account or app password").font(.callout.weight(.medium))
                        SecureField("Enter your account or app password", text: $password)
                            .textFieldStyle(.roundedBorder)
                            .focused($accountField, equals: .password)
                            .accessibilityLabel("IMAP account or app password")
                            .disabled(model.busy)
                        Text("Use an app password where supported. It is stored securely in macOS Keychain. OAuth-only accounts are not supported.").font(.footnote).foregroundStyle(.secondary)
                        Button("Connect and detect settings") { Task { await probeConnection() } }
                            .buttonStyle(.borderedProminent)
                            .keyboardShortcut(.defaultAction)
                            .disabled(!connectionValid || !OnboardingGate.canProbe(email: email, password: password, busy: model.busy))

                    }
                case 2:
                    VStack(alignment: .leading, spacing: 12) {
                        Label("Connection verified", systemImage: "checkmark.circle.fill").font(.title2.bold())
                        Text("The server confirmed encrypted access and safe message moves. Check the detected spam folder.")
                        GroupBox("Detected settings") {
                            VStack(alignment: .leading, spacing: 8) {
                                Text("Spam: \(spamFolder.isEmpty ? "choose below" : spamFolder)").bold()
                                Text("Guardian will prepare four additional protection folders.")
                                    .foregroundStyle(.secondary)
                                DisclosureGroup("Show Guardian folder names") {
                                    Text("Quarantine: \(setupFolders.quarantine)\nReview: \(setupFolders.review)\nTraining: \(setupFolders.trainSpam) and \(setupFolders.trainHam)")
                                        .padding(.top, 6)
                                }
                                DisclosureGroup("Wrong folder detected? Choose another", isExpanded: $showFolderChoice) {
                                    Picker("Spam folder", selection: $spamFolder) {
                                        ForEach(probe?.folders ?? [], id: \.self) { Text($0).tag($0) }
                                    }
                                    .padding(.top, 6)
                                }
                            }
                            .padding(6)
                        }
                        Text("The button below confirms this layout. Existing messages in training folders will be treated as your explicit corrections.")
                            .font(.footnote)
                            .foregroundStyle(.secondary)
                        HStack {
                            Button("Back") { step = 1 }.disabled(model.busy)
                            Button("Confirm folders and save") { Task { await commitSetup() } }
                                .buttonStyle(.borderedProminent)
                                .keyboardShortcut(.defaultAction)
                                .disabled(!OnboardingGate.canCommitFolders(folderSelected: !spamFolder.isEmpty, busy: model.busy))
                        }
                    }
                default:
                    VStack(alignment: .leading, spacing: 12) {
                        Text("First dry-run — no changes").font(.title2.bold())
                        Text("We will check mail and summarize proposed actions. No message will be moved, deleted or used for learning.")
                        if !dryRunDone {
                            Button("Run a safe dry-run") { Task { await runDry() } }
                                .buttonStyle(.borderedProminent)
                                .keyboardShortcut(.defaultAction)
                                .disabled(model.busy)
                            Button("Change account settings again") { step = 1 }.disabled(model.busy)
                        } else {
                            Label("Safe dry-run completed", systemImage: "checkmark.circle.fill").foregroundStyle(GuardianStyle.accent)
                            if let scan = model.lastScan, scan.dryRun { ScanOutcomeView(outcome: scan) }
                            Text("Next comes Inbox observation. Messages from spam may move to the configured review folder. Enable Inbox cleanup separately after safety requirements are met.")
                                .font(.callout).foregroundStyle(.secondary)
                            Button("Enable checks every 2 hours") { Task { await enableService() } }
                                .buttonStyle(.borderedProminent)
                                .keyboardShortcut(.defaultAction)
                                .disabled(model.busy)
                            Button("Finish in manual mode") { model.completeOnboarding() }.disabled(model.busy)
                            Text("In manual mode, Guardian checks mail only when you choose Check mail now.")
                                .font(.footnote).foregroundStyle(.secondary)
                        }
                    }
                }
            }
            .disabled(model.busy)
            PrivacyNote()
        }
        .onAppear { if step == 1 { accountField = .email } }
    }

    private func probeConnection() async {
        guard connectionValid && OnboardingGate.canProbe(email: email, password: password, busy: model.busy) else { return }
        model.failure = nil
        model.notice = nil
        model.operationTitle = "Checking account and encrypted IMAP connection…"
        model.busy = true
        defer { model.busy = false }
        do {
            email = email.trimmingCharacters(in: .whitespacesAndNewlines)
            let body = connectionRequest
            probe = try await Backend.call(["setup", "probe"], input: body, as: SetupProbe.self)
            guard probe?.safeMove == true else { throw APIErrorPayload(code: "IMAP_MOVE", severity: "critical", message: "Server does not support safe MOVE.", recovery: "Retain the check result and leave automation disabled.") }
            spamFolder = probe?.detectedSpam ?? ""
            showFolderChoice = spamFolder.isEmpty
            step = 2
        } catch let error as APIErrorPayload { model.failure = error }
        catch { model.failure = APIErrorPayload(code: "SETUP", severity: "error", message: error.localizedDescription, recovery: "Correct the settings and retry.") }
    }

    private func commitSetup() async {
        guard OnboardingGate.canCommitFolders(folderSelected: !spamFolder.isEmpty, busy: model.busy) else { return }
        model.failure = nil
        model.notice = nil
        model.operationTitle = "Saving account and preparing folders…"
        model.busy = true
        defer { model.busy = false }
        do {
            var request = connectionRequest
            // The explicitly labeled button supplies the required confirmation.
            request.spamFolder = spamFolder
            request.acceptExistingTraining = true
            let result: SetupResult = try await Backend.call(["setup", "commit"], input: request)
            password = ""
            if result.firstDryRunRequired { model.markConfigurationCommitted() }
            setupCommitted = true
            step = 3
        } catch let error as APIErrorPayload { model.failure = error }
        catch { model.failure = APIErrorPayload(code: "SETUP", severity: "error", message: error.localizedDescription, recovery: "Retry; automation was not enabled.") }
    }

    private func runDry() async {
        await model.runNow(dryRun: true)
        // Cancellation is informational and intentionally does not populate
        // model.failure. Only the durable backend gate may unlock automation.
    }

    private func enableService() async {
        await model.setAutomation(true)
        if OnboardingGate.automationEnabled(model.snapshot) {
            model.completeOnboarding()
            await model.refresh()
        }
    }
}

struct GuardianMenu: View {
    @ObservedObject var model: GuardianModel
    @Environment(\.openWindow) private var openWindow
    var body: some View {
        Text(ProtectionPresentation(model.snapshot, stale: model.snapshotIsStale).title).font(.headline)
        Text(ProtectionPresentation(model.snapshot, stale: model.snapshotIsStale).detail).font(.caption)
        Divider()
        ForEach(GuardianQuickAction.allCases) { action in
            switch action {
            case .openDashboard:
                Button("Open dashboard") {
                    NSApp.setActivationPolicy(.regular)
                    openWindow(id: "dashboard")
                    NSApp.activate(ignoringOtherApps: true)
                }
            case .runNow:
                Button("Check now") { Task { await model.runNow() } }
                    .disabled(model.busy || !model.snapshot.configured)
            case .repair:
                Button("Repair") { Task { await model.repair() } }
                    .disabled(model.busy || !model.snapshot.configured)
            case .toggleAutomation:
                Button(model.snapshot.automation == "on" ? "Pause automation" : "Resume automation") {
                    Task { await model.setAutomation(model.snapshot.automation != "on") }
                }
                .disabled(model.busy || !model.snapshot.firstDryRun)
            }
        }
        Divider()
        Button("Quit application") { NSApp.terminate(nil) }
    }
}
