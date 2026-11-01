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

struct GuardianSnapshot: Codable {
    var configured = false
    var health = "unconfigured"
    var healthLabel = "Wymaga konfiguracji"
    var recommendation = "Dokończ pierwszą konfigurację."
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
    case o2Instructions
    case repair
}

func failureQuickAction(for code: String?) -> FailureQuickAction {
    switch code {
    case "IMAP_AUTH": return .o2Instructions
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
            throw APIErrorPayload(code: "API_VERSION", severity: "critical", message: "Nieobsługiwana wersja lokalnego API.", recovery: "Uruchom ponownie Install.command.")
        }
        if !envelope.ok {
            throw envelope.error ?? APIErrorPayload(code: "UNKNOWN", severity: "error", message: "Nieznany błąd Guardiana.", recovery: "Uruchom Napraw.")
        }
        guard let value = envelope.data else {
            throw APIErrorPayload(code: "EMPTY_RESPONSE", severity: "error", message: "Guardian nie zwrócił wyniku.", recovery: "Uruchom Napraw.")
        }
        return value
    }

    private static func run(arguments: [String], input: Data?) async throws -> Data {
        let executablePath = executable
        return try await Task.detached(priority: .userInitiated) {
            guard FileManager.default.isExecutableFile(atPath: executablePath) else {
                throw APIErrorPayload(code: "NOT_INSTALLED", severity: "critical", message: "Silnik Guardian nie jest zainstalowany.", recovery: "Uruchom Install.command.")
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
                throw APIErrorPayload(code: "LOCAL_IO", severity: "error", message: "Nie udało się przygotować prywatnego bufora odpowiedzi.", recovery: "Uruchom Napraw.")
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
                throw APIErrorPayload(code: "GUI_BUSY", severity: "attention", message: "Guardian wykonuje już inną operację.", recovery: "Poczekaj na jej zakończenie albo użyj przycisku Anuluj.")
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
                    throw APIErrorPayload(code: "CANCELLED", severity: "info", message: "Operacja została anulowana.", recovery: "Nic nie zostało zmienione poza wcześniej bezpiecznie zakończonymi krokami.")
                }
                if Date() >= deadline {
                    process.terminate()
                    throw APIErrorPayload(code: "TIMEOUT", severity: "attention", message: "Operacja trwała zbyt długo i została zatrzymana.", recovery: "Uruchom Napraw; Guardian uzgodni każdy przerwany ruch.")
                }
                try await Task.sleep(for: .milliseconds(100))
            }
            if ProcessController.shared.cancelled() {
                throw APIErrorPayload(code: "CANCELLED", severity: "info", message: "Operacja została anulowana.", recovery: "Nic nie zostało zmienione poza wcześniej bezpiecznie zakończonymi krokami.")
            }
            try stdout.synchronize()
            let attributes = try FileManager.default.attributesOfItem(atPath: outputURL.path)
            let outputSize = (attributes[.size] as? NSNumber)?.intValue ?? 0
            guard outputSize <= 2 * 1024 * 1024 else {
                throw APIErrorPayload(code: "RESPONSE_TOO_LARGE", severity: "error", message: "Odpowiedź Guardiana jest zbyt duża.", recovery: "Uruchom Napraw.")
            }
            guard process.terminationStatus == 0 else {
                throw APIErrorPayload(code: "BACKEND_FAILED", severity: "error", message: "Silnik Guardian zakończył pracę błędem.", recovery: "Uruchom Napraw.")
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
    @Published var operationTitle = "Aktualizuję stan ochrony…"
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
        if ownsBusyState { operationTitle = "Aktualizuję stan ochrony…"; busy = true }
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
            recordRefreshFailure(APIErrorPayload(code: "GUI", severity: "error", message: error.localizedDescription, recovery: "Uruchom Napraw."))
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
        snapshot.healthLabel = "Nie działa"
        snapshot.recommendation = error.recovery ?? "Uruchom Napraw."
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
        // Backend atomowo unieważnia poprzedni dry-run i zatrzymuje usługę.
        // Odzwierciedlamy to od razu, aby błąd lub anulowanie następnej próby
        // nie mogły odblokować kreatora na podstawie starego snapshotu.
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
    func perform(_ title: String = "Aktualizuję ustawienia…", work: @escaping () async throws -> String?) async -> Bool {
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
                showNotice("Operacja została anulowana. Wcześniej zakończone kroki mogły zostać zapisane. Odśwież stan ochrony.")
            } else {
                failure = error
            }
        } catch {
            failure = APIErrorPayload(code: "GUI", severity: "error", message: error.localizedDescription, recovery: "Uruchom Napraw.")
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
        await perform(dryRun ? "Analizuję pocztę bez wprowadzania zmian…" : "Sprawdzam pocztę i przetwarzam korekty…") {
            let args = dryRun ? ["run", "dry-run"] : ["run"]
            let result: CompletionResult = try await Backend.call(args)
            self.lastScan = result.summary
            if let summary = result.summary, summary.errors > 0 { return "Sprawdzanie zakończono z uwagami. Zobacz podsumowanie." }
            return result.completed ? (dryRun ? "Próba zakończyła się pomyślnie." : "Skrzynka została sprawdzona.") : nil
        }
    }

    func repair() async {
        await perform("Sprawdzam połączenie i naprawiam lokalną ochronę…") {
            let result: CompletionResult = try await Backend.call(["repair"])
            return result.completed ? "Naprawa zakończyła się pomyślnie." : nil
        }
    }

    func qualifyFilter() async {
        await perform("Sprawdzam jakość filtra na oddzielonych przykładach…") {
            let result: CompletionResult = try await Backend.call(["qualify"])
            return result.completed ? "Ocena filtra zakończona. Warunki porządkowania zostały sprawdzone ponownie." : nil
        }
    }

    func setAutomation(_ enabled: Bool) async {
        await perform {
            let _: ServiceResult = try await Backend.call(["service", enabled ? "enable" : "disable"])
            return enabled ? "Automatyczne sprawdzanie jest aktywne." : "Włączono tryb ręczny."
        }
    }

    func setAppAutostart(_ enabled: Bool) async {
        await perform {
            let _: AppAutostartResult = try await Backend.call(["app-autostart", enabled ? "enable" : "disable"])
            return enabled ? "Panel będzie uruchamiany po zalogowaniu." : "Wyłączono start panelu po zalogowaniu; ochrona poczty działa niezależnie."
        }
    }

    func deepDoctor() async {
        await perform("Sprawdzam konto, foldery i lokalny silnik…") {
            let result: CompletionResult = try await Backend.call(["doctor", "deep"])
            return result.completed ? "Pełna kontrola nie wykryła problemów." : nil
        }
    }

    func exportDiagnostics() async {
        await perform("Przygotowuję prywatny raport diagnostyczny…") {
            let result: DiagnosticsResult = try await Backend.call(["diagnostics"])
            return "Bezpieczny raport zapisano: \(result.path)"
        }
    }

    func loadArchive(page: Int = 1) async {
        guard !busy else { return }
        operationTitle = "Wczytuję listę kopii…"
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
            failure = APIErrorPayload(code: "ARCHIVE", severity: "error", message: error.localizedDescription, recovery: "Uruchom Napraw.")
        }
    }

    func previewArchive(id: Int64) async -> ArchivePreview? {
        guard !busy else { return nil }
        operationTitle = "Odczytuję bezpieczny podgląd…"
        failure = nil
        busy = true
        defer { busy = false }
        do {
            return try await Backend.call(["archive", "preview", String(id)])
        } catch let error as APIErrorPayload {
            failure = error
        } catch {
            failure = APIErrorPayload(code: "ARCHIVE", severity: "error", message: error.localizedDescription, recovery: "Uruchom Napraw.")
        }
        return nil
    }

    func restoreArchive(id: Int64) async {
        let completed = await perform("Przywracam wiadomość do folderu Do sprawdzenia…") {
            let result: RestoreResult = try await Backend.call(["archive", "restore", String(id)])
            if result.alreadyPresent == true { return "Wiadomość nadal istnieje; nie utworzono duplikatu." }
            return result.restored ? "Wiadomość została przywrócona do AI-Do-sprawdzenia." : nil
        }
        if completed { await loadArchive(page: archivePage.page) }
    }
}

struct AppSelfTestFailure: Error, CustomStringConvertible {
    let check: String
    var description: String { "Samokontrola aplikacji nie powiodła się: \(check)" }
}

enum AppSelfTest {
    static func run() throws {
        let snapshotJSON = #"{"protocol":1,"ok":true,"data":{"configured":true,"health":"healthy","health_label":"Wszystko działa","recommendation":"OK","automation":"on","mode":"protect","purge_enabled":false,"summary":{},"trained_spam":2,"trained_ham":3,"required_spam":200,"required_ham":200,"first_dry_run":true,"app_autostart":true,"version":"0.3.0"}}"#
        let snapshot = try ProtocolContract.decodeSnapshot(snapshotJSON)
        guard snapshot.ok, snapshot.data?.healthLabel == "Wszystko działa", snapshot.data?.trainedHam == 3 else {
            throw AppSelfTestFailure(check: "odczyt lokalnego protokołu JSON")
        }

        let errorJSON = #"{"protocol":1,"ok":false,"error":{"code":"IMAP_AUTH","severity":"attention","message":"Błąd","recovery":"Sprawdź hasło"}}"#
        guard try ProtocolContract.decodeEmpty(errorJSON).error?.code == "IMAP_AUTH" else {
            throw AppSelfTestFailure(check: "ustrukturyzowane błędy lokalnego API")
        }
        guard OnboardingGate.totalSteps == 3,
              OnboardingGate.canProbe(email: "test@o2.pl", password: "test", busy: false),
              !OnboardingGate.canProbe(email: "test", password: "test", busy: false),
              OnboardingGate.canCommitFolders(folderSelected: true, busy: false),
              !OnboardingGate.canCommitFolders(folderSelected: false, busy: false) else {
            throw AppSelfTestFailure(check: "blokady pierwszej konfiguracji")
        }
        let quickActions = GuardianQuickAction.allCases.map(\.rawValue)
        guard !quickActions.contains("purge"), !quickActions.contains("restore") else {
            throw AppSelfTestFailure(check: "bezpieczne akcje paska menu")
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
                print("Samokontrola aplikacji: OK")
                exit(EXIT_SUCCESS)
            } catch {
                print(String(describing: error))
                exit(EXIT_FAILURE)
            }
        }
    }

    var body: some Scene {
        Window("O2 Mail Guardian", id: "dashboard") {
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
            CommandMenu("Przejdź") {
                Group {
                    Button("Przegląd") { model.section = .overview }.keyboardShortcut("1", modifiers: .command)
                    Button("Nauka i korekty") { model.section = .learning }.keyboardShortcut("2", modifiers: .command)
                    Button("Odzyskiwanie") { model.section = .archive }.keyboardShortcut("3", modifiers: .command)
                    Button("Ustawienia") { model.section = .settings }.keyboardShortcut("4", modifiers: .command)
                    Button("Pomoc") { model.section = .help }.keyboardShortcut("5", modifiers: .command)
                }.disabled(!model.initialRefreshCompleted || model.onboardingRequired || model.reconfigure)
            }
        }

        MenuBarExtra {
            GuardianMenu(model: model)
        } label: {
            Label("O2 Mail Guardian — \(ProtectionPresentation(model.snapshot, stale: model.snapshotIsStale).title)", systemImage: ProtectionPresentation(model.snapshot, stale: model.snapshotIsStale).symbol)
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
    "Stan ochrony: \(snapshot.healthLabel). \(snapshot.recommendation)"
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
        case .quarantine: return "W kwarantannie"
        case .review: return "Do sprawdzenia"
        case .pendingMoves: return "Nierozstrzygnięte ruchy"
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
    case "active": return "Przenoszenie włączone"
    case "protect": return "Tylko obserwacja"
    default: return "Nieznane — uruchom Napraw"
    }
}

enum ArchiveRestoreGate {
    static func canRestore(selectedID: Int64?, previewedID: Int64?, busy: Bool) -> Bool {
        !busy && selectedID != nil && selectedID == previewedID
    }
}

func friendlyDate(_ value: String?) -> String {
    guard let value else { return "Jeszcze brak" }
    let parser = ISO8601DateFormatter()
    parser.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
    let date = parser.date(from: value) ?? {
        parser.formatOptions = [.withInternetDateTime]
        return parser.date(from: value)
    }()
    guard let date else { return value }
    let formatter = DateFormatter()
    formatter.locale = Locale(identifier: "pl_PL")
    formatter.dateFormat = "d MMM yyyy, HH:mm"
    return formatter.string(from: date)
}

func archiveVerdictLabel(_ verdict: String) -> String {
    switch verdict {
    case "spam": return "spam"
    case "ham": return "ważna"
    case "uncertain": return "niepewna"
    case "error": return "błąd kontroli"
    default: return "nierozpoznana"
    }
}

func archiveStatusLabel(_ status: String) -> String {
    switch status {
    case "quarantined": return "kwarantanna"
    case "review": return "do sprawdzenia"
    case "rescued": return "uratowana"
    case "restored": return "przywrócona"
    case "purged": return "usunięta po retencji"
    case "pending_move", "pending_learn", "pending_restore", "move_ambiguous": return "bezpieczne uzgadnianie"
    case "superseded": return "zastąpiona nowszą korektą"
    default: return "stan techniczny"
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
                    Text("Sprawdzam stan ochrony…").foregroundStyle(.secondary)
                }
                .frame(maxWidth: .infinity, maxHeight: .infinity)
                .accessibilityElement(children: .combine)
                .accessibilityLabel("Sprawdzam stan ochrony")
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
                Label("Podgląd aplikacji · przykładowe dane · bez połączenia z Twoją pocztą", systemImage: "play.rectangle")
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
    }

    var body: some View {
        GuardianPage(eyebrow: "Zacznij ze spokojem", title: model.reconfigure ? "Ustawienia konta" : "Połącz swoją pocztę", subtitle: "Trzy kroki. Najpierw sprawdzimy wszystko bez zmieniania wiadomości.") {
            if model.reconfigure && !setupCommitted {
                Button("Anuluj zmianę ustawień", role: .cancel) { model.reconfigure = false }
            } else if setupCommitted {
                Label("Ustawienia zapisano; automat pozostaje wstrzymany do zakończenia kreatora.", systemImage: "lock.shield")
                    .foregroundStyle(.secondary)
            }
            HStack(spacing: 14) {
                ForEach(1...3, id: \.self) { index in
                    HStack(spacing: 8) {
                        Image(systemName: index < step ? "checkmark.circle.fill" : "\(index).circle.fill")
                        Text(["Konto", "Foldery", "Bezpieczna próba"][index - 1]).font(.callout.weight(index == step ? .semibold : .regular))
                    }.foregroundStyle(index <= step ? GuardianStyle.accent : .secondary)
                    if index < 3 { Rectangle().fill(.quaternary).frame(height: 1) }
                }
            }.accessibilityElement(children: .ignore).accessibilityLabel("Krok \(step) z 3: \(["Konto", "Foldery", "Bezpieczna próba"][step - 1])")
            GuardianCard {
                switch step {
                case 1:
                    VStack(alignment: .leading, spacing: 12) {
                        Text("Konto i hasło aplikacyjne").font(.title2.bold())
                        DisclosureGroup("Przygotuj konto o2", isExpanded: $showAccountPreparation) {
                            VStack(alignment: .leading, spacing: 12) {
                                Label("1. Włącz dostęp IMAP w ustawieniach poczty o2.", systemImage: "envelope.badge.shield.half.filled")
                                Label("2. Włącz logowanie dwustopniowe i zachowaj klucze awaryjne.", systemImage: "lock.shield")
                                Label("3. Utwórz osobne hasło aplikacyjne dla Guardiana.", systemImage: "key")
                                Link("Jak utworzyć hasło aplikacyjne w o2", destination: URL(string: "https://pomoc.o2.pl/wpkonto/hasla-do-aplikacji-zewnetrznej")!)
                                Text("Masz już hasło aplikacyjne? Wpisz dane poniżej. Tych kroków nie trzeba wykonywać ponownie.")
                                    .foregroundStyle(.secondary)
                            }.font(.callout).padding(.vertical, 10)
                                .frame(maxWidth: .infinity, alignment: .leading)
                        }
                        Text("Adres e-mail o2").font(.callout.weight(.medium))
                        TextField("adres@o2.pl", text: $email)
                            .textFieldStyle(.roundedBorder)
                            .focused($accountField, equals: .email)
                            .accessibilityLabel("Adres e-mail o2")
                            .disabled(model.busy)
                            .onSubmit { accountField = .password }
                            .textContentType(.username)
                            .autocorrectionDisabled()
                        if !email.isEmpty && accountField != .email && !OnboardingGate.emailLooksComplete(email) {
                            Text("Wpisz pełny adres, np. nazwa@o2.pl.")
                                .font(.footnote)
                                .foregroundStyle(.orange)
                        }
                        Text("Hasło aplikacyjne").font(.callout.weight(.medium))
                        SecureField("Wklej hasło utworzone w o2", text: $password)
                            .textFieldStyle(.roundedBorder)
                            .focused($accountField, equals: .password)
                            .accessibilityLabel("Hasło aplikacyjne o2")
                            .disabled(model.busy)
                        Text("Nie wpisuj zwykłego hasła do poczty. Zapiszemy je bezpiecznie w pęku kluczy macOS.").font(.footnote).foregroundStyle(.secondary)
                        Button("Połącz i wykryj ustawienia") { Task { await probeConnection() } }
                            .buttonStyle(.borderedProminent)
                            .keyboardShortcut(.defaultAction)
                            .disabled(!OnboardingGate.canProbe(email: email, password: password, busy: model.busy))

                    }
                case 2:
                    VStack(alignment: .leading, spacing: 12) {
                        Label("Połączenie jest bezpieczne", systemImage: "checkmark.circle.fill").font(.title2.bold())
                        Text("o2 potwierdziło szyfrowane połączenie i bezpieczne przenoszenie wiadomości. Sprawdź tylko wykryty folder SPAM.")
                        GroupBox("Wykryte ustawienia") {
                            VStack(alignment: .leading, spacing: 8) {
                                Text("SPAM o2: \(spamFolder.isEmpty ? "wybierz poniżej" : spamFolder)").bold()
                                Text("Guardian przygotuje cztery dodatkowe foldery ochronne.")
                                    .foregroundStyle(.secondary)
                                DisclosureGroup("Pokaż nazwy folderów Guardiana") {
                                    Text("Kwarantanna: AI-Kwarantanna\nDo sprawdzenia: AI-Do-sprawdzenia\nNauka: AI-Naucz-spam i AI-Naucz-wazne")
                                        .padding(.top, 6)
                                }
                                DisclosureGroup("Wykryto zły folder? Wybierz inny", isExpanded: $showFolderChoice) {
                                    Picker("Folder SPAM", selection: $spamFolder) {
                                        ForEach(probe?.folders ?? [], id: \.self) { Text($0).tag($0) }
                                    }
                                    .padding(.top, 6)
                                }
                            }
                            .padding(6)
                        }
                        Text("Klikając przycisk poniżej, potwierdzasz pokazany układ. Jeśli foldery nauki zawierają już wiadomości, Guardian potraktuje je jako Twoje świadome poprawki.")
                            .font(.footnote)
                            .foregroundStyle(.secondary)
                        HStack {
                            Button("Wstecz") { step = 1 }.disabled(model.busy)
                            Button("Potwierdzam foldery i zapisuję") { Task { await commitSetup() } }
                                .buttonStyle(.borderedProminent)
                                .keyboardShortcut(.defaultAction)
                                .disabled(!OnboardingGate.canCommitFolders(folderSelected: !spamFolder.isEmpty, busy: model.busy))
                        }
                    }
                default:
                    VStack(alignment: .leading, spacing: 12) {
                        Text("Pierwsza próba — bez zmian").font(.title2.bold())
                        Text("Sprawdzimy pocztę i pokażemy podsumowanie proponowanych działań. Żadna wiadomość nie zostanie przeniesiona, usunięta ani użyta do nauki.")
                        if !dryRunDone {
                            Button("Wykonaj bezpieczną próbę") { Task { await runDry() } }
                                .buttonStyle(.borderedProminent)
                                .keyboardShortcut(.defaultAction)
                                .disabled(model.busy)
                            Button("Zmień ponownie dane konta") { step = 1 }.disabled(model.busy)
                        } else {
                            Label("Bezpieczna próba została wykonana", systemImage: "checkmark.circle.fill").foregroundStyle(GuardianStyle.accent)
                            if let scan = model.lastScan, scan.dryRun { ScanOutcomeView(outcome: scan) }
                            Text("Następny etap to obserwacja Odebranych. Wiadomości z folderu SPAM mogą być odkładane do AI-Do-sprawdzenia. Porządkowanie Odebranych włączysz osobno po spełnieniu warunków bezpieczeństwa.")
                                .font(.callout).foregroundStyle(.secondary)
                            Button("Włącz sprawdzanie co 2 godziny") { Task { await enableService() } }
                                .buttonStyle(.borderedProminent)
                                .keyboardShortcut(.defaultAction)
                                .disabled(model.busy)
                            Button("Zakończ w trybie ręcznym") { model.completeOnboarding() }.disabled(model.busy)
                            Text("W trybie ręcznym Guardian sprawdza pocztę tylko po użyciu przycisku „Sprawdź pocztę teraz”.")
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
        guard OnboardingGate.canProbe(email: email, password: password, busy: model.busy) else { return }
        model.failure = nil
        model.notice = nil
        model.operationTitle = "Sprawdzam konto i bezpieczne połączenie z o2…"
        model.busy = true
        defer { model.busy = false }
        do {
            email = email.trimmingCharacters(in: .whitespacesAndNewlines)
            let body = ["email": email, "password": password]
            probe = try await Backend.call(["setup", "probe"], input: body, as: SetupProbe.self)
            guard probe?.safeMove == true else { throw APIErrorPayload(code: "IMAP_MOVE", severity: "critical", message: "Serwer nie obsługuje bezpiecznego MOVE.", recovery: "Zachowaj wynik kontroli i nie włączaj automatyzacji.") }
            spamFolder = probe?.detectedSpam ?? ""
            showFolderChoice = spamFolder.isEmpty
            step = 2
        } catch let error as APIErrorPayload { model.failure = error }
        catch { model.failure = APIErrorPayload(code: "SETUP", severity: "error", message: error.localizedDescription, recovery: "Popraw dane i spróbuj ponownie.") }
    }

    private func commitSetup() async {
        guard OnboardingGate.canCommitFolders(folderSelected: !spamFolder.isEmpty, busy: model.busy) else { return }
        model.failure = nil
        model.notice = nil
        model.operationTitle = "Zapisuję konto i przygotowuję foldery…"
        model.busy = true
        defer { model.busy = false }
        do {
            struct Request: Encodable { let email, password, spamFolder: String; let acceptExistingTraining: Bool }
            // Sam jednoznacznie opisany przycisk jest jawnym potwierdzeniem.
            // Osobny checkbox nie dawał alternatywy i tylko komplikował kreator.
            let request = Request(email: email, password: password, spamFolder: spamFolder, acceptExistingTraining: true)
            let result: SetupResult = try await Backend.call(["setup", "commit"], input: request)
            password = ""
            if result.firstDryRunRequired { model.markConfigurationCommitted() }
            setupCommitted = true
            step = 3
        } catch let error as APIErrorPayload { model.failure = error }
        catch { model.failure = APIErrorPayload(code: "SETUP", severity: "error", message: error.localizedDescription, recovery: "Spróbuj ponownie; automatyzacja nie została włączona.") }
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
                Button("Otwórz panel") {
                    NSApp.setActivationPolicy(.regular)
                    openWindow(id: "dashboard")
                    NSApp.activate(ignoringOtherApps: true)
                }
            case .runNow:
                Button("Sprawdź teraz") { Task { await model.runNow() } }
                    .disabled(model.busy || !model.snapshot.configured)
            case .repair:
                Button("Napraw") { Task { await model.repair() } }
                    .disabled(model.busy || !model.snapshot.configured)
            case .toggleAutomation:
                Button(model.snapshot.automation == "on" ? "Wstrzymaj automat" : "Wznów automat") {
                    Task { await model.setAutomation(model.snapshot.automation != "on") }
                }
                .disabled(model.busy || !model.snapshot.firstDryRun)
            }
        }
        Divider()
        Button("Zakończ aplikację") { NSApp.terminate(nil) }
    }
}
