import AppKit
import SwiftUI

struct QualityCheck: Codable, Identifiable {
    var id: String
    var title: String
    var detail: String
    var passed: Bool
}

struct ProtectionProgress: Codable {
    var requiredDays: Int
    var remainingDays: Int
    var periodComplete: Bool
    var qualityReady: Bool
    var ready: Bool
    var message: String
    var qualityChecks: [QualityCheck]? = nil
}

struct ScanOutcome: Codable {
    var dryRun: Bool
    var scanned: Int
    var kept: Int
    var rescued: Int
    var quarantined: Int
    var review: Int
    var errors: Int
}

enum GuardianSection: String, CaseIterable, Identifiable {
    case overview, learning, archive, settings, help
    var id: String { rawValue }
    var title: String {
        switch self {
        case .overview: return "Overview"
        case .learning: return "Training and corrections"
        case .archive: return "Recovery"
        case .settings: return "Settings"
        case .help: return "Help"
        }
    }
    var symbol: String {
        switch self {
        case .overview: return "square.grid.2x2"
        case .learning: return "hand.thumbsup"
        case .archive: return "tray.and.arrow.up"
        case .settings: return "slider.horizontal.3"
        case .help: return "questionmark.circle"
        }
    }
}

// Service health and permission to move mail are separate facts. In particular,
// a healthy observer must never claim that automatic sorting is active.
struct ProtectionPresentation {
    let title: String
    let detail: String
    let symbol: String
    let tone: Color

    init(_ snapshot: GuardianSnapshot, stale: Bool = false) {
        if stale {
            title = "Cannot confirm status"
            detail = "Showing the last retrieved data. Check the connection to the local engine."
            symbol = "questionmark.shield"
            tone = .orange
        } else if snapshot.health == "critical" || snapshot.health == "attention" {
            title = snapshot.health == "critical" ? "Protection needs repair" : "Protection needs attention"
            detail = snapshot.recommendation
            symbol = snapshot.health == "critical" ? "exclamationmark.shield.fill" : "exclamationmark.triangle.fill"
            tone = snapshot.health == "critical" ? .red : .orange
        } else if !snapshot.configured {
            title = "Connect your email"
            detail = "Complete a short setup to start a safe dry-run."
            symbol = "envelope.badge.shield.half.filled"
            tone = GuardianStyle.accent
        } else if snapshot.automation != "on" {
            title = "Checks on demand"
            detail = "Automation is off. Guardian checks mail when you request it."
            symbol = "pause.circle.fill"
            tone = .secondary
        } else if snapshot.mode == "protect" {
            title = "Inbox under observation"
            detail = "Guardian checks mail every 2 hours. Inbox messages are not moved automatically."
            symbol = "eye.fill"
            tone = GuardianStyle.accent
        } else if snapshot.mode == "active" {
            title = "Cleanup enabled"
            detail = "Guardian quarantines confident spam and rescues legitimate messages from the spam folder."
            symbol = "checkmark.shield.fill"
            tone = GuardianStyle.accent
        } else {
            title = "Check protection settings"
            detail = "Unrecognized operating mode. Run Check and repair."
            symbol = "questionmark.shield"
            tone = .orange
        }
    }
}

enum GuardianStyle {
    static let accent = Color(nsColor: NSColor(name: nil) { appearance in
        appearance.bestMatch(from: [.darkAqua, .aqua]) == .darkAqua
            ? NSColor(srgbRed: 0.37, green: 0.82, blue: 0.74, alpha: 1)
            : NSColor(srgbRed: 0.08, green: 0.39, blue: 0.35, alpha: 1)
    })
    static let surface = Color(nsColor: .controlBackgroundColor)
    static let background = Color(nsColor: .windowBackgroundColor)
}

struct GuardianPage<Content: View>: View {
    let eyebrow: String
    let title: String
    let subtitle: String
    @ViewBuilder var content: Content

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 24) {
                VStack(alignment: .leading, spacing: 8) {
                    Text(eyebrow.uppercased()).font(.system(size: 10, weight: .semibold)).tracking(1.8).foregroundStyle(GuardianStyle.accent)
                    Text(title).font(.system(size: 28, weight: .bold, design: .rounded)).accessibilityAddTraits(.isHeader)
                    if !subtitle.isEmpty { Text(subtitle).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true) }
                }
                content
            }
            .frame(maxWidth: 960, alignment: .leading)
            .padding(30)
            .frame(maxWidth: .infinity, alignment: .topLeading)
        }
        .background(GuardianStyle.background)
    }
}

struct GuardianCard<Content: View>: View {
    @ViewBuilder var content: Content
    var body: some View {
        VStack(alignment: .leading, spacing: 16) { content }
            .frame(maxWidth: .infinity, alignment: .leading)
            .padding(20)
            .background(GuardianStyle.surface, in: RoundedRectangle(cornerRadius: 16))
            .overlay(RoundedRectangle(cornerRadius: 16).strokeBorder(.primary.opacity(0.07)))
    }
}

struct PrivacyNote: View {
    var body: some View {
        Label("Analysis on your Mac. Links and attachments are not opened.", systemImage: "lock.shield")
            .font(.caption).foregroundStyle(.secondary)
            .fixedSize(horizontal: false, vertical: true)
    }
}

struct EmptyState: View {
    let symbol: String
    let title: String
    let detail: String
    var body: some View {
        VStack(spacing: 12) {
            Image(systemName: symbol).font(.system(size: 32, weight: .light)).foregroundStyle(GuardianStyle.accent).accessibilityHidden(true)
            Text(title).font(.headline)
            Text(detail).foregroundStyle(.secondary).multilineTextAlignment(.center).fixedSize(horizontal: false, vertical: true)
        }.padding(28).frame(maxWidth: .infinity, maxHeight: .infinity)
    }
}

struct ScanOutcomeView: View {
    let outcome: ScanOutcome
    var body: some View {
        GuardianCard {
            Label(outcome.errors > 0 ? "Check completed with issues" : (outcome.dryRun ? "Dry-run result" : "Last check result"),
                  systemImage: outcome.errors > 0 ? "exclamationmark.triangle" : "checkmark.circle")
                .font(.headline)
            Text(outcome.dryRun ? "This simulates the current mode. No messages were moved, deleted or used for learning." : "Results of this operation, excluding previous checks.")
                .font(.callout).foregroundStyle(.secondary)
            LazyVGrid(columns: [GridItem(.adaptive(minimum: 130), alignment: .leading)], alignment: .leading, spacing: 16) {
                outcomeNumber(outcome.scanned, "Scanned")
                outcomeNumber(outcome.review, outcome.dryRun ? "Review · planned" : "Review")
                outcomeNumber(outcome.quarantined, outcome.dryRun ? "Quarantine · planned" : "Quarantined")
                outcomeNumber(outcome.rescued, outcome.dryRun ? "Rescue · planned" : "Rescued")
            }
            if outcome.errors > 0 {
                Text("Some checks failed (\(outcome.errors)). Check and repair protection before retrying.")
                    .foregroundStyle(.orange).font(.callout)
            }
        }
    }
    private func outcomeNumber(_ value: Int, _ label: String) -> some View {
        VStack(alignment: .leading, spacing: 5) {
            Text(value, format: .number).font(.title2.bold()).monospacedDigit()
            Text(label).font(.caption).foregroundStyle(.secondary)
        }.accessibilityElement(children: .combine)
    }
}

struct ProtectionProgressView: View {
    @ObservedObject var model: GuardianModel
    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            HStack {
                Label("Progress toward automatic cleanup", systemImage: "checklist").font(.headline)
                Spacer()
            }
            if let progress = model.snapshot.protection {
                HStack {
                    Text(progress.periodComplete ? "Observation period complete" : "Observation days remaining: \(progress.remainingDays)")
                    Spacer()
                    Text("\(max(0, progress.requiredDays - progress.remainingDays)) / \(progress.requiredDays) days").foregroundStyle(.secondary)
                }.font(.callout)
                ProgressView(value: Double(max(0, progress.requiredDays - progress.remainingDays)), total: Double(max(1, progress.requiredDays)))
                    .accessibilityLabel("Observation period")
                Label(progress.qualityReady ? "Decision quality confirmed" : "Decision quality needs confirmation", systemImage: progress.qualityReady ? "checkmark.circle.fill" : "circle.dashed")
                    .font(.callout).foregroundStyle(progress.qualityReady ? GuardianStyle.accent : .secondary)
                Text(progress.message).font(.callout).foregroundStyle(.secondary)
                if let checks = progress.qualityChecks, !checks.isEmpty {
                    DisclosureGroup("Quality requirements: \(checks.filter { $0.passed }.count) of \(checks.count) met") {
                        VStack(alignment: .leading, spacing: 14) {
                            Text("This assessment covers the current observation period and your confirmations. No reported errors does not guarantee error-free operation.")
                                .font(.callout).foregroundStyle(.secondary)
                            ForEach(checks) { check in
                                VStack(alignment: .leading, spacing: 4) {
                                    Label(check.title, systemImage: check.passed ? "checkmark.circle.fill" : "circle.dashed")
                                        .foregroundStyle(check.passed ? GuardianStyle.accent : .primary)
                                    Text(check.detail).font(.callout).foregroundStyle(.secondary)
                                }.accessibilityElement(children: .ignore)
                                    .accessibilityLabel("\(check.title). \(check.passed ? "Requirement met" : "Requirement unmet"). \(check.detail)")
                            }
                        }.padding(.top, 10)
                    }
                }

            } else {
                Text("Moves require completed observation and confirmed decision quality. Refresh status to check readiness.").foregroundStyle(.secondary)
            }
        }
    }
}

struct MainTabs: View {
    @ObservedObject var model: GuardianModel
    var body: some View {
        NavigationSplitView {
            VStack(alignment: .leading, spacing: 16) {
                HStack(spacing: 10) {
                    Image(systemName: "checkmark.shield.fill").font(.title).foregroundStyle(GuardianStyle.accent)
                    VStack(alignment: .leading, spacing: 2) {
                        Text("Mail Guardian").font(.headline)
                        Text("Peace of mind for your email").font(.caption).foregroundStyle(.secondary)
                    }
                }.padding(.horizontal, 18).padding(.top, 24)
                List(GuardianSection.allCases, selection: Binding<GuardianSection?>(get: { model.section }, set: { if let value = $0 { model.section = value } })) { section in
                    Label(section.title, systemImage: section.symbol).padding(.vertical, 6).tag(section)
                }.listStyle(.sidebar)
                VStack(alignment: .leading, spacing: 8) {
                    Label("Runs locally on your Mac", systemImage: "lock.shield").font(.caption)
                    Text("Mail Guardian \(model.snapshot.version)").font(.caption2)
                }.foregroundStyle(.secondary).padding(18)
            }.navigationSplitViewColumnWidth(min: 195, ideal: 205, max: 230)
        } detail: {
            switch model.section {
            case .overview: DashboardView(model: model)
            case .learning: LearningView(model: model)
            case .archive: ArchiveView(model: model)
            case .settings: SettingsView(model: model)
            case .help: HelpView(model: model)
            }
        }
    }
}

struct DashboardView: View {
    @ObservedObject var model: GuardianModel
    @State private var showDetails = false
    private var presentation: ProtectionPresentation { ProtectionPresentation(model.snapshot, stale: model.snapshotIsStale) }
    var body: some View {
        GuardianPage(eyebrow: "Your email, under control", title: "Your email", subtitle: "") {
            VStack(alignment: .leading, spacing: 20) {
                HStack(alignment: .top, spacing: 16) {
                    Image(systemName: presentation.symbol).font(.system(size: 27)).frame(width: 56, height: 56)
                        .background(presentation.tone.opacity(0.12), in: RoundedRectangle(cornerRadius: 16)).foregroundStyle(presentation.tone).accessibilityHidden(true)
                    VStack(alignment: .leading, spacing: 8) {
                        Text(presentation.title).font(.system(size: 23, weight: .semibold, design: .rounded))
                        Text(presentation.detail).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
                    }
                }
                HStack(spacing: 12) {
                    if model.snapshotIsStale || model.snapshot.health == "critical" || model.snapshot.health == "attention" {
                        Button("Check and repair") { Task { await model.repair() } }.buttonStyle(.borderedProminent)
                    } else {
                        Button("Check mail now") { Task { await model.runNow() } }.buttonStyle(.borderedProminent)
                    }
                    if model.snapshot.automation != "on" && model.snapshot.firstDryRun {
                        Button("Enable automation") { Task { await model.setAutomation(true) } }
                    }
                    Spacer()
                }.controlSize(.large).disabled(model.busy)
                Divider()
                HStack(alignment: .top) {
                    Label("Last success: \(friendlyDate(model.snapshot.lastSuccess))", systemImage: "checkmark.circle")
                    Spacer()
                    Label(model.snapshot.automation == "on" ? "Automatically every 2 hours" : "Manual checks", systemImage: "clock")
                }.font(.callout).foregroundStyle(.secondary)
                Label(model.snapshot.purgeEnabled ? "Permanent deletion enabled — safety checks apply" : "Permanent deletion disabled", systemImage: model.snapshot.purgeEnabled ? "exclamationmark.circle" : "lock.fill")
                    .font(.caption).foregroundStyle(.secondary)
            }.padding(24).frame(maxWidth: .infinity, alignment: .leading)
                .background(LinearGradient(colors: [presentation.tone.opacity(0.08), GuardianStyle.surface], startPoint: .topLeading, endPoint: .bottomTrailing), in: RoundedRectangle(cornerRadius: 20))
                .overlay(RoundedRectangle(cornerRadius: 20).strokeBorder(presentation.tone.opacity(0.16)))

            if let scan = model.lastScan { ScanOutcomeView(outcome: scan) }
            if model.snapshot.summary.waitingReview > 0 || model.snapshot.summary.pendingMoves > 0 {
                GuardianCard {
                    Label("Your next action", systemImage: "tray.full").font(.headline)
                    if model.snapshot.summary.waitingReview > 0 {
                        Text("Messages awaiting review: \(model.snapshot.summary.waitingReview). Open \(model.snapshot.folders.review) in your email client.")
                        Button("Review messages", systemImage: "arrow.right") { model.section = .learning }
                    }
                    if model.snapshot.summary.pendingMoves > 0 {
                        Text("Guardian is reconciling interrupted operations: \(model.snapshot.summary.pendingMoves). Use Repair instead of repeating them manually.").font(.callout).foregroundStyle(.secondary)
                        Button("Check and repair") { Task { await model.repair() } }.disabled(model.busy)
                    }
                }
            }
            if model.snapshot.configured && model.snapshot.health == "healthy" && !model.snapshotIsStale && model.snapshot.summary.waitingReview == 0 && model.snapshot.summary.pendingMoves == 0 {
                Label(model.snapshot.automation == "on" ? "No messages await review according to the latest records." : "No recorded messages await review. Run the next check manually.", systemImage: "checkmark.circle")
                    .font(.callout).foregroundStyle(.secondary)
            }
            if model.snapshot.mode == "protect" {
                GuardianCard {
                    ProtectionProgressView(model: model)
                    HStack {
                        Button(model.snapshot.protection?.ready == true ? "Enable cleanup" : "View protection settings") { model.section = .settings }
                        Button("How to help with training") { model.section = .learning }
                    }
                    Text("During observation, messages from spam may move to the review folder. Guardian also processes your corrections.").font(.caption).foregroundStyle(.secondary)
                }
            }
            VStack(alignment: .leading, spacing: 12) {
                HStack {
                    Text("Last 24 hours").font(.headline)
                    Spacer()
                    if model.snapshotIsStale { Text("Data may be outdated").font(.caption).foregroundStyle(.orange) }
                }
                LazyVGrid(columns: Array(repeating: GridItem(.flexible(), alignment: .topLeading), count: 3), spacing: 12) {
                    metric("Scanned", value: model.snapshot.summary.scanned, symbol: "envelope", detail: "message analysis")
                    metric("Rescued", value: model.snapshot.summary.rescued, symbol: "tray.and.arrow.up", detail: "from spam")
                    metric("Spam held", value: model.snapshot.summary.quarantined, symbol: "shield.lefthalf.filled", detail: "moves to quarantine")
                }
            }
            GuardianCard {
                DisclosureGroup("Operation details", isExpanded: $showDetails) {
                    VStack(alignment: .leading, spacing: 10) {
                        Text("Last attempt: \(friendlyDate(model.snapshot.lastAttempt))")
                        Text("Quarantine backups in the latest records: \(model.snapshot.summary.waitingQuarantine)")
                        HStack {
                            Button("View backups") { model.section = .archive }
                            Button("Refresh status") { Task { await model.refresh() } }.disabled(model.busy)
                        }
                    }.font(.callout).padding(.top, 10)
                }
            }
            PrivacyNote()
        }
    }
    private func metric(_ title: String, value: Int, symbol: String, detail: String) -> some View {
        GuardianCard {
            Label(title, systemImage: symbol).font(.callout).foregroundStyle(.secondary)
            Text(value, format: .number).font(.system(size: 26, weight: .semibold, design: .rounded)).monospacedDigit()
            Text(detail).font(.caption).foregroundStyle(.secondary)
        }.accessibilityElement(children: .combine)
    }
}

struct OperationFeedback: View {
    @ObservedObject var model: GuardianModel
    @State private var showErrorDetails = false
    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            if let error = model.failure {
                HStack(alignment: .top, spacing: 12) {
                    Image(systemName: "exclamationmark.circle.fill").foregroundStyle(.orange)
                    VStack(alignment: .leading, spacing: 8) {
                        Text(error.message).font(.callout.weight(.semibold)).textSelection(.enabled)
                        if let recovery = error.recovery { Text(recovery).font(.callout).foregroundStyle(.secondary) }
                        HStack {
                            if failureQuickAction(for: error.code) == .accountSettings {
                                Button("Open account settings") { model.reconfigure = true; model.failure = nil }.disabled(model.busy)
                            } else {
                                Button(model.snapshotIsStale ? "Retry status retrieval" : "Check and repair") {
                                    model.failure = nil
                                    Task { if model.snapshotIsStale { await model.refresh() } else { await model.repair() } }
                                }.disabled(model.busy)
                            }
                            Button(showErrorDetails ? "Hide details" : "Support details") { showErrorDetails.toggle() }.buttonStyle(.link)
                        }.font(.caption)
                        if showErrorDetails { Text("Code: \(error.code)").font(.caption.monospaced()).textSelection(.enabled) }
                    }
                    Spacer(minLength: 0)
                    Button { model.failure = nil; showErrorDetails = false } label: { Image(systemName: "xmark") }.buttonStyle(.plain).help("Dismiss error").accessibilityLabel("Dismiss error")
                }.padding(16).background(.orange.opacity(0.07))
            }
            if model.busy {
                HStack(spacing: 12) {
                    ProgressView().controlSize(.small)
                    VStack(alignment: .leading, spacing: 3) {
                        Text(model.operationTitle).font(.callout.weight(.medium))
                        Text("You may cancel. Previously completed steps remain saved.").font(.caption).foregroundStyle(.secondary)
                    }
                    Spacer()
                    Button("Cancel") { model.cancel() }
                }.padding(.horizontal, 20).padding(.vertical, 14)
            } else if let notice = model.notice {
                HStack(spacing: 10) {
                    Image(systemName: "info.circle").foregroundStyle(GuardianStyle.accent)
                    Text(notice).font(.callout).textSelection(.enabled)
                    Spacer()
                    Button { model.notice = nil } label: { Image(systemName: "xmark") }.buttonStyle(.plain).help("Dismiss notification").accessibilityLabel("Dismiss notification")
                }.padding(.horizontal, 20).padding(.vertical, 14)
            }
        }.background(.regularMaterial)
    }
}
