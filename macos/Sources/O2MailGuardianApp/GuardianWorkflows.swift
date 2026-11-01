import AppKit
import SwiftUI

struct LearningView: View {
    @ObservedObject var model: GuardianModel
    @State private var copiedFolder: String?
    var body: some View {
        GuardianPage(eyebrow: "Message review", title: "Review and correct", subtitle: "Three steps: open your email client, move a message, process the correction.") {
            GuardianCard {
                Label("1. Open messages for review", systemImage: "tray.full").font(.headline)
                Text("Open \(model.snapshot.folders.review) in your email client. Move recognized messages to one of the folders below. Leave uncertain messages for later review.")
                    .foregroundStyle(.secondary)
                HStack {
                    if model.snapshot.connection?.provider == "o2" {
                        Link("Open o2 webmail", destination: URL(string: "https://poczta.o2.pl/")!)
                            .buttonStyle(.borderedProminent).controlSize(.large)
                    }
                    Button("Process corrections already moved") { Task { await model.runNow() } }.disabled(model.busy)
                }
                Text("Use your usual email client. Processing starts a full check under the current protection mode.").font(.callout).foregroundStyle(.secondary)
            }
            HStack {
                Text("2. Choose the appropriate folder in your email client").font(.headline)
            }
            correctionCard("This is a legitimate message", symbol: "hand.thumbsup", folder: model.snapshot.folders.trainHam, detail: "Use when a legitimate message ended up in spam, quarantine or review.", result: "After successful learning, Guardian moves it to Inbox. Your correction blocks automatic deletion.", count: model.snapshot.trainedHam)
            correctionCard("This is spam", symbol: "hand.thumbsdown", folder: model.snapshot.folders.trainSpam, detail: "Use when unwanted mail remains in Inbox or awaits your assessment.", result: "After successful learning, Guardian moves it to quarantine.", count: model.snapshot.trainedSpam)
            GuardianCard {
                Text("3. Process corrections").font(.headline)
                Text(model.snapshot.automation == "on" ? "Corrections are processed during the next automatic check. You may also run it now." : "Automation is off. After moving messages, start a check with the button below.").foregroundStyle(.secondary)
                Button("Check mail and process corrections") { Task { await model.runNow() } }.buttonStyle(.borderedProminent).controlSize(.large).disabled(model.busy)
                Text("This also checks other mail under the current protection mode.").font(.caption).foregroundStyle(.secondary)
            }
            if let scan = model.lastScan { ScanOutcomeView(outcome: scan) }
            PrivacyNote()
        }
        .task(id: copiedFolder) {
            guard copiedFolder != nil else { return }
            do { try await Task.sleep(for: .seconds(3)) } catch { return }
            copiedFolder = nil
        }
    }
    private func correctionCard(_ title: String, symbol: String, folder: String, detail: String, result: String, count: Int) -> some View {
        GuardianCard {
            HStack {
                Label(title, systemImage: symbol).font(.title3.weight(.semibold))
                Spacer()
                Text("Corrections: \(count)").font(.caption).foregroundStyle(.secondary)
            }
            Text(detail).foregroundStyle(.secondary)
            HStack {
                Text(folder).font(.system(.body, design: .monospaced)).textSelection(.enabled)
                Spacer()
                Button(copiedFolder == folder ? "Copied" : "Copy name", systemImage: copiedFolder == folder ? "checkmark" : "doc.on.doc") {
                    NSPasteboard.general.clearContents()
                    NSPasteboard.general.setString(folder, forType: .string)
                    copiedFolder = folder
                }.help("Copy folder name to clipboard")
                .accessibilityLabel(copiedFolder == folder ? "Copied folder name \(folder)" : "Copy folder name \(folder)")
            }.padding(12).background(GuardianStyle.accent.opacity(0.06), in: RoundedRectangle(cornerRadius: 8))
            Text(result).font(.callout).foregroundStyle(.secondary)
        }
    }
}

struct ArchiveView: View {
    @ObservedObject var model: GuardianModel
    @State private var useDateRange = false
    @State private var fromDate = Calendar.current.date(byAdding: .day, value: -30, to: Date()) ?? Date()
    @State private var throughDate = Date()
    @State private var selected: ArchiveItem?
    @State private var previewedID: Int64?
    @State private var preview: ArchivePreview?
    @State private var confirmationItem: ArchiveItem?
    @State private var showingRestoreConfirmation = false
    private var canRestore: Bool {
        ArchiveRestoreGate.canRestore(selectedID: selected?.id, previewedID: previewedID, busy: model.busy)
    }
    var body: some View {
        GuardianPage(eyebrow: "Safe recovery", title: "Recover messages", subtitle: "Find a backup, check sender and subject, then restore the message.") {
            HStack {
                Picker("Show", selection: $model.archiveFilter) {
                    Text("All backups").tag("all")
                    Text("Quarantine").tag("quarantined")
                    Text("Review").tag("review")
                    Text("Restored").tag("restored")
                }.frame(maxWidth: 280).disabled(model.busy)
                Spacer()
                Button("Refresh", systemImage: "arrow.clockwise") { Task { await reload() } }.disabled(model.busy)
            }
            VStack(alignment: .leading, spacing: 12) {
                Toggle("Filter by first-backup date", isOn: $useDateRange).disabled(model.busy)
                if useDateRange {
                    HStack {
                        DatePicker("From", selection: $fromDate, displayedComponents: .date)
                            .environment(\.locale, Locale(identifier: "en"))
                            .disabled(model.busy)
                        DatePicker("To", selection: $throughDate, displayedComponents: .date)
                            .environment(\.locale, Locale(identifier: "en"))
                            .disabled(model.busy)
                        Button("Apply dates") { Task { await applyDateRange() } }
                            .disabled(model.busy || Calendar.current.startOfDay(for: fromDate) > Calendar.current.startOfDay(for: throughDate))
                    }
                    if Calendar.current.startOfDay(for: fromDate) > Calendar.current.startOfDay(for: throughDate) {
                        Text("From must not be later than To.").foregroundStyle(.red).font(.callout)
                    }
                    Text(model.archiveDateRange.isEmpty ? "Choose dates and apply the filter. The list still shows all dates." : "Showing period: \(appliedDateLabel). After changing dates, click Apply dates.")
                        .font(.callout).foregroundStyle(.secondary)
                }
            }
            Text("The list shows the first-backup date. Select an entry and reveal headers to identify it.")
                .font(.callout).foregroundStyle(.secondary)
            if !model.archiveLoaded {
                GuardianCard {
                    EmptyState(symbol: "tray", title: model.busy ? "Loading backups…" : "Could not read backups", detail: model.busy ? "Only the list is loaded. Message content remains encrypted." : "Retry. Your backups are unchanged.")
                    if !model.busy { Button("Retry") { Task { await reload() } } }
                }
            } else if model.archivePage.items.isEmpty {
                GuardianCard {
                    if model.archivePage.page > 1 {
                        EmptyState(symbol: "tray", title: "No more backups on this page", detail: "The archive may have changed. Return to the first page with your selected filters.")
                        Button("Return to first page") { Task { await changePage(1) } }.disabled(model.busy)
                    } else {
                    EmptyState(symbol: "tray", title: !model.archiveDateRange.isEmpty ? "No backups in this period" : (model.archiveFilter == "all" ? "No backups yet" : "No backups in this category"), detail: !model.archiveDateRange.isEmpty ? "Change the dates or disable the date filter to find other backups." : (model.archiveFilter == "all" ? "Backups appear when Guardian protects messages. No recovery is needed now." : "Choose another category to see other backups."))
                    }
                    HStack {
                        if !model.archiveDateRange.isEmpty {
                            Button("Disable date filter") { useDateRange = false }.disabled(model.busy)
                        }
                        if model.archiveFilter != "all" {
                            Button("Show all categories") { model.archiveFilter = "all" }.disabled(model.busy)
                        }
                    }
                }
            } else {
                HStack(alignment: .top, spacing: 16) {
                    VStack(alignment: .leading, spacing: 8) {
                        Text("SAVED BACKUPS").font(.system(size: 10, weight: .semibold)).tracking(1.2).foregroundStyle(.secondary).padding(.horizontal, 10)
                        ForEach(model.archivePage.items) { item in
                            Button {
                                selected = item
                                preview = nil
                                previewedID = nil
                            } label: {
                                VStack(alignment: .leading, spacing: 7) {
                                    Text(friendlyDate(item.date)).font(.callout.weight(.semibold))
                                    Text(archiveStatusLabel(item.status).capitalized).font(.caption).foregroundStyle(.secondary)
                                    Text("Backup \(item.id) · \(archiveVerdictLabel(item.verdict))").font(.caption2).foregroundStyle(.secondary)
                                }.frame(maxWidth: .infinity, alignment: .leading).padding(12)
                                    .background(selected?.id == item.id ? GuardianStyle.accent.opacity(0.12) : GuardianStyle.surface, in: RoundedRectangle(cornerRadius: 10))
                                    .overlay(RoundedRectangle(cornerRadius: 10).strokeBorder(selected?.id == item.id ? GuardianStyle.accent.opacity(0.4) : .clear))
                                    .contentShape(Rectangle())
                            }.buttonStyle(.plain).disabled(model.busy)
                                .accessibilityHint("Select a backup. Reveal sender and subject with a separate button.")
                                .accessibilityAddTraits(selected?.id == item.id ? .isSelected : [])
                        }
                    }.frame(width: 220)
                    GuardianCard {
                        if let selected {
                            HStack {
                                Text("Backup \(selected.id)").font(.headline)
                                Spacer()
                                Label("Local backup", systemImage: "lock").font(.caption).foregroundStyle(.secondary)
                            }
                            if let preview, previewedID == selected.id {
                                header("FROM", value: preview.from)
                                header("SUBJECT", value: preview.subject)
                                header("MESSAGE DATE", value: preview.date)
                                Divider()
                                Text("After restoration, find the message in \(model.snapshot.folders.review) in your email client.").font(.callout).foregroundStyle(.secondary)
                                Button("Restore message", systemImage: "tray.and.arrow.up") {
                                    confirmationItem = selected
                                    showingRestoreConfirmation = true
                                }.buttonStyle(.borderedProminent).controlSize(.large).disabled(!canRestore)
                                    .accessibilityHint("Opens confirmation to restore the selected backup to the review folder.")
                            } else {
                                Text("Reveal sender, subject and date to identify the message.").foregroundStyle(.secondary)
                                Button("Show sender and subject") { Task { await loadPreview(selected) } }.buttonStyle(.borderedProminent).disabled(model.busy)
                            }
                            HStack {
                                Button("Previous backup", systemImage: "chevron.up") { selectNeighbor(-1) }
                                    .disabled(model.busy || selectedIndex == nil || selectedIndex == 0)
                                    .accessibilityHint("Selects the previous entry on this page and hides headers.")
                                Button("Next backup", systemImage: "chevron.down") { selectNeighbor(1) }
                                    .disabled(model.busy || selectedIndex == nil || selectedIndex == model.archivePage.items.count - 1)
                                    .accessibilityHint("Selects the next entry on this page and hides headers.")
                            }
                            Text("Message body, links and attachments stay closed.").font(.caption).foregroundStyle(.secondary)
                        } else {
                            EmptyState(symbol: "sidebar.left", title: "Select a backup from the list", detail: "A safe preview appears here. Restoration requires your confirmation.")
                        }
                    }.frame(maxWidth: .infinity)
                }
            }
            HStack {
                Button("Previous", systemImage: "chevron.left") { Task { await changePage(max(1, model.archivePage.page - 1)) } }.disabled(!model.archiveLoaded || model.archivePage.page <= 1 || model.busy)
                Spacer()
                Text("Page \(model.archivePage.page)").font(.caption).foregroundStyle(.secondary)
                Spacer()
                Button("Next", systemImage: "chevron.right") { Task { await changePage(model.archivePage.page + 1) } }.disabled(!model.archiveLoaded || !model.archivePage.hasNext || model.busy)
            }
            PrivacyNote()
        }
        .task { await model.loadArchive() }
        .onChange(of: model.busy) { busy in
            if !busy && !model.archiveLoaded && model.failure == nil { Task { await model.loadArchive() } }
        }
        .onChange(of: model.archiveFilter) { _ in Task { await changePage(1) } }
        .onChange(of: useDateRange) { enabled in
            if !enabled { model.archiveDateRange = []; Task { await changePage(1) } }
        }
        .onAppear {
            useDateRange = !model.archiveDateRange.isEmpty
            if model.archiveDateRange.count == 2 {
                let formatter = ISO8601DateFormatter()
                if let start = formatter.date(from: model.archiveDateRange[0]), let end = formatter.date(from: model.archiveDateRange[1]) {
                    fromDate = start
                    throughDate = Calendar.current.date(byAdding: .day, value: -1, to: end) ?? end
                }
            }
        }
        .onDisappear { preview = nil; previewedID = nil }
        .confirmationDialog("Restore backup \(confirmationItem?.id ?? 0)?", isPresented: $showingRestoreConfirmation) {
            Button("Restore to \(model.snapshot.folders.review)") {
                if let item = confirmationItem, item.id == previewedID, item.id == selected?.id {
                    Task {
                        await model.restoreArchive(id: item.id)
                        preview = nil
                        previewedID = nil
                    }
                }
            }
            Button("Cancel", role: .cancel) { confirmationItem = nil }
        } message: {
            Text("Guardian creates a copy in \(model.snapshot.folders.review). Check it in your email client. No email is sent.")
        }
    }
    private var appliedDateLabel: String {
        guard model.archiveDateRange.count == 2 else { return "" }
        let parser = ISO8601DateFormatter()
        guard let start = parser.date(from: model.archiveDateRange[0]), let end = parser.date(from: model.archiveDateRange[1]) else { return "" }
        let formatter = DateFormatter()
        formatter.locale = Locale(identifier: "en")
        formatter.dateStyle = .medium
        formatter.timeStyle = .none
        let through = Calendar.current.date(byAdding: .day, value: -1, to: end) ?? end
        return "\(formatter.string(from: start)) – \(formatter.string(from: through))"
    }
    private func applyDateRange() async {
        let calendar = Calendar.current
        let start = calendar.startOfDay(for: fromDate)
        guard let end = calendar.date(byAdding: .day, value: 1, to: calendar.startOfDay(for: throughDate)), start < end else { return }
        let formatter = ISO8601DateFormatter()
        model.archiveDateRange = [formatter.string(from: start), formatter.string(from: end)]
        await changePage(1)
    }
    private var selectedIndex: Int? {
        model.archivePage.items.firstIndex { $0.id == selected?.id }
    }
    private func selectNeighbor(_ offset: Int) {
        guard let index = selectedIndex, model.archivePage.items.indices.contains(index + offset) else { return }
        selected = model.archivePage.items[index + offset]
        preview = nil
        previewedID = nil
        confirmationItem = nil
    }
    private func header(_ label: String, value: String) -> some View {
        VStack(alignment: .leading, spacing: 6) {
            Text(label).font(.system(size: 10, weight: .semibold)).tracking(1).foregroundStyle(.secondary)
            Text(value.isEmpty ? "No information" : value).textSelection(.enabled).fixedSize(horizontal: false, vertical: true)
        }
    }
    private func reload() async { await changePage(model.archivePage.page) }
    private func changePage(_ page: Int) async {
        selected = nil; preview = nil; previewedID = nil
        confirmationItem = nil; showingRestoreConfirmation = false
        await model.loadArchive(page: page)
    }
    private func loadPreview(_ item: ArchiveItem) async {
        preview = nil; previewedID = nil
        let result = await model.previewArchive(id: item.id)
        if model.section == .archive, selected?.id == item.id, let value = result {
            preview = value
            previewedID = item.id
        }
    }
}

struct SettingsView: View {
    @ObservedObject var model: GuardianModel
    @State private var activeConfirmation = ""
    @State private var purgeConfirmation = ""
    @State private var showAdvancedSafety = false
    @State private var showActivation = false
    @State private var showObservationConfirmation = false
    var body: some View {
        GuardianPage(eyebrow: "On your terms", title: "Protection settings", subtitle: "Choose when Guardian checks mail and what it may do.") {
            GuardianCard {
                Label("Automatic checks", systemImage: "clock.arrow.circlepath").font(.headline)
                Toggle("Check mail every 2 hours", isOn: Binding(get: { model.snapshot.automation == "on" }, set: { value in Task { await model.setAutomation(value) } }))
                    .toggleStyle(.switch).disabled(model.busy || !model.snapshot.firstDryRun)
                Text("Closing the window does not stop automation. Turn this off for checks on demand only.").font(.callout).foregroundStyle(.secondary)
            }
            GuardianCard {
                Label("Message moves", systemImage: "tray.2").font(.headline)
                if model.snapshot.mode == "active" {
                    Text("Automatic cleanup enabled").font(.title3.weight(.semibold))
                    Text("Confident spam goes to quarantine, legitimate messages return from spam to Inbox, and uncertain cases await your review.").foregroundStyle(.secondary)
                    Button("Return to observation") { showObservationConfirmation = true }.disabled(model.busy)
                } else {
                    Text("Inbox remains unchanged").font(.title3.weight(.semibold))
                    Text("During observation, messages from spam may move to the review folder. Your corrections are still processed.").foregroundStyle(.secondary)
                    Divider()
                    ProtectionProgressView(model: model)
                    HStack {
                        Button("Enable cleanup…") { activeConfirmation = ""; model.failure = nil; showActivation = true }
                            .buttonStyle(.borderedProminent).disabled(model.busy || model.snapshotIsStale || model.snapshot.protection?.ready != true)
                        Button("Open training") { model.section = .learning }
                    }
                }
                Button("Reevaluate filter quality") { Task { await model.qualifyFilter() } }.disabled(model.busy || model.snapshotIsStale)
                Text("Reevaluation trains a separate model and tests it on different messages. History is retained; cleanup still requires your confirmation.").font(.caption).foregroundStyle(.secondary)
            }
            GuardianCard {
                Label("Application and account", systemImage: "person.crop.circle").font(.headline)
                Toggle("Start dashboard at Mac login", isOn: Binding(get: { model.snapshot.appAutostart }, set: { value in Task { await model.setAppAutostart(value) } })).toggleStyle(.switch).disabled(model.busy)
                Text("This controls the window and menu-bar icon. The mail-check schedule is separate above.").font(.callout).foregroundStyle(.secondary)
                Divider()
                Button("Change account settings or password…") { model.reconfigure = true }.disabled(model.busy)
                Text("Changing settings pauses automation and requires another safe dry-run. The password is stored in macOS Keychain.").font(.callout).foregroundStyle(.secondary)
            }
            GuardianCard {
                DisclosureGroup("Advanced: permanent deletion", isExpanded: $showAdvancedSafety) {
                    VStack(alignment: .leading, spacing: 12) {
                        Label(model.snapshot.purgeEnabled ? "Permanent deletion enabled" : "Permanent deletion disabled", systemImage: "trash").font(.headline)
                        Text("This is a separate permission. Ordinary cleanup does not require deletion. Enabling it still requires protection periods and quality checks.").foregroundStyle(.secondary)
                        if model.snapshot.purgeEnabled {
                            Button("Disable permanent deletion") { Task { await setPurge("disable", confirmation: "") } }.disabled(model.busy)
                        } else {
                            Text("To authorize permanent deletion after qualification, type ENABLE.").font(.callout)
                            TextField("Confirm ENABLE", text: $purgeConfirmation).textFieldStyle(.roundedBorder)
                            Button("Enable permanent deletion", role: .destructive) { Task { await setPurge("enable", confirmation: purgeConfirmation) } }.disabled(purgeConfirmation != "ENABLE" || model.busy)
                        }
                    }.padding(.top, 14)
                }
            }
            PrivacyNote()
        }
        .confirmationDialog("Return to observation?", isPresented: $showObservationConfirmation) {
            Button("Return to observation") { Task { await setMode("protect", confirmation: "") } }
            Button("Cancel", role: .cancel) {}
        } message: {
            Text("Guardian stops automatic Inbox moves. A new observation period starts and permanent deletion is disabled.")
        }
        .sheet(isPresented: $showActivation) {
            VStack(alignment: .leading, spacing: 20) {
                Label("Enable mail cleanup", systemImage: "checkmark.shield").font(.title2.bold())
                Text("Guardian will quarantine confident Inbox spam and rescue legitimate messages from spam. Permanent deletion remains disabled.")
                if let failure = model.failure {
                    Label(failure.message, systemImage: "exclamationmark.triangle")
                        .foregroundStyle(.red).fixedSize(horizontal: false, vertical: true)
                    if let recovery = failure.recovery { Text(recovery).font(.callout).foregroundStyle(.secondary) }
                }
                if model.snapshotIsStale {
                    Text("Confirm the current protection status before retrying.").font(.callout).foregroundStyle(.secondary)
                    Button("Refresh protection status") { Task { await model.refresh() } }.disabled(model.busy)
                }
                Text("To confirm, type ACTIVE.").font(.callout)
                TextField("Confirm ACTIVE", text: $activeConfirmation).textFieldStyle(.roundedBorder)
                HStack {
                    Button("Cancel", role: .cancel) { showActivation = false }.keyboardShortcut(.cancelAction).disabled(model.busy)
                    Spacer()
                    Button("Enable cleanup") {
                        Task {
                            if await setMode("active", confirmation: activeConfirmation) { showActivation = false }
                        }
                    }.buttonStyle(.borderedProminent).disabled(activeConfirmation != "ACTIVE" || model.busy || model.snapshotIsStale || model.snapshot.protection?.ready != true)
                }
            }.padding(28).frame(width: 480).interactiveDismissDisabled(model.busy)
        }
    }
    @discardableResult
    private func setMode(_ value: String, confirmation: String) async -> Bool {
        let completed = await model.perform("Changing protection mode…") {
            let _: EmptyPayload = try await Backend.call(["mode"], input: ["value": value, "confirm": confirmation])
            return value == "active" ? "Cleanup enabled. Permanent deletion remains disabled." : "A new observation period started."
        }
        if completed { activeConfirmation = "" }
        return completed
    }
    private func setPurge(_ value: String, confirmation: String) async {
        let completed = await model.perform {
            let _: EmptyPayload = try await Backend.call(["purge"], input: ["value": value, "confirm": confirmation])
            return "Permanent-deletion setting changed."
        }
        if completed { purgeConfirmation = "" }
    }
}

struct HelpView: View {
    @ObservedObject var model: GuardianModel
    var body: some View {
        GuardianPage(eyebrow: "Help with everyday situations", title: "Help", subtitle: "Start with the situation you want to resolve.") {
            GuardianCard {
                Label("An important email disappeared", systemImage: "envelope.badge").font(.headline)
                Text("Check spam, \(model.snapshot.folders.quarantine) and \(model.snapshot.folders.review) in your email client. Move legitimate mail to \(model.snapshot.folders.trainHam). If missing, look for a local backup.").foregroundStyle(.secondary)
                Button("Open recovery", systemImage: "arrow.right") { model.section = .archive }
            }
            GuardianCard {
                Label("Spam remains in Inbox", systemImage: "hand.thumbsdown").font(.headline)
                Text("This is expected during observation: Guardian does not automatically move Inbox messages. Mark spam using the training folder.").foregroundStyle(.secondary)
                Button("Show correction instructions", systemImage: "arrow.right") { model.section = .learning }
            }
            GuardianCard {
                Label("Protection is not working as expected", systemImage: "wrench.and.screwdriver").font(.headline)
                Text("Repair checks the local engine and configuration. A full check also inspects the account and folders.").foregroundStyle(.secondary)
                HStack {
                    Button("Check and repair") { Task { await model.repair() } }.buttonStyle(.borderedProminent)
                    Button("Full check") { Task { await model.deepDoctor() } }
                }.disabled(model.busy)
            }
            GuardianCard {
                Label("Support report", systemImage: "doc.text").font(.headline)
                Text("Excludes messages, addresses, subjects, attachments and passwords. The report is saved to Desktop; you choose whom to share it with.").foregroundStyle(.secondary)
                Button("Save report to Desktop") { Task { await model.exportDiagnostics() } }.disabled(model.busy)
            }
            PrivacyNote()
        }
    }
}
