import AppKit
import SwiftUI

struct LearningView: View {
    @ObservedObject var model: GuardianModel
    @State private var copiedFolder: String?
    var body: some View {
        GuardianPage(eyebrow: "Ocena wiadomości", title: "Sprawdź i popraw", subtitle: "Trzy kroki: otwórz pocztę, przenieś wiadomość, przetwórz korektę.") {
            GuardianCard {
                Label("1. Otwórz wiadomości do sprawdzenia", systemImage: "tray.full").font(.headline)
                Text("Otwórz folder AI-Do-sprawdzenia w poczcie o2. Gdy rozpoznasz wiadomość, przenieś ją do jednego z folderów poniżej. Jeśli nie masz pewności, pozostaw ją do późniejszej oceny.")
                    .foregroundStyle(.secondary)
                HStack {
                    Link("Otwórz pocztę o2", destination: URL(string: "https://poczta.o2.pl/")!)
                        .buttonStyle(.borderedProminent).controlSize(.large)
                    Button("Przetwórz już przeniesione korekty") { Task { await model.runNow() } }.disabled(model.busy)
                }
                Text("Poczta otworzy się w przeglądarce. Wybierz folder AI-Do-sprawdzenia. Przetwarzanie uruchamia pełne sprawdzenie zgodnie z bieżącym trybem.").font(.callout).foregroundStyle(.secondary)
            }
            HStack {
                Text("2. Wybierz właściwy folder w poczcie o2").font(.headline)
            }
            correctionCard("To ważna wiadomość", symbol: "hand.thumbsup", folder: "AI-Naucz-wazne", detail: "Użyj, gdy prawidłowa wiadomość trafiła do SPAM-u, kwarantanny lub folderu Do sprawdzenia.", result: "Po udanej nauce Guardian przeniesie ją do Odebranych. Twoja korekta blokuje jej automatyczne usunięcie.", count: model.snapshot.trainedHam)
            correctionCard("To jest spam", symbol: "hand.thumbsdown", folder: "AI-Naucz-spam", detail: "Użyj, gdy niechciana wiadomość pozostała w Odebranych lub czeka na Twoją ocenę.", result: "Po udanej nauce Guardian przeniesie ją do kwarantanny.", count: model.snapshot.trainedSpam)
            GuardianCard {
                Text("3. Przetwórz korekty").font(.headline)
                Text(model.snapshot.automation == "on" ? "Korekty zostaną przetworzone przy następnym automatycznym sprawdzeniu. Możesz też uruchomić je teraz." : "Automat jest wyłączony. Po przeniesieniu wiadomości uruchom sprawdzanie przyciskiem poniżej.").foregroundStyle(.secondary)
                Button("Sprawdź pocztę i przetwórz korekty") { Task { await model.runNow() } }.buttonStyle(.borderedProminent).controlSize(.large).disabled(model.busy)
                Text("Sprawdzanie obejmuje także pozostałą pocztę, zgodnie z bieżącym trybem ochrony.").font(.caption).foregroundStyle(.secondary)
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
                Text("Korekty: \(count)").font(.caption).foregroundStyle(.secondary)
            }
            Text(detail).foregroundStyle(.secondary)
            HStack {
                Text(folder).font(.system(.body, design: .monospaced)).textSelection(.enabled)
                Spacer()
                Button(copiedFolder == folder ? "Skopiowano" : "Kopiuj nazwę", systemImage: copiedFolder == folder ? "checkmark" : "doc.on.doc") {
                    NSPasteboard.general.clearContents()
                    NSPasteboard.general.setString(folder, forType: .string)
                    copiedFolder = folder
                }.help("Kopiuj nazwę folderu do schowka")
                .accessibilityLabel(copiedFolder == folder ? "Skopiowano nazwę folderu \(folder)" : "Kopiuj nazwę folderu \(folder)")
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
        GuardianPage(eyebrow: "Bezpieczny powrót", title: "Odzyskiwanie wiadomości", subtitle: "Znajdź kopię, sprawdź nadawcę i temat, a potem przywróć wiadomość.") {
            HStack {
                Picker("Pokaż", selection: $model.archiveFilter) {
                    Text("Wszystkie kopie").tag("all")
                    Text("Kwarantanna").tag("quarantined")
                    Text("Do sprawdzenia").tag("review")
                    Text("Przywrócone").tag("restored")
                }.frame(maxWidth: 280).disabled(model.busy)
                Spacer()
                Button("Odśwież", systemImage: "arrow.clockwise") { Task { await reload() } }.disabled(model.busy)
            }
            VStack(alignment: .leading, spacing: 12) {
                Toggle("Zawęź datę pierwszego zapisu", isOn: $useDateRange).disabled(model.busy)
                if useDateRange {
                    HStack {
                        DatePicker("Od", selection: $fromDate, displayedComponents: .date)
                            .environment(\.locale, Locale(identifier: "pl_PL"))
                            .disabled(model.busy)
                        DatePicker("Do", selection: $throughDate, displayedComponents: .date)
                            .environment(\.locale, Locale(identifier: "pl_PL"))
                            .disabled(model.busy)
                        Button("Zastosuj daty") { Task { await applyDateRange() } }
                            .disabled(model.busy || Calendar.current.startOfDay(for: fromDate) > Calendar.current.startOfDay(for: throughDate))
                    }
                    if Calendar.current.startOfDay(for: fromDate) > Calendar.current.startOfDay(for: throughDate) {
                        Text("Data Od nie może być późniejsza niż Do.").foregroundStyle(.red).font(.callout)
                    }
                    Text(model.archiveDateRange.isEmpty ? "Wybierz daty i zastosuj filtr. Lista nadal pokazuje wszystkie daty." : "Lista dla okresu: \(appliedDateLabel). Po zmianie dat kliknij Zastosuj daty.")
                        .font(.callout).foregroundStyle(.secondary)
                }
            }
            Text("Lista pokazuje datę pierwszego zapisu. Wybierz wpis i odsłoń nagłówki, aby rozpoznać wiadomość.")
                .font(.callout).foregroundStyle(.secondary)
            if !model.archiveLoaded {
                GuardianCard {
                    EmptyState(symbol: "tray", title: model.busy ? "Wczytuję kopie…" : "Nie udało się odczytać kopii", detail: model.busy ? "Odczytujemy tylko listę. Treść wiadomości pozostaje zaszyfrowana." : "Spróbuj ponownie. Twoje kopie nie zostały zmienione.")
                    if !model.busy { Button("Spróbuj ponownie") { Task { await reload() } } }
                }
            } else if model.archivePage.items.isEmpty {
                GuardianCard {
                    if model.archivePage.page > 1 {
                        EmptyState(symbol: "tray", title: "Na tej stronie nie ma już kopii", detail: "Zawartość archiwum mogła się zmienić. Wróć do początku listy, zachowując wybrane filtry.")
                        Button("Wróć do pierwszej strony") { Task { await changePage(1) } }.disabled(model.busy)
                    } else {
                    EmptyState(symbol: "tray", title: !model.archiveDateRange.isEmpty ? "Brak kopii w wybranym okresie" : (model.archiveFilter == "all" ? "Nie ma jeszcze kopii" : "Brak kopii w tej kategorii"), detail: !model.archiveDateRange.isEmpty ? "Zmień daty lub wyłącz filtr dat, aby poszukać pozostałych kopii." : (model.archiveFilter == "all" ? "Kopie pojawią się tutaj, gdy Guardian zabezpieczy wiadomości. Niczego nie musisz teraz odzyskiwać." : "Wybierz inną kategorię, aby zobaczyć pozostałe kopie."))
                    }
                    HStack {
                        if !model.archiveDateRange.isEmpty {
                            Button("Wyłącz filtr dat") { useDateRange = false }.disabled(model.busy)
                        }
                        if model.archiveFilter != "all" {
                            Button("Pokaż wszystkie kategorie") { model.archiveFilter = "all" }.disabled(model.busy)
                        }
                    }
                }
            } else {
                HStack(alignment: .top, spacing: 16) {
                    VStack(alignment: .leading, spacing: 8) {
                        Text("ZAPISANE KOPIE").font(.system(size: 10, weight: .semibold)).tracking(1.2).foregroundStyle(.secondary).padding(.horizontal, 10)
                        ForEach(model.archivePage.items) { item in
                            Button {
                                selected = item
                                preview = nil
                                previewedID = nil
                            } label: {
                                VStack(alignment: .leading, spacing: 7) {
                                    Text(friendlyDate(item.date)).font(.callout.weight(.semibold))
                                    Text(archiveStatusLabel(item.status).capitalized).font(.caption).foregroundStyle(.secondary)
                                    Text("Kopia \(item.id) · \(archiveVerdictLabel(item.verdict))").font(.caption2).foregroundStyle(.secondary)
                                }.frame(maxWidth: .infinity, alignment: .leading).padding(12)
                                    .background(selected?.id == item.id ? GuardianStyle.accent.opacity(0.12) : GuardianStyle.surface, in: RoundedRectangle(cornerRadius: 10))
                                    .overlay(RoundedRectangle(cornerRadius: 10).strokeBorder(selected?.id == item.id ? GuardianStyle.accent.opacity(0.4) : .clear))
                                    .contentShape(Rectangle())
                            }.buttonStyle(.plain).disabled(model.busy)
                                .accessibilityHint("Wybierz kopię. Nadawcę i temat odsłonisz osobnym przyciskiem.")
                                .accessibilityAddTraits(selected?.id == item.id ? .isSelected : [])
                        }
                    }.frame(width: 220)
                    GuardianCard {
                        if let selected {
                            HStack {
                                Text("Kopia \(selected.id)").font(.headline)
                                Spacer()
                                Label("Lokalna kopia", systemImage: "lock").font(.caption).foregroundStyle(.secondary)
                            }
                            if let preview, previewedID == selected.id {
                                header("OD", value: preview.from)
                                header("TEMAT", value: preview.subject)
                                header("DATA WIADOMOŚCI", value: preview.date)
                                Divider()
                                Text("Po przywróceniu znajdziesz wiadomość w folderze AI-Do-sprawdzenia w poczcie o2.").font(.callout).foregroundStyle(.secondary)
                                Button("Przywróć wiadomość", systemImage: "tray.and.arrow.up") {
                                    confirmationItem = selected
                                    showingRestoreConfirmation = true
                                }.buttonStyle(.borderedProminent).controlSize(.large).disabled(!canRestore)
                                    .accessibilityHint("Otwiera potwierdzenie przywrócenia wybranej kopii do folderu Do sprawdzenia.")
                            } else {
                                Text("Odsłoń nadawcę, temat i datę, aby sprawdzić, czy to szukana wiadomość.").foregroundStyle(.secondary)
                                Button("Pokaż nadawcę i temat") { Task { await loadPreview(selected) } }.buttonStyle(.borderedProminent).disabled(model.busy)
                            }
                            HStack {
                                Button("Poprzednia kopia", systemImage: "chevron.up") { selectNeighbor(-1) }
                                    .disabled(model.busy || selectedIndex == nil || selectedIndex == 0)
                                    .accessibilityHint("Wybiera poprzedni wpis na tej stronie i ukrywa nagłówki.")
                                Button("Następna kopia", systemImage: "chevron.down") { selectNeighbor(1) }
                                    .disabled(model.busy || selectedIndex == nil || selectedIndex == model.archivePage.items.count - 1)
                                    .accessibilityHint("Wybiera następny wpis na tej stronie i ukrywa nagłówki.")
                            }
                            Text("Bez otwierania treści, linków i załączników.").font(.caption).foregroundStyle(.secondary)
                        } else {
                            EmptyState(symbol: "sidebar.left", title: "Wybierz kopię z listy", detail: "Tutaj zobaczysz bezpieczny podgląd. Przywrócenie będzie wymagać Twojego potwierdzenia.")
                        }
                    }.frame(maxWidth: .infinity)
                }
            }
            HStack {
                Button("Poprzednia", systemImage: "chevron.left") { Task { await changePage(max(1, model.archivePage.page - 1)) } }.disabled(!model.archiveLoaded || model.archivePage.page <= 1 || model.busy)
                Spacer()
                Text("Strona \(model.archivePage.page)").font(.caption).foregroundStyle(.secondary)
                Spacer()
                Button("Następna", systemImage: "chevron.right") { Task { await changePage(model.archivePage.page + 1) } }.disabled(!model.archiveLoaded || !model.archivePage.hasNext || model.busy)
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
        .confirmationDialog("Przywrócić kopię \(confirmationItem?.id ?? 0)?", isPresented: $showingRestoreConfirmation) {
            Button("Przywróć do AI-Do-sprawdzenia") {
                if let item = confirmationItem, item.id == previewedID, item.id == selected?.id {
                    Task {
                        await model.restoreArchive(id: item.id)
                        preview = nil
                        previewedID = nil
                    }
                }
            }
            Button("Anuluj", role: .cancel) { confirmationItem = nil }
        } message: {
            Text("Guardian utworzy kopię w folderze AI-Do-sprawdzenia. Sprawdzisz ją w poczcie o2. Żadna wiadomość nie zostanie wysłana.")
        }
    }
    private var appliedDateLabel: String {
        guard model.archiveDateRange.count == 2 else { return "" }
        let parser = ISO8601DateFormatter()
        guard let start = parser.date(from: model.archiveDateRange[0]), let end = parser.date(from: model.archiveDateRange[1]) else { return "" }
        let formatter = DateFormatter()
        formatter.locale = Locale(identifier: "pl_PL")
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
            Text(value.isEmpty ? "Brak informacji" : value).textSelection(.enabled).fixedSize(horizontal: false, vertical: true)
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
        GuardianPage(eyebrow: "Na Twoich zasadach", title: "Ustawienia ochrony", subtitle: "Zdecyduj, kiedy Guardian sprawdza pocztę i co może z nią robić.") {
            GuardianCard {
                Label("Automatyczne sprawdzanie", systemImage: "clock.arrow.circlepath").font(.headline)
                Toggle("Sprawdzaj pocztę co 2 godziny", isOn: Binding(get: { model.snapshot.automation == "on" }, set: { value in Task { await model.setAutomation(value) } }))
                    .toggleStyle(.switch).disabled(model.busy || !model.snapshot.firstDryRun)
                Text("Zamknięcie okna nie zatrzymuje automatu. Wyłącz tę opcję, jeśli chcesz sprawdzać pocztę tylko na żądanie.").font(.callout).foregroundStyle(.secondary)
            }
            GuardianCard {
                Label("Przenoszenie wiadomości", systemImage: "tray.2").font(.headline)
                if model.snapshot.mode == "active" {
                    Text("Automatyczne porządkowanie włączone").font(.title3.weight(.semibold))
                    Text("Pewny spam trafia do kwarantanny, a ważne wiadomości z folderu SPAM wracają do Odebranych. Przypadki niepewne czekają na Twoją ocenę.").foregroundStyle(.secondary)
                    Button("Wróć do obserwacji") { showObservationConfirmation = true }.disabled(model.busy)
                } else {
                    Text("Odebrane pozostają bez zmian").font(.title3.weight(.semibold))
                    Text("W okresie obserwacji wiadomości z folderu SPAM mogą trafiać do AI-Do-sprawdzenia. Twoje korekty nadal są przetwarzane.").foregroundStyle(.secondary)
                    Divider()
                    ProtectionProgressView(model: model)
                    HStack {
                        Button("Włącz porządkowanie…") { activeConfirmation = ""; model.failure = nil; showActivation = true }
                            .buttonStyle(.borderedProminent).disabled(model.busy || model.snapshotIsStale || model.snapshot.protection?.ready != true)
                        Button("Przejdź do nauki") { model.section = .learning }
                    }
                }
                Button("Sprawdź ponownie jakość filtra") { Task { await model.qualifyFilter() } }.disabled(model.busy || model.snapshotIsStale)
                Text("Ponowna ocena uczy osobny model i sprawdza go na innych wiadomościach. Zachowuje historię, a wynik nie włącza porządkowania bez Twojego potwierdzenia.").font(.caption).foregroundStyle(.secondary)
            }
            GuardianCard {
                Label("Aplikacja i konto", systemImage: "person.crop.circle").font(.headline)
                Toggle("Uruchamiaj panel po zalogowaniu do Maca", isOn: Binding(get: { model.snapshot.appAutostart }, set: { value in Task { await model.setAppAutostart(value) } })).toggleStyle(.switch).disabled(model.busy)
                Text("Ta opcja dotyczy okna i ikony w pasku menu. Harmonogram sprawdzania ustawiasz osobno powyżej.").font(.callout).foregroundStyle(.secondary)
                Divider()
                Button("Zmień dane konta lub hasło…") { model.reconfigure = true }.disabled(model.busy)
                Text("Zmiana danych zatrzyma automat i będzie wymagać ponownej bezpiecznej próby. Hasło przechowujemy w pęku kluczy macOS.").font(.callout).foregroundStyle(.secondary)
            }
            GuardianCard {
                DisclosureGroup("Zaawansowane: trwałe usuwanie", isExpanded: $showAdvancedSafety) {
                    VStack(alignment: .leading, spacing: 12) {
                        Label(model.snapshot.purgeEnabled ? "Trwałe usuwanie włączone" : "Trwałe usuwanie wyłączone", systemImage: "trash").font(.headline)
                        Text("To osobne uprawnienie. Zwykłe porządkowanie nie wymaga usuwania wiadomości. Włączenie nadal podlega okresom ochronnym i kontrolom jakości.").foregroundStyle(.secondary)
                        if model.snapshot.purgeEnabled {
                            Button("Wyłącz trwałe usuwanie") { Task { await setPurge("disable", confirmation: "") } }.disabled(model.busy)
                        } else {
                            Text("Aby zezwolić na trwałe usuwanie po kontrolach, wpisz WLACZ.").font(.callout)
                            TextField("Potwierdzenie WLACZ", text: $purgeConfirmation).textFieldStyle(.roundedBorder)
                            Button("Włącz trwałe usuwanie", role: .destructive) { Task { await setPurge("enable", confirmation: purgeConfirmation) } }.disabled(purgeConfirmation != "WLACZ" || model.busy)
                        }
                    }.padding(.top, 14)
                }
            }
            PrivacyNote()
        }
        .confirmationDialog("Wrócić do obserwacji?", isPresented: $showObservationConfirmation) {
            Button("Wróć do obserwacji") { Task { await setMode("protect", confirmation: "") } }
            Button("Anuluj", role: .cancel) {}
        } message: {
            Text("Guardian przestanie automatycznie przenosić wiadomości z Odebranych. Rozpocznie nowy okres obserwacji, a trwałe usuwanie zostanie wyłączone.")
        }
        .sheet(isPresented: $showActivation) {
            VStack(alignment: .leading, spacing: 20) {
                Label("Włącz porządkowanie poczty", systemImage: "checkmark.shield").font(.title2.bold())
                Text("Guardian będzie przenosić pewny spam z Odebranych do kwarantanny i ratować ważne wiadomości z folderu SPAM. Trwałe usuwanie pozostanie wyłączone.")
                if let failure = model.failure {
                    Label(failure.message, systemImage: "exclamationmark.triangle")
                        .foregroundStyle(.red).fixedSize(horizontal: false, vertical: true)
                    if let recovery = failure.recovery { Text(recovery).font(.callout).foregroundStyle(.secondary) }
                }
                if model.snapshotIsStale {
                    Text("Przed ponowieniem potwierdź aktualny stan ochrony.").font(.callout).foregroundStyle(.secondary)
                    Button("Odśwież stan ochrony") { Task { await model.refresh() } }.disabled(model.busy)
                }
                Text("Aby potwierdzić, wpisz AKTYWNY.").font(.callout)
                TextField("Potwierdzenie AKTYWNY", text: $activeConfirmation).textFieldStyle(.roundedBorder)
                HStack {
                    Button("Anuluj", role: .cancel) { showActivation = false }.keyboardShortcut(.cancelAction).disabled(model.busy)
                    Spacer()
                    Button("Włącz porządkowanie") {
                        Task {
                            if await setMode("active", confirmation: activeConfirmation) { showActivation = false }
                        }
                    }.buttonStyle(.borderedProminent).disabled(activeConfirmation != "AKTYWNY" || model.busy || model.snapshotIsStale || model.snapshot.protection?.ready != true)
                }
            }.padding(28).frame(width: 480).interactiveDismissDisabled(model.busy)
        }
    }
    @discardableResult
    private func setMode(_ value: String, confirmation: String) async -> Bool {
        let completed = await model.perform("Zmieniam tryb ochrony…") {
            let _: EmptyPayload = try await Backend.call(["mode"], input: ["value": value, "confirm": confirmation])
            return value == "active" ? "Porządkowanie włączone. Trwałe usuwanie pozostaje wyłączone." : "Włączono nowy okres obserwacji."
        }
        if completed { activeConfirmation = "" }
        return completed
    }
    private func setPurge(_ value: String, confirmation: String) async {
        let completed = await model.perform {
            let _: EmptyPayload = try await Backend.call(["purge"], input: ["value": value, "confirm": confirmation])
            return "Zmieniono ustawienie trwałego usuwania."
        }
        if completed { purgeConfirmation = "" }
    }
}

struct HelpView: View {
    @ObservedObject var model: GuardianModel
    var body: some View {
        GuardianPage(eyebrow: "Pomoc w codziennych sytuacjach", title: "Pomoc", subtitle: "Zacznij od sytuacji, którą chcesz rozwiązać.") {
            GuardianCard {
                Label("Ważny e-mail zniknął", systemImage: "envelope.badge").font(.headline)
                Text("Sprawdź foldery SPAM, AI-Kwarantanna i AI-Do-sprawdzenia w poczcie o2. Ważną wiadomość przenieś do AI-Naucz-wazne. Jeśli jej nie ma, poszukaj lokalnej kopii.").foregroundStyle(.secondary)
                Button("Przejdź do odzyskiwania", systemImage: "arrow.right") { model.section = .archive }
            }
            GuardianCard {
                Label("Spam nadal jest w Odebranych", systemImage: "hand.thumbsdown").font(.headline)
                Text("W trybie obserwacji to zamierzone: Guardian nie przenosi automatycznie wiadomości z Odebranych. Możesz wskazać spam w folderze nauki.").foregroundStyle(.secondary)
                Button("Pokaż instrukcję korekt", systemImage: "arrow.right") { model.section = .learning }
            }
            GuardianCard {
                Label("Ochrona nie działa zgodnie z oczekiwaniami", systemImage: "wrench.and.screwdriver").font(.headline)
                Text("Naprawa sprawdzi lokalny silnik i konfigurację. Pełna kontrola dodatkowo sprawdzi konto oraz foldery.").foregroundStyle(.secondary)
                HStack {
                    Button("Sprawdź i napraw") { Task { await model.repair() } }.buttonStyle(.borderedProminent)
                    Button("Pełna kontrola") { Task { await model.deepDoctor() } }
                }.disabled(model.busy)
            }
            GuardianCard {
                Label("Raport dla osoby pomagającej", systemImage: "doc.text").font(.headline)
                Text("Bez wiadomości, adresów, tematów, załączników i haseł. Raport zostanie zapisany na Biurku; sam zdecydujesz, komu go przekażesz.").foregroundStyle(.secondary)
                Button("Zapisz raport na Biurku") { Task { await model.exportDiagnostics() } }.disabled(model.busy)
            }
            PrivacyNote()
        }
    }
}
