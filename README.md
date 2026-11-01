# O2 Mail Guardian

**Wersja źródłowa 0.6.1 — 1 listopada 2026 r.** Guardian zawiera aplikację
macOS oraz worker Linux z systemd, szyfrowanymi kopiami, odzyskiwaniem,
monitoringiem i kontrolowanymi aktualizacjami. Ostatnia poprawka wzmacnia
potwierdzanie ruchu IMAP, gdy serwer nie zwraca docelowego UID.

| Potrzebujesz | Zacznij tutaj |
| --- | --- |
| Instalacja i codzienna obsługa | Instrukcja poniżej i [instrukcja instalacji](docs/INSTALACJA.md) |
| Dokumentacja projektu i status funkcji | [Mapa dokumentacji](docs/README.md) |
| Rozwój, testy i wymagane kontrole | [CONTRIBUTING.md](CONTRIBUTING.md) |
| Architektura, granice uprawnień i bezpieczeństwo poczty | [Architektura dla developerów](docs/maintainers/ARCHITECTURE.md) |
| Serwer, monitoring, backup i awaria | [Przewodnik operacyjny](docs/maintainers/OPERATIONS.md) |
| Codzienne aktualizacje i przegląd nowych wersji | [Konserwacja VPS](ops/vps-maintenance/README.md) |
| Publikacja i zgodność źródeł z wdrożeniem | [Proces wydania](docs/maintainers/RELEASING.md) |

Linux obsługuje prywatne hosty Ubuntu amd64; szczegółowe wymagania i zakres
sprawdzeń poszczególnych wydań opisuje [instrukcja wdrożenia](deploy/linux/README.md).
Nowy instalator pozostawia harmonogram wyłączony. Samo pobranie źródeł,
budowanie lub opublikowanie wydania nie uruchamia dostępu do poczty.
Jedna skrzynka ma jednego aktywnego pracownika. Po migracji na VPS stary Mac
pozostaje panelem kontrolnym; nie wznawiaj jego nieaktualnego stanu.

Lokalny strażnik poczty o2.pl, który pomaga w obu najbardziej uciążliwych
sytuacjach:

- przenosi bardzo prawdopodobny spam z Odebranych do 30-dniowej kwarantanny;
- ratuje prawidłowe wiadomości błędnie umieszczone przez o2 w folderze SPAM;
- odkłada niejednoznaczne przypadki do ręcznego sprawdzenia;
- uczy się na podstawie dwóch prostych folderów: „to jest spam” i „to jest
  ważne”.

Program przetwarza wiadomości na wybranym Macu lub prywatnym serwerze Linux.
Nie korzysta z LLM, nie otwiera linków ani załączników i nie wysyła treści
wiadomości do zewnętrznych usług analizy. Publiczna
usługa fuzzy Rspamd jest wyłączona — skróty treści wiadomości również nie
trafiają do zewnętrznej bazy fuzzy.

> **Najważniejsze:** przez pierwsze 14 dni Guardian nie przenosi automatycznie
> wiadomości z Odebranych. Wiadomości z folderu SPAM mogą trafiać do
> `AI-Do-sprawdzenia`, a Twoje korekty są przetwarzane. Trwałe usuwanie jest wyłączone. Nie zmieniaj ustawień
> zaawansowanych, dopóki aplikacja nie potwierdzi zakończenia okresu obserwacji
> i wszystkich kontroli jakości.

Sam upływ 14 dni nie włącza porządkowania. Obecne kryteria zawierają
historyczne blokady. W Ustawieniach wybierz **Sprawdź ponownie jakość filtra**:
Guardian nauczy osobny model i oceni go na innych wiadomościach. Pomyślny
raport potwierdza aktualną jakość bez wymazywania dawnej historii.
Bayes zaczyna klasyfikować dopiero po osiągnięciu `min_learns` w **obu**
klasach; przy domyślnym ustawieniu potrzeba 100 przykładów statystycznych spamu i 100 ważnych. Trwałe usuwanie nadal
wymaga co najmniej 200/200 i dodatkowych kontroli.
Przykłady muszą odzwierciedlać rzeczywiste oceny użytkownika.

## Najprostszy start

### 1. Przygotuj konto o2

1. Zaloguj się do poczty o2 w przeglądarce.
2. Włącz dostęp IMAP: **Opcje → IMAP/POP → Włącz IMAP**.
3. Włącz logowanie dwustopniowe i zapisz klucze awaryjne.
4. Utwórz osobne hasło do programu pocztowego o nazwie np.
   `O2 Mail Guardian – Mac`.

Nie podawaj programowi zwykłego hasła do poczty. Szczegółowa instrukcja krok
po kroku znajduje się w
[instrukcji instalacji](docs/INSTALACJA.md).

### 2. Uruchom instalator

Jeżeli nie jesteś programistą, zacznij właśnie tutaj — nie trzeba wcześniej
otwierać Terminala ani wpisywać poleceń. Jeżeli otrzymałeś plik
**`O2-Mail-Guardian-0.6.1-macos-arm64.zip`**, rozpakuj go i otwórz powstały folder. Są w
nim tylko instrukcja, licencja i instalator; techniczne składniki są celowo
ukryte. W Finderze kliknij dwukrotnie **`Install.command`**. Instalator:

- sprawdzi wymagania;
- zainstaluje potrzebne lokalne składniki;
- uruchomi bezpieczny stos Rspamd;
- sprawdzi sumy plików, podpisy i samokontrolę gotowych programów;
- zainstaluje ją jako `~/Applications/O2 Mail Guardian.app`;
- otworzy graficzny kreator konfiguracji.

Po jednym potwierdzeniu zobaczysz tylko krótkie komunikaty o kolejnych etapach.
Szczegóły techniczne są zapisywane w prywatnym pliku
`~/Library/Logs/O2 Mail Guardian/instalacja.log`; nie trzeba ich śledzić ani
rozumieć. Przy pierwszej instalacji macOS może poprosić o hasło administratora,
ale instalator nigdy nie pyta w Terminalu o hasło do poczty.

Jeżeli macOS nie pozwoli otworzyć pliku, kliknij go z naciśniętym klawiszem
Control, wybierz **Otwórz**, a następnie ponownie **Otwórz**. Nie wyłączaj
globalnie zabezpieczeń macOS.

Ten sam `Install.command` służy do bezpiecznej aktualizacji. Jeśli działająca
konfiguracja już istnieje, instalator zachowuje konto, hasło w pęku kluczy,
bazę, archiwum i ustawienie automatycznej usługi. Nie uruchamia ponownie
kreatora hasła. Najpierw weryfikuje gotowe programy wersji 0.6.1, a backend,
aplikację i konfigurację silnika podmienia dopiero po walidacji. Po awarii
podejmuje przywracanie poprzedniego kompletu. Jeśli przywracanie się nie uda,
zachowuje kopie i prosi o pomoc zamiast potwierdzać sukces.

Paczka jest przeznaczona dla **Apple Silicon i macOS 13 lub nowszego**.
Nie kompiluje Guardiana i nie instaluje Go. Homebrew oraz lokalny silnik
mogą nadal wymagać narzędzi Apple i dostępu do internetu. Instalacja ze źródeł
w repozytorium zachowuje budowanie Go/Swift.

Programy mają lokalny podpis ad hoc, bez Developer ID i notaryzacji Apple.
Nie wyłączaj zabezpieczeń systemu ani nie usuwaj automatycznie kwarantanny.
Obok ZIP-a znajduje się plik `.sha256` do sprawdzenia pobrania; sumy kontrolne
wykrywają uszkodzenie plików, ale nie potwierdzają tożsamości wydawcy.

Wynik „Program zainstalowany — ochrona wymaga uwagi” oznacza, że pliki są
zainstalowane, lecz kontrola, wznowienie harmonogramu lub otwarcie aplikacji
wymaga sprawdzenia. Nie oznacza aktywnej ochrony skrzynki.

### 3. Przejdź przez kreator

Przygotuj:

- pełny adres e-mail o2;
- jednorazowo wyświetlone hasło do programu pocztowego;
- około 10 minut.

Graficzny kreator ma trzy krótkie ekrany: dane konta, automatycznie wykryte
bezpieczne ustawienia oraz obowiązkową próbę bez zmian. Folder SPAM wybierasz
ręcznie tylko wtedy, gdy automat wykrył go błędnie. Hasło płynie do backendu
wyłącznie przez stdin i trafia do pęku
kluczy macOS; nie pojawia się w argumentach, konfiguracji, odpowiedzi JSON ani
logu. Automat co 2 godziny zostanie włączony dopiero po udanej próbie i
kliknięciu **Włącz sprawdzanie co 2 godziny**. Alternatywnie można zakończyć
kreator w trybie ręcznym; wtedy nic nie działa w tle, a sprawdzenie uruchamiasz
samodzielnie z pulpitu aplikacji.

Późniejsza zmiana hasła albo folderu SPAM również zatrzymuje automat,
wraca do trybu ochronnego i wymaga nowego dry-run. Wcześniejsze potwierdzenie
nie jest przenoszone na zmienioną konfigurację.

### 4. Otwieraj aplikację

Po instalacji aplikację znajdziesz w folderze **Aplikacje** w swoim katalogu
domowym. Ma normalne okno i ikonę w pasku menu. Wyraźnie odróżnia
**Odebrane pod obserwacją**, **Porządkowanie jest włączone**, tryb ręczny
oraz stany wymagające uwagi. Przegląd pokazuje efekty sprawdzania, następne
działanie i postęp przygotowania do porządkowania. Szczegóły nowego interfejsu
znajdziesz w [instrukcji panelu](docs/GUI-I-PIERWSZE-KROKI.md).

Dwukrotne kliknięcie **`Guardian.command`** również otwiera aplikację. Dwa
dodatkowe skróty pozostają interfejsem awaryjnym:

- **`Uruchom-teraz.command`** — natychmiastowe bezpieczne sprawdzenie poczty;
- **`Sprawdz-stan.command`** — raport z ostatnich 24 godzin.

Awaryjne menu tekstowe można otworzyć w Terminalu:

```bash
guardian menu
```

GUI prowadzi przez sprawdzenie stanu, naukę, naprawę i odzyskiwanie wiadomości.
Jego wyłączenie przy logowaniu nie zatrzymuje niezależnej usługi skanującej.
Jeśli chcesz jedynie sprawdzić, czy wszystko działa:

```bash
guardian doctor
guardian doctor --deep
guardian status
```

## Codzienna obsługa

Po instalacji robot może działać automatycznie co 2 godziny. Użytkownik
potrzebny jest tylko przy pomyłkach:

| Sytuacja | Co zrobić w poczcie o2 |
|---|---|
| Spam pozostał w Odebranych | Przenieś go do `AI-Naucz-spam` |
| Ważna wiadomość trafiła do SPAM-u, kwarantanny lub sprawdzenia | Przenieś ją do `AI-Naucz-wazne` |
| Nie masz pewności | Pozostaw ją w `AI-Do-sprawdzenia` |
| Chcesz tylko podejrzeć zatrzymany spam | Otwórz `AI-Kwarantanna`; niczego nie klikaj w wiadomości |

Przy następnym przebiegu Guardian zapisze Twoją korektę i spróbuje nauczyć
Rspamd poprawnej klasyfikacji. Po udanym uczeniu przeniesie ważną wiadomość
do Odebranych albo spam do kwarantanny. Jeśli Rspamd jawnie pominie uczenie
zgodnie ze swoimi warunkami (HTTP 204), Guardian zachowa korektę dla dokładnie
tej wiadomości i również ją przeniesie, ale nie zwiększy licznika przykładów
Bayesa. Błąd połączenia lub brak prawidłowego potwierdzenia pozostawia
wiadomość w folderze uczącym do ponownej próby.

Wadliwe kodowanie MIME nie jest poprawiane przez przepisywanie wiadomości.
Jeśli sam przeniesiesz taki oryginał do folderu nauki, Guardian zachowa jego
zaszyfrowaną kopię i Twoją korektę, a następnie przeniesie oryginał zgodnie
z wybranym folderem. Pominie uczenie Bayesa i nie zwiększy jego liczników.

Lista **Zaufani** w o2 działa wyłącznie po stronie o2. Guardian jej nie
odczytuje i nie używa jej jako sygnału zaufania — każdą wiadomość ocenia na
podstawie jej rzeczywistych nagłówków i lokalnego filtra.

## Foldery tworzone przez program

- **`AI-Kwarantanna`** — bardzo prawdopodobny spam, przechowywany co najmniej
  30 dni przed ewentualnym usunięciem;
- **`AI-Do-sprawdzenia`** — przypadki niepewne i wiadomości, których nie udało
  się bezpiecznie przeskanować;
- **`AI-Naucz-spam`** — folder korekt: „ta wiadomość jest spamem”;
- **`AI-Naucz-wazne`** — folder korekt: „ta wiadomość jest prawidłowa”.

Nazwy nie zawierają polskich znaków celowo — dzięki temu działają poprawnie
również w starszych implementacjach IMAP.

## Przydatne polecenia

```bash
guardian menu
guardian napraw
guardian doctor
guardian preflight
guardian run --dry-run
guardian run
guardian status --since 24h
guardian mode status
guardian mode protect
guardian mode active
guardian archive list
guardian archive show <ID>
guardian archive restore <ID>
guardian purge --dry-run
guardian service status
guardian stack status
```

`--dry-run` oznacza próbę bez przenoszenia lub usuwania wiadomości.
Polecenie `archive show` pokazuje na żądanie tylko oczyszczone nagłówki
**Od**, **Temat** i **Data** z zaszyfrowanej kopii. Nie renderuje HTML, nie
otwiera odnośników ani załączników i nie zapisuje tych danych w bazie lub
logach.
Polecenie `archive restore` odtwarza kopię do `AI-Do-sprawdzenia`; nie wysyła
wiadomości do żadnego odbiorcy.

Jeżeli po przerwanym połączeniu `guardian status` pokaże „ruchy wymagające
uzgodnienia”, kolejne przebiegi sprawdzą źródło i cel. Program uzna ruch za
zakończony wyłącznie wtedy, gdy znajdzie jeden jednoznaczny wynik. Jeśli
licznik nie spada, pozostawi przypadek zablokowany bez kasowania — postępuj
według instrukcji rozwiązywania problemów.

## Dokumentacja

- [Zmiany w wersji 0.6.1](CHANGELOG.md)
- [Kryteria audytu CX i dostępności](docs/AUDYT-CX.md)

- [Instalacja krok po kroku](docs/INSTALACJA.md)
- [Graficzny panel i pierwsze kroki](docs/GUI-I-PIERWSZE-KROKI.md)
- [Codzienna obsługa i uczenie](docs/OBSLUGA.md)
- [Bezpieczeństwo, kopie i odzyskiwanie](docs/BEZPIECZENSTWO-I-ODZYSKIWANIE.md)
- [Architektura i prywatność](docs/ARCHITEKTURA-I-PRYWATNOSC.md)
- [Rozwiązywanie problemów](docs/ROZWIAZYWANIE-PROBLEMOW.md)

O2 Mail Guardian jest niezależnym projektem open source i nie jest produktem
ani oficjalną usługą o2/WP. Kod jest udostępniany na licencji
[MIT](LICENSE).
