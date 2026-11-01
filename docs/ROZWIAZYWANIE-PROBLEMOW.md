# Rozwiązywanie problemów

## Zacznij od jednej kontroli

W aplikacji otwórz **Pomoc → Pełna kontrola**. Następnie, jeśli aplikacja to
zaleci, użyj przycisku **Sprawdź i napraw** na Pulpicie.

Terminal nie jest potrzebny. Dla pomocy technicznej odpowiednikami są:

```bash
guardian doctor
```

W aplikacji odpowiada temu **Pomoc → Pełna kontrola**. Kontrola rozszerzona:

```bash
guardian doctor --deep
```

sprawdza dodatkowo LaunchAgent, heartbeat, Redis, DNS, konfigurację Rspamd,
rewizje Bayesa i wolne miejsce wewnątrz Colimy.

Przycisk **Zapisz bezpieczny raport na Biurku** tworzy pakiet bez wiadomości,
adresów, tematów, skrótów wiadomości i sekretów.

Jeśli nie udała się sama instalacja, `Install.command` automatycznie wskaże w
Finderze prywatny plik `~/Library/Logs/O2 Mail Guardian/instalacja.log`.
Nie trzeba przepisywać komunikatów z Terminala — zachowaj ten jeden plik dla
osoby pomagającej w diagnozie. Główne okno poda nazwę nieukończonego etapu i
jedną poradę; numery wierszy i inne szczegóły techniczne pozostają wyłącznie w
prywatnym logu.

Kontrola jest bezpieczna: sprawdza konfigurację, pęk kluczy, IMAP, lokalny
silnik, foldery i miejsce na dysku, ale nie przenosi wiadomości. Nie wklejaj
do wiadomości ani zgłoszenia żadnego hasła.

Awaryjna automatyczna próba naprawy w Terminalu:

```bash
guardian napraw
```

Uruchamia lokalny silnik, czeka na jego gotowość, wykonuje `doctor`, a po
powodzeniu odświeża usługę działającą co 2 godziny. Polecenia mają ograniczony
czas; naprawa nie będzie czekać bez końca na Colimę lub Dockera.

## Poczta pozostaje niesprawdzona po uśpieniu Maca

Guardian działa lokalnie, więc nie sprawdza nowych wiadomości podczas snu
lub wyłączenia Maca. Od wersji 0.6.1 automat po wybudzeniu nadrabia jeden
pominięty przebieg. Poza tym sprawdza pocztę o parzystych godzinach lokalnych.
Jeśli Mac był krótko otwarty, wcześniejsza wersja mogła całkiem pominąć
sprawdzenie. Zaktualizuj program przez `Install.command`, aby odświeżyć także
harmonogram.

Pulpit i Pełna kontrola pokazują ostrzeżenie po ponad 4 godzinach bez udanego
automatycznego sprawdzenia. Wybierz **Sprawdź i napraw**, jeśli przerwa trwa
mimo wybudzonego Maca i dostępnego internetu.

## Korekty po potwierdzonej pomyłce filtra

Przenieś błędnie zatrzymaną ważną wiadomość do `AI-Naucz-wazne`, a spam
pozostawiony w Odebranych do `AI-Naucz-spam`. Guardian obsłuży te jawne
korekty również wtedy, gdy wcześniejsza pomyłka odebrała filtrowi ocenę
jakości. Automatyczne porządkowanie pozostaje wtedy wstrzymane. Po korektach
wybierz w Ustawieniach **Sprawdź ponownie jakość filtra**; udany test na
oddzielonych przykładach pozwoli wznowić porządkowanie.

## „Nie znaleziono polecenia guardian”

Najpierw zamknij Terminal i otwórz go ponownie. Jeśli problem pozostał,
uruchom program pełną ścieżką:

```bash
~/.local/bin/o2-mail-guardian/guardian doctor
```

Jeżeli to działa, instalacja jest poprawna, lecz Terminal nie odświeżył
ścieżki poleceń. Ponowne uruchomienie `Install.command` może bezpiecznie
naprawić skrót bez kasowania konfiguracji.

## „Logowanie nie powiodło się”

Sprawdź kolejno:

1. Czy w o2 włączony jest IMAP?
2. Czy używasz pełnego adresu, np. `nazwa@o2.pl`?
3. Czy włączone jest logowanie dwustopniowe?
4. Czy hasło jest hasłem do programu pocztowego, a nie zwykłym hasłem?
5. Czy podczas kopiowania hasła nie dodano spacji?
6. Czy hasło nie zostało usunięte w ustawieniach o2?

Hasło programu według o2 działa tylko na jednym urządzeniu. Utwórz nowe,
osobne hasło, a potem uruchom:

```bash
guardian setup
```

Nie wyłączaj 2FA w celu „naprawienia” logowania.

## „IMAP jest wyłączony” albo „folder SPAM nie został wykryty”

Włącz IMAP według
[instrukcji o2](https://pomoc.o2.pl/aktywacja-dostepu-dla-programow-pocztowych),
a następnie:

```bash
guardian preflight
guardian setup
```

Nie zmieniaj ręcznie nazwy systemowego folderu SPAM w plikach. Serwer może
używać innej nazwy lub specjalnego oznaczenia, które wykrywa kreator.

## „Brak natywnego IMAP MOVE”

Guardian nie zastępuje tej funkcji wieloetapowym `COPY` i kasowaniem źródła,
bo zerwane połączenie mogłoby pozostawić niejednoznaczny stan. Sprawdź:

```bash
guardian preflight
```

Jeżeli o2 nadal nie zgłasza `MOVE` ani IMAP4rev2, automatyczne przenoszenie
pozostanie zablokowane. Nie obchodź tej blokady zmianą konfiguracji; zachowaj
wynik `preflight` i zgłoś problem.

## Rspamd, Redis albo DNS nie działa

Sprawdź:

```bash
guardian stack status
```

Uruchom ponownie lokalny stos:

```bash
guardian stack down
guardian stack up
guardian doctor
```

Gdy silnik nie działa, Guardian pozostawia Odebrane bez zmian, a wiadomość z
krótkotrwałego SPAM-u o2 może zabezpieczyć w `AI-Do-sprawdzenia`. Nie przenoś
jej ręcznie do Kosza tylko dlatego, że skan się nie udał.

## Colima nie uruchamia się po restarcie Maca

Uruchom:

```bash
guardian stack up
guardian service status
```

Jeżeli automatyczna usługa nie jest zainstalowana:

```bash
guardian service install
```

Pierwsze uruchomienie po aktualizacji macOS może trwać kilka minut.

Możesz też od razu użyć `guardian napraw`. Automatyczna usługa wykonuje
podobną próbę przed każdym skanem i przy utrzymującym się błędzie wyświetla
ogólne powiadomienie najwyżej raz na 24 godziny.

Guardian celowo nie włącza osobnego `brew services` dla Colimy. Uruchamia ją
na żądanie przed skanem, bez zmiany globalnego kontekstu Dockera.

## Wiadomości pozostają w folderze uczącym

Oznacza to zazwyczaj, że uczenie nie zostało potwierdzone. Program celowo nie
przenosi wiadomości, zanim Rspamd nie zapisze korekty.

```bash
guardian doctor
guardian stack status
guardian run
guardian status --since 24h
```

Nie przenoś masowo tych samych wiadomości tam i z powrotem. Po usunięciu
problemu następny przebieg przetworzy je ponownie.

## Zbyt wiele wiadomości trafia do `AI-Do-sprawdzenia`

W pierwszych 14 dniach jest to spodziewane. System celowo zachowuje się
ostrożnie. Regularnie przenoś:

- prawidłowe wiadomości do `AI-Naucz-wazne`;
- spam do `AI-Naucz-spam`.

Bayes zaczyna dostarczać pełny sygnał dopiero po zebraniu odpowiedniej liczby
przykładów obu klas. Nie obniżaj samodzielnie progów, aby „przyspieszyć”
uczenie.

## Ważna poczta nadal trafia do systemowego SPAM-u o2

Guardian może ją uratować dopiero podczas następnego przebiegu. Sprawdź:

```bash
guardian service status
guardian status --since 24h
```

Jeśli wiadomość jest pilna, przenieś ją z systemowego SPAM-u do
`AI-Naucz-wazne`. Dla stałego, zweryfikowanego nadawcy możesz dodatkowo dodać
dokładny adres do listy Zaufani w ustawieniach o2, ale pamiętaj: ta lista
wpływa tylko na filtr o2. Guardian jej nie odczytuje i nadal samodzielnie
sprawdza wiadomość.

Pamiętaj, że o2 może usuwać wiadomości z systemowego SPAM-u po 7 dniach, więc
nie zatrzymuj usługi na dłużej bez ręcznego sprawdzania tego folderu.

## Podejrzany spam pozostał w Odebranych

Przenieś go do `AI-Naucz-spam`. Nie klikaj linków, obrazków, „potwierdź” ani
„wypisz się”. Jeśli to phishing podszywający się pod bank lub urząd, zgłoś go
również właściwej instytucji zgodnie z jej oficjalną instrukcją.

## Brak miejsca na dysku

Guardian zatrzymuje przenoszenie i purge, gdy nie może utworzyć kompletnej
kopii. Zwolnij miejsce bez usuwania katalogu danych Guardiana, a potem:

```bash
guardian doctor
guardian run
```

Nie usuwaj ręcznie plików bazy ani zaszyfrowanego archiwum. Mogłoby to
uniemożliwić bezpieczne sprawdzenie retencji i odzyskanie wiadomości.

## Wiadomość ma ponad 100 MiB i pozostaje w SPAM-ie o2

Bezwzględny limit lokalnej kopii chroni Maca przed wyczerpaniem pamięci przez
złośliwą wiadomość. Guardian zapisze błąd i nie przeniesie takiej wiadomości
bez poprawnej zaszyfrowanej kopii. Ponieważ systemowy SPAM o2 ma krótką
retencję, przenieś tę konkretną wiadomość ręcznie do
`AI-Do-sprawdzenia` i nie otwieraj jej załączników. `guardian status` będzie
pokazywać błąd, dopóki wiadomość pozostaje w skanowanym folderze.

## `purge` odmawia usunięcia

Najpierw sprawdź wersję próbną:

```bash
guardian purge --dry-run
```

Najczęstsze prawidłowe przyczyny odmowy:

- wiadomość ma mniej niż 30 dni;
- trwa tryb ochronny;
- nie osiągnięto kryteriów jakości;
- brakuje kopii lub nie zgadza się skrót;
- wiadomość nie została ponownie potwierdzona jako spam.

Nie obchodź blokady przez przeniesienie całej kwarantanny do Kosza.

## Tryb aktywny nie chce się włączyć

To nie musi oznaczać awarii. Guardian wymaga 14 pełnych dni bieżącego trybu
ochronnego oraz wyników jakościowych:

- zero ważnych wiadomości wcześniej pewnie rozpoznanych jako spam;
- zero spamów wcześniej automatycznie uratowanych;
- przynajmniej jedna korekta w `AI-Naucz-spam`;
- co najmniej 90% tych korekt wcześniej rozpoznanych jako pewny spam;
- pozostałe korekty wcześniej skierowane do ręcznego sprawdzenia, bez
  niewyjaśnionych przypadków.

Zobacz bieżący stan:

```bash
guardian status
guardian mode status
```

Jeśli wcześniej przełączono system z trybu aktywnego z powrotem na ochronny,
od tej zmiany biegnie nowy 14-dniowy okres. Pozostań w trybie ochronnym,
regularnie używaj folderów uczących i spróbuj ponownie później.

## „Ruchy wymagające uzgodnienia” są większe od zera

Najczęściej połączenie zostało zerwane, gdy serwer wykonywał MOVE, więc
Guardian nie zgaduje, gdzie znajduje się wiadomość. Uruchom:

```bash
guardian run
guardian status
```

Program porówna źródło i cel na podstawie pełnego SHA-256 oraz Message-ID.
Jeśli znajdzie jeden jednoznaczny wynik, dokończy zapis albo bezpiecznie
ponowi ruch. Jeśli istnieją kopie po obu stronach, więcej niż jedna zgodna
kopia lub nadal brakuje pewności, niczego nie skasuje. Pozostawi przypadek do
dalszego sprawdzenia zamiast wybrać arbitralną kopię.

Kolejne przebiegi ponawiają kontrolę bez kasowania. Jeżeli licznik mimo to
pozostaje dodatni:

1. nie kasuj i nie przenoś ręcznie podobnych kopii;
2. uruchom `guardian doctor`;
3. zachowaj wynik `guardian status` i dokładny komunikat błędu;
4. poproś o pomoc, przekazując te dwa wyniki bez haseł i treści wiadomości.

Taki trwale niejednoznaczny stan blokuje późniejszy purge danej wiadomości.

## Nie mogę znaleźć kopii do odzyskania

Wyświetl dostępne kopie:

```bash
guardian archive list
```

Lista pokazuje do 100 kopii na stronie. Jeśli program poda polecenie
„Następna strona”, uruchom je, aby zobaczyć starsze pozycje, np.:

```bash
guardian archive list --page 2 --limit 100
```

Jeżeli właściwa kopia ma identyfikator, przywróć ją:

```bash
guardian archive restore <ID>
```

Wiadomość pojawi się jako nieprzeczytana w `AI-Do-sprawdzenia`, a nie
bezpośrednio w Odebranych. To zabezpieczenie pozwala sprawdzić ją przed
dalszym uczeniem. Brak kopii na liście może oznaczać, że minęła 35-dniowa
retencja, archiwum jest niedostępne albo klucz nie znajduje się już w pęku
kluczy. Uruchom `guardian doctor` i nie usuwaj ręcznie plików archiwum.

## `setup` odmawia utworzenia nowego klucza kopii

Kreator wykrył wcześniejszą bazę lub pliki `.eml.age`, lecz nie znalazł
pasującego klucza w pęku kluczy. Jest to blokada przed nieodwracalną utratą
dostępu do starszych kopii.

- Nie usuwaj bazy ani archiwum.
- Nie próbuj tworzyć nowej konfiguracji „od zera”.
- Odtwórz pęk kluczy użytkownika z Time Machine albo wcześniejszej kopii Maca.
- Następnie ponownie uruchom `guardian setup`.

## Mac był wyłączony przez kilka dni

Po uruchomieniu komputera:

```bash
guardian stack up
guardian run
guardian status
```

Guardian nadrabia wiadomości przy następnym przebiegu. Najpierw przejrzyj
systemowy SPAM o2, ponieważ jego retencja jest krótsza niż kwarantanny
Guardiana.

## Powtórna instalacja

Ponowne uruchomienie `Install.command` zachowuje poprawną konfigurację, hasło
w pęku kluczy, bazę, archiwum, tryb i stan usługi. Nie uruchamia ponownie
kreatora ani nie pyta ponownie o działające hasło. Mimo to przed większą
aktualizacją sprawdź:

```bash
guardian status
guardian service uninstall
```

Po aktualizacji:

```bash
guardian doctor
guardian run --dry-run
guardian service install
```

Instalator sam buduje i testuje nową binarkę, przygotowuje czysty katalog
`deploy` i czeka na zdrowie Rspamd. Jeśli nowy stos nie wystartuje, przywraca
poprzedni katalog. Jeśli istniejący `config.toml` jest nieczytelny, zatrzymuje
się przed podmianą działającej instalacji.

### Homebrew zgłasza brak uprawnień

Uruchom:

```bash
brew doctor
```

Napraw tylko katalogi wskazane w wyniku. Instalator celowo nie wykonuje
rekurencyjnego `sudo chown -R /opt/homebrew`, ponieważ mogłoby to zmienić
właściciela plików innych narzędzi i użytkowników.

## Jak przygotować bezpieczne informacje o błędzie

Możesz przekazać:

- wersję macOS;
- wynik `guardian doctor`;
- wynik `guardian stack status`;
- dokładny komunikat błędu;
- godzinę wystąpienia problemu.

Nie przekazuj:

- zwykłego hasła do o2;
- hasła programu pocztowego;
- kluczy awaryjnych 2FA;
- odszyfrowanych wiadomości lub załączników;
- całej zawartości pęku kluczy.
