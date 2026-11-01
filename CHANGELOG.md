# Zmiany w Mail Guardian

## 0.6.1 — 2026-11-01

### Linux, odzyskiwanie i utrzymanie

- Publiczne źródła obejmują worker Linux, systemd, prywatne poświadczenia,
  ograniczony pomocnik administracyjny, wiązanie konfiguracji i tożsamości
  wdrożenia, migrację, szyfrowane kopie oraz porównywanie modelu Redis.
- Nowy instalator pozostawia harmonogram wyłączony. Przejęcie istniejącej
  polityki wymaga sprawdzonej historii oraz świeżego dry-run; skopiowanie bazy
  nie przenosi zgody na inną konfigurację lub host.
- Opcjonalny obserwator porównuje rzeczywisty przebieg, heartbeat i nierozstrzygnięte
  operacje. Status procesu lub kontenera nie zastępuje udanego sprawdzenia poczty.
- Opublikowano codzienne koordynatory aktualizacji Ubuntu, Dockera, obrazów
  i zależności/kompilatora Guardiana wraz z testami. Zachowują spójny punkt
  odzyskiwania z modelem, blokady, dziennik i kontrolę po zmianie. Nowe linie
  major/minor pozostają do ręcznego przeglądu.
- Potwierdzanie MOVE bez COPYUID ma do trzech prób odczytu z przerwami
  250 ms i 750 ms. Używa dokładnej treści i UIDVALIDITY, bez zbędnego ENVELOPE;
  nie ponawia samego MOVE. Niejednoznaczność nadal wymaga odzyskiwania.
- Poprawiono test, którego serwer mimo braku UIDPLUS nadal wysyłał COPYUID.
  Nowe regresje faktycznie usuwają mapowanie z odpowiedzi protokołu.
- Dokumentacja dla developerów obejmuje architekturę, testy, źródła konserwacji,
  wydania i postępowanie po awarii. Stare plany pilota oznaczono historycznie.
- CI obejmuje macOS i Linux, testy operacyjne, linki dokumentacji i skan sekretów.
  Codzienne propozycje zależności i kontrola podatności nie wdrażają kodu na VPS.

### Konfiguracja i sekrety

- Konfiguracja v2 rozdziela konto, nazwę logowania i dostawcę. Wczytanie v1
  zachowuje dotychczasową instalację o2, jej foldery, ścieżki i wpisy Keychain.
- Dziennik skrzynki jest przypisany do instancji i połączenia. Zmiana serwera
  lub loginu nie może wykorzystać starych UID i oczekujących operacji. Zmiana
  folderów wymaga nowej próby oraz obserwacji; historia jakości pozostaje.
- Wspólny interfejs sekretów obsługuje Keychain i odczyt prywatnych poświadczeń
  Linux. Błąd odczytu lub uszkodzony klucz archiwum nie powoduje jego wymiany.
- API konfiguracji zachowuje dotychczasowe żądania i przyjmuje dodatkowe pola
  połączenia custom IMAP. Wspólne pola konfiguracyjne nie oznaczają ukończonej
  obsługi OAuth ani akceptacji każdego dostawcy IMAP.

### Naprawy macOS i wspólnego silnika

- Automat nadrabia po wybudzeniu Maca jeden przebieg pominięty podczas snu.
  Wcześniejszy harmonogram mógł pominąć sprawdzanie nawet wtedy, gdy Mac
  został później na krótko otwarty. Nowy harmonogram działa o parzystych
  godzinach lokalnych i przy załadowaniu usługi.
- Pełna kontrola i pulpit jednakowo ostrzegają, gdy brak udanego przebiegu
  albo ostatni sukces jest starszy niż 4 godziny; ponad 48 godzin to stan
  krytyczny. Dawniej pełna kontrola mogła potwierdzać aktualność mimo dobowej
  przerwy widocznej na pulpicie.
- Ostatnia jawna korekta wiadomości określa jej bieżącą klasę. Zmiana decyzji
  spam → ważne → spam ponownie wywołuje uczenie zamiast korzystać ze starego
  potwierdzenia. Każde historyczne wskazanie „ważne” nadal blokuje trwałe
  usunięcie tej samej treści.
- Utrata oceny jakości nie blokuje przetwarzania kolejnych jawnych korekt.
  Automatyczne porządkowanie nadal wymaga prawidłowej oceny, sprawdzanej
  po przetworzeniu folderów nauki.
- Długi, poprawnie działający przegląd skrzynki nie traci połączenia IMAP
  po 10 minutach. Limit dotyczy pojedynczej komendy; zawieszona operacja
  przerywa przebieg zamiast wywoływać serię błędów odczytu kolejnych wiadomości.
- Przejściowy błąd eksportu kopii modelu może być ponowiony jeden raz.
  Każda próba ma własny limit czasu, a zapis kopii wymaga prawidłowego
  zakończenia eksportu i zgodnej sumy kontrolnej.
- Kontrole trwałego zapisu Redis mają osobne limity czasu i jedną ponowną
  próbę po błędzie procesu. Poprawna kontrola statusu zapisu nie skraca czasu
  dostępnego na następną kontrolę ustawień synchronizacji.

## 0.6.0

- Kończenie obserwacji może korzystać z aktualnej, zapisanej oceny filtra.
  Osobny, pusty model otrzymuje około 70% oznaczonych wiadomości, 10% służy
  do wyboru progu, a pozostałe 20% do niezależnego sprawdzenia. Wiadomości
  o tak samo znormalizowanym temacie pozostają w jednej części.
- Kwalifikacja wymaga minimum 40 przykładów spamu i 30 ważnych w teście,
  co najmniej 90% wykrytego spamu, zera błędnie zatrzymanych ważnych i zera
  błędnie ratowanego spamu. Wynik jest związany z konfiguracją skrzynki,
  wersją reguł i wybranym progiem. Nowa potwierdzona pomyłka w przenoszeniu
  odbiera tę kwalifikację do czasu ponownego sprawdzenia.
- Bayes klasyfikuje od 100 statystycznych przykładów każdej klasy. Odrębna
  ocena pozwala dobrać próg kwarantanny od 6; bez niej aktywacja nadal wymaga
  dotychczasowego progu co najmniej 12 i dawnych kontroli.
- Niepełny pomocniczy test DNS nie unieważnia silnych dodatnich dowodów
  spamu przy przenoszeniu do odwracalnej kwarantanny. Timeout całego skanu,
  pominięcie i soft reject nadal blokują decyzję. Ratowanie wymaga kompletnego
  skanu; trwałe usuwanie zachowuje kompletność, próg co najmniej 12, minimum
  nauki 200/200 i pozostałe odrębne warunki.
- W Ustawieniach dostępna jest ponowna ocena jakości bez resetowania historii.
  Ten sam proces jest dostępny przez `guardian qualify`; raporty zawierają
  skróty i wyniki, bez treści wiadomości i danych logowania.
- Budowanie i instalacja wymagają Go 1.27.3 lub poprawionego Go 1.26.10.
  Usuwa to osiągalne zgłoszenie GO-2026-6809 dotyczące sprawdzania certyfikatów.

## Poprawka lokalna 2026-10-22 — skanowanie dostarczonej poczty

- Skan IMAP wyłącza wyłącznie `GREYLIST_CHECK` i `GREYLIST_SAVE`: odraczanie
  dostawy SMTP nie ma zastosowania do poczty już znajdującej się w skrzynce.
  Rzeczywiste timeouty, błędy DNS oraz pozostałe odpowiedzi `soft reject`
  nadal blokują automatyczną decyzję.
- Wiadomości pozostawione w skanowanym zakresie Odebranych są oceniane ponownie
  po dobie albo po potwierdzonym uczeniu podczas bieżącego przebiegu.
  Skończone ruchy i jawne korekty nie są powtarzane.
- Pierwsza ocena i akcja są zachowane oddzielnie od aktualnego wyniku.
  Powtórny skan nie może poprawić wstecz historycznych kryteriów aktywacji.
- Komunikat po zakończonej obserwacji wyjaśnia bezterminowe blokady historyczne;
  zdrowy harmonogram nie sugeruje, że automatyczne porządkowanie jest gotowe.
  Ta poprawka nie włącza porządkowania ani trwałego usuwania.

## 0.5.3

- Logowanie IMAP czeka na powitanie serwera. Usunięto wyścig, w którym
  LOGIN mógł zostać wysłany przed gotowością serwera.
- Jawna korekta w folderze nauki pozostaje skuteczna również dla wiadomości
  z wadliwym MIME: Guardian szyfruje oryginał, zapisuje korektę dokładnej treści
  i przenosi ją zgodnie z wyborem użytkownika. Nie wysyła wadliwej treści do
  uczenia ani nie zwiększa liczników Bayesa. Automatyczna klasyfikacja nadal
  odrzuca wadliwe wiadomości. Dawniej zablokowane korekty są ponawiane.
- Zależność x/crypto 0.58.0 usuwa 16 zgłoszeń dotyczących starszych wydań.
  Nienaprawialne zgłoszenie dotyczące nieużywanego OpenPGP pozostaje jawne;
  kontrola zależności zabrania importowania tego pakietu.
- Błędy zapisu wirtualnego dysku Colimy blokują start, restart instalatora
  i pomyślne zakończenie przebiegu, również gdy Redis nadal odpowiada z pamięci.
  Zapis AOF jest synchroniczny; jego przebudowa rozpoczyna się od 4 MiB.

## 0.5.2

- Zerwanie połączenia i niedostępność serwera podczas logowania IMAP nie są
  przedstawiane jako odrzucenie hasła; zachowana jest rzeczywista przyczyna błędu.
- Próba z błędami pojedynczych wiadomości nie potwierdza gotowości do
  włączenia harmonogramu. API zachowuje podsumowanie, lecz nie zgłasza
  pełnego sukcesu; polecenie konsolowe zwraca błąd również przy częściowej awarii.
- Budowanie używa poprawionego Go 1.27.2. Pakowanie i instalacja ze źródeł
  odrzucają starsze podatne wersje, w tym Go 1.27.1 i 1.26.8.
- Budowanie aplikacji, testy, podgląd i instalator wybierają pełny Xcode,
  gdy system wskazuje Command Line Tools, a Xcode jest zainstalowany.
  Jawny wybór DEVELOPER_DIR jest zachowany; ustawienie systemowe nie zmienia się.
- Wspólny katalog roboczy Swift poza Documents może być używany również
  podczas pakowania, podglądu i instalacji ze źródeł.

## 0.5.1

- Naprawa i sprawdzanie stosu działają z aplikacji macOS również przy
  ograniczonym PATH; zależności Colimy i Dockera dostają jawne ścieżki.
- Model Redis ma dwie sprawdzane sumą kontrolną kopie na Macu poza Colimą.
  Cofnięty model nie zastępuje dobrej kopii; błędy trwałego zapisu Redis
  i eksportu modelu pozostają widoczne w wyniku przebiegu.
- Uzgadnianie przeniesień bez COPYUID potwierdza pełną treść wiadomości.
  Wyszukiwanie po rozmiarze omija nieczytelne, niezwiązane wiadomości na
  serwerze. Niejednoznaczne wyniki ani błędy odczytu nie potwierdzają ruchu.
- Pominięcie uczenia przez Rspamd (HTTP 204) zachowuje korektę użytkownika
  bez fałszywego zwiększania liczników i bez zapętlenia ponowień.
- Kontrola utraty modelu używa obserwowanych liczników Rspamd; duplikaty
  statystyczne nie powodują fałszywego alarmu.
- Status opiera się na ostatnim zakończonym sprawdzeniu. Przebieg z błędami
  lub nierozstrzygniętymi operacjami nie dostaje zielonego wyniku ani udanego
  heartbeat.
- Kreator obsługuje zgodne nazwy pól starszej aplikacji i aktualnego backendu.
- GitHub sprawdza testy, podatności, aplikację i instalator przy zmianach.
  Testy nie mają dostępu do prawdziwej poczty ani haseł.

## 0.5.0

- Lokalny ZIP dla Apple Silicon zawiera gotowy backend i aplikację macOS.
  Instalowanie Guardiana z paczki nie kompiluje Go ani Swift.
- Manifest sprawdza kompletność payloadu, wersję, architekturę i sumy SHA-256;
  samokontrola i lokalne podpisy są sprawdzane przed podmianą programów.
- Wspólna blokada chroni przed równoległym instalowaniem i nadpisaniem logu.
- Wynik instalacji odróżnia sukces, potrzebę uwagi i awarię. Problem kontroli
  końcowej lub wznowienia harmonogramu pozostaje widoczny.
- Nieudane przywracanie zachowuje kopie aktualizacyjne i nie deklaruje sukcesu.
- Paczka zachowuje źródła; instalacja bezpośrednio z repozytorium nadal buduje
  program. Sumy kontrolne wykrywają uszkodzenia, nie uwierzytelniają wydawcy.
- Podpis ad hoc, bez Developer ID i notaryzacji. Minimalny deklarowany macOS 13;
  test na obecnym Macu nie potwierdza działania na wszystkich starszych wersjach.

## 0.4.0

Pierwsza iteracja poprawy designu i codziennej obsługi aplikacji macOS.

- Pulpit pokazuje zadania użytkownika przed statystykami. Ostatnie udane
  sprawdzenie i harmonogram są w karcie statusu, a postęp obserwacji ma jedną sekcję.
- Brak zapisanych wiadomości do oceny ma osobny komunikat, zależny od trybu
  automatycznego lub ręcznego; komunikat nie pojawia się przy nieaktualnych danych.
- Nauka i korekty prowadzą przez trzy kroki, pozwalają otworzyć pocztę o2
  w przeglądarce i uruchomić przetwarzanie już przeniesionych korekt u góry strony.
- Kopiowanie nazwy folderu wyświetla czasowe potwierdzenie.
- Odzyskiwanie objaśnia daty na liście i pozwala przechodzić między sąsiednimi
  kopiami na bieżącej stronie. Każda zmiana unieważnia odsłonięte nagłówki
  oraz możliwość przywrócenia poprzednio wybranej wiadomości.

- Archiwum pozwala wybrać daty Od/Do. Zakres obejmuje całe dni w lokalnej
  strefie czasu i łączy się z kategorią przed paginacją po stronie bazy.
  Zastosowanie filtra wraca do pierwszej strony i usuwa poprzedni podgląd.
- Ocena gotowości pokazuje pięć konkretnych warunków jakości oraz liczniki
  z bieżącego okresu obserwacji. Nie zmienia zasad aktywacji.

- Menu Przejdź i skróty ⌘1–⌘5 ułatwiają nawigację klawiaturą.
- Etykiety dostępności rozróżniają kopiowane foldery oraz spełnione
  i niespełnione warunki jakości.
- Błąd aktywacji pozostaje w otwartym oknie potwierdzenia; ponowienie
  nie wymaga ponownego wpisywania tekstu.

- Przygotowanie konta w kreatorze ma trzy czytelne kroki w rozwijanej sekcji.
  Pola danych są zablokowane podczas sprawdzania połączenia, aby wynik próby
  odpowiadał danym widocznym w formularzu.

- Ikona paska menu odróżnia obserwację od aktywnego porządkowania i pokazuje
  brak potwierdzenia stanu, gdy ostatni odczyt się nie udał.
- Test paczki sprawdza zgodność wersji i spakowanych widoków z kodem projektu.

- Puste wyniki odzyskiwania pozwalają bezpośrednio wyłączyć filtr dat lub
  pokazać wszystkie kategorie. Pusta dalsza strona ma powrót do początku listy.
- Błąd odczytu archiwum usuwa nieaktualną listę i blokuje nawigację stron.
  Ponowienie odczytu dotyczy strony, której wczytanie się nie udało.

- Anulowanie operacji nie jest traktowane jak sukces: okno aktywacji zachowuje
  potwierdzenie, a dalsze kroki uruchamiają się dopiero po udanej operacji
  i odczycie stanu. Przerwanie oznacza stan ochrony jako niepotwierdzony.
- Komunikat anulowania wyjaśnia, że zakończone kroki mogły zostać zapisane.
  Okno aktywacji pozwala odświeżyć stan przed ponowieniem.

### Dalsze prace

- Gotowa aplikacja podpisana Developer ID i notaryzowana zamiast lokalnego budowania.
- Audyt VoiceOver, klawiatury i testy użyteczności z osobami spoza projektu.

## 0.3.0

Pierwsze wydanie: lokalny silnik ochrony, natywna aplikacja macOS, kreator
konfiguracji, nauka, zaszyfrowane kopie i odzyskiwanie wiadomości.
