# Graficzny panel i pierwsze kroki

## Pierwsza konfiguracja — trzy kroki

1. **Konto:** rozwiń instrukcję przygotowania konta (IMAP, logowanie
   dwustopniowe i hasło aplikacyjne), następnie wpisz adres o2 i osobne hasło
   aplikacyjne. Podczas sprawdzania połączenia dane nie są edytowalne. Przycisk **Połącz i
   wykryj ustawienia** sprawdza konto i bezpieczne połączenie. Instrukcja
   tworzenia hasła jest dostępna przy formularzu; hasło zostanie zapisane
   w pęku kluczy macOS.
2. **Foldery:** sprawdź wykryty folder SPAM i kliknij **Potwierdzam foldery
   i zapisuję**. Listę rozwijaj tylko, jeśli wykryta nazwa jest nieprawidłowa.
   Nazwy dodatkowych folderów są dostępne w rozwijanej sekcji.
3. **Bezpieczna próba:** kliknij **Wykonaj bezpieczną próbę**. Wynik pokazuje
   liczbę sprawdzonych wiadomości i proponowanych działań z tej konkretnej
   operacji. To symulacja bieżącego trybu, bez przenoszenia, nauki i kasowania.
   Następnie wybierz **Włącz sprawdzanie co 2 godziny** albo świadomy tryb ręczny.

Po zapisaniu konta zamknięcie aplikacji przed końcem próby nie wymaga ponownego
wpisywania hasła: następne uruchomienie wróci do kroku 3. Liczniki konkretnej
próby są pokazywane po jej wykonaniu w bieżącej sesji; aplikacja nie zastępuje
ich statystyką dobową, jeśli poprzednia próba nie jest już dostępna w pamięci.

## Co Guardian robi z pocztą

Sprawność automatu i uprawnienie do porządkowania to dwie odrębne informacje.
Przegląd i pasek menu pokazują m.in.:

- **Odebrane pod obserwacją:** automat sprawdza pocztę, ale nie przenosi
  automatycznie wiadomości z Odebranych. Wiadomości z folderu SPAM mogą trafić
  do `AI-Do-sprawdzenia`. Korekty z folderów nauki nadal są przetwarzane.
- **Porządkowanie jest włączone:** pewny spam trafia do kwarantanny,
  prawidłowe wiadomości z folderu SPAM wracają do Odebranych, a przypadki
  niepewne trafiają do sprawdzenia.
- **Sprawdzanie na Twoje żądanie:** automat jest wyłączony. Uruchom sprawdzanie
  przyciskiem w aplikacji lub ponownie włącz harmonogram.
- **Ochrona wymaga uwagi / naprawy:** skorzystaj z proponowanego działania.
- **Nie można potwierdzić stanu:** ostatni odczyt się nie udał. Widoczne dane
  mogą być nieaktualne; interfejs nie przedstawia ich jako potwierdzenia ochrony.

Trwałe usuwanie jest osobnym uprawnieniem i domyślnie pozostaje wyłączone.
Włączenie porządkowania nie włącza trwałego usuwania.

## Przegląd

Pulpit pokazuje stan, jedno główne działanie oraz osobno:

- zadania użytkownika przed statystykami;
- wyniki ostatnich 24 godzin (bez doliczania próbnych skanowań);
- wynik ostatniego sprawdzenia uruchomionego w tej sesji;
- wiadomości do oceny i przypadki wymagające naprawy;
- postęp okresu obserwacji i potwierdzenia jakości;
- ostatni sukces, harmonogram oraz rozwijane szczegóły.

Liczniki folderów pochodzą z zapisów Guardiana, nie z ciągłego podglądu IMAP.
Podsumowanie skanowania może zawierać uwagi nawet przy zakończonej operacji;
liczba nieudanych kontroli jest wtedy widoczna osobno.

## Nauka i korekty

W poczcie o2 przenieś wiadomość do:

- `AI-Naucz-wazne`, jeśli to prawidłowa wiadomość;
- `AI-Naucz-spam`, jeśli to spam.

Wersja 0.5.0 prowadzi przez trzy kroki: otwarcie poczty, przeniesienie wiadomości
i przetworzenie korekt. Przycisk **Otwórz pocztę o2** otwiera stronę poczty
w przeglądarce; użytkownik sam wybiera folder. Aplikacja objaśnia oba przypadki
i pozwala skopiować nazwę folderu z krótkim potwierdzeniem **Skopiowano**. Przycisk
**Sprawdź pocztę i przetwórz korekty** uruchamia pełne sprawdzenie, zgodnie
z bieżącym trybem. Przy wyłączonym automacie należy uruchomić je ręcznie.

## Odzyskiwanie

Kategorie **Wszystkie kopie**, **Kwarantanna**, **Do sprawdzenia** i
**Przywrócone** filtrują całe archiwum danego konta przed podziałem na strony.
Każda strona zawiera do 10 wpisów. Opcja **Zawęź datę pierwszego zapisu**
pozwala wybrać daty **Od** i **Do**. Kliknij **Zastosuj daty**, aby odczytać
wyniki z całego archiwum. Dzień końcowy jest uwzględniony w całości, w lokalnej
strefie czasu Maca. Pod datami widzisz zastosowany zakres. Wyłączenie opcji
przywraca wszystkie daty; każda zmiana zastosowanego filtra wraca do strony 1.
To daty pierwszego zapisu przez Guardiana, a nie daty wysłania wiadomości. Lista celowo nie odszyfrowuje tematów
wiadomości automatycznie.

1. Wybierz kopię według daty pierwszego zapisu i stanu.
2. Kliknij **Pokaż nadawcę i temat**. Obok listy zobaczysz wyłącznie oczyszczone
   nagłówki: nadawcę, temat i datę.
3. Kliknij **Przywróć wiadomość** i potwierdź przywrócenie do
   `AI-Do-sprawdzenia` w poczcie o2.

Przyciski **Poprzednia kopia** i **Następna kopia** przechodzą między wpisami
na bieżącej stronie. Nagłówki każdej kolejnej kopii odsłaniasz osobno.

Zmiana wyboru, strony lub kategorii unieważnia podgląd i możliwość przywrócenia
poprzedniej kopii. Treść, HTML, linki i załączniki nie są renderowane. Pusta
lista i nieudany odczyt mają odrębne komunikaty.

## Ustawienia

Harmonogram, przenoszenie wiadomości oraz uruchamianie panelu po zalogowaniu
mają oddzielne sekcje. Zamknięcie okna i wyłączenie startu panelu nie zatrzymują
niezależnego automatu.

Przenoszenie nie jest ukryte w ustawieniach zaawansowanych. Jego sekcja pokazuje
postęp okresu ochronnego i wynik oceny jakości, odczytane z lokalnego backendu.
Przycisk **Sprawdź ponownie jakość filtra** uruchamia odrębną naukę, dobór
progu i test na innych wiadomościach, bez zmiany folderów i bez resetu historii.
Rozwijane **Warunki jakości** pokazują oddzielenie przykładów, minimum 90%
wykrytego spamu w teście, zero błędnie zatrzymanych ważnych i zero błędnie
ratowanego spamu oraz wystarczającą naukę modelu. Starsza instalacja bez
raportu nadal pokazuje dotychczasowe warunki historyczne. Nie należy oznaczać
prawidłowych wiadomości jako spam, aby odblokować automat. Wynik ograniczonej
próby nie stanowi gwarancji bezbłędności. Po spełnieniu warunków można wybrać
**Włącz porządkowanie…**. Nadal wymagane
jest wpisanie `AKTYWNY`; backend ponownie sprawdza warunki przed zmianą trybu.
Brak danych o gotowości albo nieaktualny stan nie odblokowuje przycisku.

Powrót do obserwacji wymaga potwierdzenia, ponieważ rozpoczyna nowy okres
obserwacji i wyłącza trwałe usuwanie. Trwałe usuwanie pozostaje w osobnej,
zwiniętej sekcji zaawansowanej i wymaga potwierdzenia `WLACZ`.

Zmiana danych konta zatrzymuje automat, unieważnia dotychczasową próbę oraz
przywraca tryb ochronny. Po zmianie trzeba wykonać nową próbę i świadomie
włączyć harmonogram. Niepowodzenie konfiguracji uruchamia próbę przywrócenia
poprzedniej konfiguracji, sekretu i automatu.

## Klawiatura i dostępność

Menu **Przejdź** udostępnia skróty **⌘1–⌘5**: Przegląd, Nauka i korekty,
Odzyskiwanie, Ustawienia i Pomoc. Podczas pierwszej konfiguracji skróty są
wyłączone. Etykiety dla czytnika ekranu wskazują nazwę kopiowanego folderu,
stan każdego warunku jakości i skutek zmiany wybranej kopii.

Jeśli aktywacja porządkowania się nie powiedzie, jej okno pozostaje otwarte
z błędem i wskazówką. Wpisane potwierdzenie pozostaje dostępne do ponowienia
próby; backend za każdym razem ponownie sprawdza gotowość.

## Pomoc i informacja zwrotna

Pomoc prowadzi od problemu (brak ważnego e-maila, spam w Odebranych, problem
z ochroną) do odpowiedniego działania. Dłuższe operacje pokazują opis działania
oraz przycisk anulowania niezależnie od wybranej sekcji. Komunikaty błędów
pozostają w widocznym pasku, z następnym działaniem i rozwijanym kodem dla pomocy.
Raport diagnostyczny jest zapisywany na Biurku i nie jest nikomu wysyłany.

## Lokalny podgląd dla projektowania i testów

```bash
bash scripts/preview-gui.sh healthy
bash scripts/preview-gui.sh ready dark
```

Skrypt buduje izolowaną aplikację i wypisuje ścieżkę `.app`, którą można
otworzyć w Finderze. Korzysta wyłącznie z demonstracyjnego backendu: nie
łączy się z IMAP, pękiem kluczy, Rspamd ani launchd. Dostępne scenariusze:
`healthy`, `active`, `ready`, `attention`, `critical`, `manual`, `unconfigured`,
`empty`, `offline`. Drugi argument `dark` zmienia wygląd tylko podglądu.

Testy mostu GUI i reguł prezentacji: `bash scripts/test-swift.sh`.
Pełny zestaw kontroli projektu: `make check` (wymaga Go oraz narzędzi Apple).
