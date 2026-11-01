# Codzienna obsługa

## Najłatwiejszy sposób: aplikacja

Otwórz `~/Applications/O2 Mail Guardian.app` albo kliknij
`Guardian.command`. Pulpit pokazuje stan i jedno zalecane działanie. Zakładka
**Nauka** prowadzi przez korekty, a **Odzyskiwanie** przez bezpieczny podgląd
i przywrócenie kopii.

Awaryjne menu tekstowe nadal można uruchomić:

```bash
guardian menu
```

GUI i menu opisują każde działanie prostym językiem i wymagają dodatkowego
potwierdzenia przed operacją trwałego usunięcia. Na co dzień nie trzeba
obserwować okna Terminala — automatyczna usługa wykonuje przebieg co 2
godziny, o parzystych godzinach lokalnych. Gdy termin przypada podczas snu
Maca, po wybudzeniu nadrabia jeden zaległy przebieg. Wyłączony lub uśpiony Mac
nie filtruje poczty na bieżąco.

Pozycja **Napraw instalację** wykonuje typowe działania naprawcze w poprawnej
kolejności. To samo można uruchomić poleceniem `guardian napraw`.

## Cztery foldery, które warto znać

### `AI-Kwarantanna`

Tu trafia wiadomość sklasyfikowana z dużą pewnością jako spam. Nie jest
natychmiast kasowana. Pozostaje w kwarantannie co najmniej 30 dni.

Jeśli znajdziesz tu ważną wiadomość, przenieś ją do
`AI-Naucz-wazne`. Nie przenoś jej od razu do Odebranych — użycie folderu
uczącego zapobiega powtórzeniu pomyłki.

### `AI-Do-sprawdzenia`

Tu trafiają przypadki niejednoznaczne, bardzo duże wiadomości oraz wiadomości,
których skanowanie zakończyło się błędem. Guardian nie usuwa ich automatycznie.

- prawidłowa wiadomość → `AI-Naucz-wazne`;
- spam → `AI-Naucz-spam`;
- nadal nie masz pewności → pozostaw bez zmian.

### `AI-Naucz-spam`

Przenieś tutaj spam, który robot pozostawił w Odebranych lub uznał za
niepewny. Przy następnym przebiegu program:

1. przekaże wiadomość do lokalnego uczenia jako spam;
2. sprawdzi, czy uczenie się powiodło;
3. dopiero wtedy przeniesie wiadomość do kwarantanny.

### `AI-Naucz-wazne`

Przenieś tutaj prawidłową wiadomość błędnie umieszczoną w SPAM-ie,
kwarantannie lub folderze do sprawdzenia. Przy następnym przebiegu program:

1. nauczy lokalny filtr, że to prawidłowa poczta;
2. po udanym uczeniu przeniesie ją do Odebranych;
3. oznaczy ją jako nieprzeczytaną, aby nie została przeoczona.

Jeśli Rspamd jawnie pominie uczenie (HTTP 204), program zachowa Twoją korektę
dla dokładnej zawartości wiadomości i przeniesie ją zgodnie z wyborem. Raport
pokaże pominięcie, a licznik przykładów Bayesa nie wzrośnie. Takie pominięcie
nie powoduje ponawiania tej samej operacji co dwie godziny. Pozostałe błędy
uczenia pozostawiają wiadomość w folderze uczącym do ponownej próby.

## Jak bezpiecznie zebrać przykłady Bayesa

Nie trzeba robić tego jednego dnia. `guardian status` pokazuje dwa liczniki
postępu do 100 przykładów każdej klasy potrzebnych Bayesowi. Liczniki korekt
i statystyczne liczniki Rspamd mogą się różnić dla podobnych wiadomości.

- Przenoś do `AI-Naucz-spam` starsze wiadomości, co do których nie masz żadnych
  wątpliwości, że są spamem.
- Do `AI-Naucz-wazne` możesz partiami przenosić znane rachunki, potwierdzenia,
  korespondencję z rodziną lub inne prawidłowe maile. Po udanym uczeniu wrócą
  do Odebranych.
- Zacznij od partii po 20–50 wiadomości i po każdym przebiegu sprawdź raport.
- Nie używaj jako przykładów wiadomości niejednoznacznych.

Uczenie i treść przykładów pozostają lokalnie na Macu. Publiczna baza fuzzy
Rspamd jest wyłączona, więc nie otrzymuje również skrótów tych wiadomości.
Trwałe usuwanie nie może zostać włączone, dopóki oba liczniki nie osiągną
200. Sam tryb aktywny ma osobną bramkę jakości opisaną poniżej.

## Ważna różnica: „zaufany” a „wygląda znajomo”

Adres widoczny w polu Od można łatwo podrobić. Dlatego sama nazwa banku,
urzędu, sklepu czy znajomej osoby nie powoduje automatycznego zaufania.

Dla naprawdę ważnych nadawców można dodatkowo użyć listy **Zaufani** w
ustawieniach o2, ale działa ona wyłącznie w filtrze dostawcy o2. Guardian nie
ma dostępu do tej listy, nie importuje jej i nie traktuje jej jako sygnału
zaufania. Wiadomość od takiego adresu nadal przechodzi zwykłą kontrolę
Guardiana, ponieważ widoczny adres Od może być podrobiony.

## Tryb ochronny i kolejne etapy

### Dni 1–14: obserwacja

- brak trwałego usuwania;
- Odebrane nie są zmieniane na podstawie niepewnych wyników;
- poczta z systemowego SPAM-u o2 jest zabezpieczana w
  `AI-Do-sprawdzenia`;
- zbierane są korekty użytkownika.

Jest to ważne, ponieważ o2 informuje, że wiadomości w folderach Spam i Kosz
mogą zostać usunięte po 7 dniach:
[zasady retencji o2](https://pomoc.o2.pl/dlaczego-wiadomosci-znikaja).

### Po 14 pełnych dniach: bramka trybu aktywnego

Upływ czasu nie wystarcza. W wersji 0.6.0 wybierz w Ustawieniach
**Sprawdź ponownie jakość filtra**. Guardian nauczy nowy, osobny model na
około 70% Twoich jednoznacznych przykładów, dobierze próg na kolejnych 10%
i sprawdzi wynik na pozostałych 20%. Wiadomości z takim samym znormalizowanym
tematem pozostają w jednej części. Model testowy nie zmienia Twojej poczty
ani produkcyjnej bazy Bayesa.

Ocena wymaga co najmniej 40 wiadomości spamu i 30 ważnych w części testowej,
minimum 90% wykrytego spamu, zera błędnie zatrzymanych ważnych i zera błędnie
ratowanego spamu. Potrzeba też co najmniej 100 statystycznych przykładów
każdej klasy w samej części uczącej. Wynik dotyczy sprawdzonego mechanizmu
i próby; nie jest obietnicą bezbłędnej klasyfikacji przyszłej poczty.

Pomyślny raport zastępuje historyczną blokadę bez wymazywania starych pomyłek.
Nowa potwierdzona pomyłka w automatycznym przenoszeniu wymaga ponownej oceny.
Możesz ją uruchomić tym samym przyciskiem, zachowując historię i daty obserwacji.

Dla starszej instalacji bez takiego raportu pozostają dotychczasowe kontrole
wyników z bieżącego okresu ochronnego:

- żadna wiadomość oznaczona później jako ważna nie mogła wcześniej otrzymać
  pewnego werdyktu `spam`;
- żadna wiadomość oznaczona później jako spam nie mogła wcześniej zostać
  automatycznie uratowana;
- co najmniej jedna wiadomość musiała zostać jawnie oznaczona w
  `AI-Naucz-spam`;
- co najmniej 90% tak oznaczonych spamów musiało wcześniej otrzymać pewny
  werdykt `spam`;
- wszystkie pozostałe oznaczone spamy musiały wcześniej trafić do ręcznego
  sprawdzenia — żaden przypadek nie może być niewyjaśniony.

Jeśli wszystkie warunki są spełnione, wybierz tryb aktywny w menu albo użyj:

```bash
guardian mode active
```

Program jeszcze raz opisze zmianę i poprosi o wpisanie potwierdzenia. Dopiero
wtedy może:

- ratować mocno uwierzytelnione wiadomości prawidłowe;
- przenosić bardzo prawdopodobny spam do odwracalnej kwarantanny.

Wciąż niczego nie kasuje trwale.

### Powrót do ochrony

W każdej chwili można użyć menu albo:

```bash
guardian mode protect
```

Przejście z trybu aktywnego do ochronnego natychmiast wyłącza purge, zeruje
zegar trybu aktywnego i rozpoczyna nowy, pełny 14-dniowy okres obserwacji.
Ponowne wydanie tego polecenia, gdy tryb ochronny już działa, nie rozpoczyna
okresu od nowa.

### Po 30 dniach trybu aktywnego: możliwe czyszczenie

Trwałe usuwanie nie powinno włączać się automatycznie tylko dlatego, że
minął określony dzień. Przy próbie włączenia Guardian ponownie sprawdzi:

- wcześniejszy, co najmniej 14-dniowy okres ochronny i jego bramki jakości;
- co najmniej 30 pełnych dni nieprzerwanego trybu aktywnego;
- brak wykrytych ważnych wiadomości w grupie spamu;
- brak spamu w grupie automatycznie uratowanej;
- kompletne, poprawne kopie bezpieczeństwa.

Najpierw zawsze uruchom:

```bash
guardian purge --dry-run
```

Przeczytaj podsumowanie. Po co najmniej 30 dniach poprawnej pracy trybu
aktywnego i zebraniu co najmniej 200 przykładów spamu oraz 200 ważnych
wiadomości — oraz dopiero gdy przez 30 dni nie było sprzecznej korekty
pewnego werdyktu — włącz czyszczenie w `guardian menu` albo poleceniem:

```bash
guardian purge enable
```

Od tej chwili zwykłe automatyczne przebiegi usuwają wyłącznie wiadomości,
które spełniły wszystkie blokady bezpieczeństwa. `guardian purge disable`
natychmiast wyłącza dalsze trwałe usuwanie. Ręczne `guardian purge` dodatkowo
wymaga wpisania słowa potwierdzającego.

## Sprawdzanie stanu

Stan z ostatniej doby:

```bash
guardian status --since 24h
```

Ogólny stan:

```bash
guardian status
```

W podsumowaniu najważniejsze są:

- **uratowane** — wiadomości przeniesione ze SPAM-u do Odebranych;
- **kwarantanna** — wiadomości zatrzymane jako spam;
- **do sprawdzenia** — decyzje wymagające człowieka;
- **błędy** — wiadomości pozostawione bez destrukcyjnego działania;
- **nauczone spam/ważne** — liczba korekt z potwierdzonym uczeniem Bayesa;
- **spełnia warunek wieku purge** — liczba wiadomości starszych niż 30 dni;
  przed usunięciem każda z nich przechodzi jeszcze kontrolę kopii, UID,
  UIDVALIDITY, skrótów i ponowny skan Rspamd.

## Ręczne uruchomienie

Próba bez zmian:

```bash
guardian run --dry-run
```

Zwykły przebieg:

```bash
guardian run
```

Jeśli drugi przebieg uruchomi się w czasie działania pierwszego, zakończy się
bezpiecznie zamiast wykonywać te same operacje dwukrotnie.

Jeżeli po wysłaniu polecenia MOVE serwer zerwie połączenie, Guardian zapisuje
ruch jako wymagający uzgodnienia. Przy kolejnym `guardian run` sprawdza cały
folder źródłowy i docelowy oraz porównuje pełny SHA-256 i skrót Message-ID:

- jedna zgodna kopia w celu i brak kopii w źródle → ruch zostaje potwierdzony;
- zgodna wiadomość tylko w źródle → bezpiecznie ponawia wcześniej zapisany
  ruch;
- kopie po obu stronach, więcej niż jedna zgodna kopia albo brak pewności →
  pozostawia stan jako niejednoznaczny i niczego nie kasuje.

Liczbę takich przypadków pokazuje `guardian status` jako **ruchy wymagające
uzgodnienia**. Kolejne przebiegi ponawiają bezpieczne sprawdzenie, ale stan
niejednoznaczny nigdy nie jest rozstrzygany przez arbitralne wybranie jednej
kopii. Jeśli licznik nie spada, nie usuwaj ani nie przenoś tych kopii ręcznie;
wykonaj `guardian doctor` i skorzystaj z procedury rozwiązywania problemów.

## Sterowanie usługą i silnikiem

```bash
guardian service status
guardian service install
guardian service uninstall

guardian stack status
guardian stack up
guardian stack down
```

- **service** — harmonogram uruchamiający Guardiana co 2 godziny;
- **stack** — lokalny silnik Rspamd, Redis i bezpieczny DNS.

Wyłączenie `service` zatrzymuje automatyczne skanowanie. Wyłączenie `stack`
powoduje, że Guardian pozostawia pocztę bez zmian do czasu ponownego
uruchomienia silnika.

Przed każdym automatycznym przebiegiem usługa sprawdza i w razie potrzeby
uruchamia Colimę oraz kontenery. Jeśli samonaprawa albo skan się nie powiedzie,
macOS pokazuje ogólne powiadomienie bez tematu, nadawcy, treści i sekretów.
Powtarzający się błąd powoduje najwyżej jedno takie powiadomienie na 24
godziny.

Po udanym sprawdzeniu poczty Guardian zabezpiecza model uczący w katalogu
`redis-backup` obok danych programu na Macu, poza dyskiem Colimy. Zachowuje
dwie generacje kopii, sprawdza ich sumy kontrolne i odmawia zastąpienia kopii
modelem o niższych licznikach uczenia. Kopia jest odświeżana po nowym uczeniu
lub po 12 godzinach. Błąd jej zapisu jest raportowany jako błąd przebiegu.
Uruchamianie filtra sprawdza też trwały zapis Redis, ponieważ sama odpowiedź
na test połączenia nie oznacza, że model jest bezpiecznie zapisywany.

`guardian.log` nie rośnie bez końca. Po przekroczeniu 5 MiB usługa zachowuje
bieżący zapis jako `guardian.log.1`, wcześniejszy jako `guardian.log.2` i
zaczyna nowy prywatny plik. Rotacja nie kasuje właśnie diagnozowanego logu.

Polecenia Dockera zawsze używają jawnie kontekstu `colima`; Guardian nie
zmienia globalnego kontekstu innych projektów użytkownika.
Colima nie dostaje osobnej usługi `brew services`: w razie potrzeby uruchamia
ją dopiero LaunchAgent Guardiana, bez przełączania globalnego kontekstu.

## Bezpieczny podgląd zaszyfrowanej kopii

Lista archiwum nie pokazuje danych wiadomości. Jeśli przed przywróceniem
chcesz rozpoznać konkretną kopię, wybierz podgląd w menu albo wpisz:

```bash
guardian archive show <ID>
```

Guardian odszyfruje kopię tylko na czas tej operacji i pokaże wyłącznie
oczyszczone nagłówki **Od**, **Temat** i **Data**. Usuwa pełne sekwencje
sterujące ANSI, nie wyświetla treści ani HTML, nie otwiera odnośników lub
załączników i nie zapisuje pokazanych nagłówków w bazie ani w logach.

## Dobre nawyki

- Raz dziennie sprawdź `AI-Do-sprawdzenia` podczas pierwszych dwóch tygodni.
- Raz w tygodniu przejrzyj `AI-Kwarantanna`, dopóki system się uczy.
- Używaj folderów uczących przy każdej pomyłce.
- Nie klikaj „wypisz się” w ewidentnym phishingu — taki odnośnik może
  potwierdzić przestępcy, że adres jest aktywny.
- Nie otwieraj załączników w kwarantannie.
- Dla legalnego newslettera od znanej firmy użyj oficjalnego mechanizmu
  rezygnacji dopiero po sprawdzeniu domeny.
