# Holograficzne Przestrzenie Sesji: Unifikacja Izolacji Procesów i Dostępu do Danych w Kognitywnych Systemach Operacyjnych

**Maciej Mazur** — Niezależny Badacz AI | Warszawa, Polska  
GitHub: Maciej-EriAmo/Holomem  
Wersja: 2.5.0 | Data: 2026-04-10 | Licencja: CC BY 4.0

---

## Streszczenie

Proponujemy **Holograficzne Przestrzenie Sesji (HSS)** — zunifikowany mechanizm izolacji procesów, tymczasowego przechowywania danych i komunikacji międzyprocesowej (IPC). W przeciwieństwie do tradycyjnych modeli DAC/MAC, HSS wyprowadza capability tokeny bezpośrednio z prywatnej geometrii kognitywnej użytkownika — przestrzeni stanów **$\Phi$** architektury Holon. Każda sesja procesowa otrzymuje unikalny *token zdolności sesji* kryptograficznie powiązany z $\Phi$.

Kluczową innowacją jest przejście od liniowych Holograficznych Reprezentacji Zredukowanych (HRR) do formalnie trudnego problemu **Ring Learning with Errors (Ring-LWE)** nad pierścieniem wielomianów ilorazowych $R_q = \mathbb{Z}_q[X]/(X^N + 1)$, zgodnie z konstrukcją Lyubashevsky-Peikert-Regev (LPR). Wprowadzamy **Dynamiczne Holograficzne Przestrzenie Pamięci Zadań** regulowane przez **PrismMaski**: mechanizm pochodnych kluczy oparty na KDF, który umożliwia ciągłe, częściowe atenuowanie dostępu bez naruszania założeń RLWE o małych normach wielomianów.

Centralna teza HSS: **agent istnieje tylko w przestrzeni zdefiniowanej przez ukryty operator projekcji zależny od sekretu, a wszystkie operacje poza tą przestrzenią są informacyjnie zerowe.** Bezpieczeństwo nie jest zatem zewnętrzną warstwą polityki — jest topologiczną właściwością przestrzeni wykonania. Kontrola dostępu staje się *warunkiem zaistnienia*, nie barierą. Convolution Bleed jest formalnie scharakteryzowany jako właściwość mnożenia wielomianów w $R_q$ (Sekcja 2.3). Moduł LSM jądra działa jako lekki **filtr upcall**: wszystkie decyzje kryptograficzne są delegowane do uprzywilejowanego demona przestrzeni użytkownika, zapewniając że żaden plaintext nigdy nie trafia do pamięci jądra.

**Słowa kluczowe:** Ring-LWE, LPR, bezpieczeństwo oparte na capability, izolacja procesów, PrismMask, filtr upcall, HolonOS, post-quantum

---

## 1. Wprowadzenie

Nowoczesne systemy operacyjne zabezpieczają zasoby procesów za pomocą list kontroli dostępu (ACL), identyfikatorów użytkowników i obowiązkowych frameworków kontroli dostępu (SELinux, AppArmor). Mechanizmy te mają wspólną fundamentalną słabość: **są zewnętrzne wobec danych, które chronią**. Skompromitowany proces działający pod UID użytkownika dziedziczy całą jego ambient authority, włącznie z dostępem do katalogów tymczasowych (`/tmp`), gniazd IPC i możliwością odczytu poufnych plików. Co więcej, klasyczne mechanizmy wymuszają binarny paradygmat — dostęp jest albo w pełni przyznany, albo całkowicie odmówiony.

Architektura kognitywna Holon [Mazur, 2026] wprowadziła radykalną alternatywę: informacje nie są przechowywane jako plaintext z zewnętrznymi zamkami, lecz są **kryptograficznie powiązane** z prywatną geometrią użytkownika $\Phi$. HSS rozszerza tę zasadę do jądra systemu operacyjnego.

System działa na dwóch formalnie odrębnych, ale sprzężonych warstwach:

1. **Warstwa kryptograficzna**: RLWE w stylu LPR dostarcza tokeny capability twarde w sensie IND-CPA. Bezpieczeństwo na tej warstwie jest bezwarunkowe wobec jakiejkolwiek interpretacji semantycznej.
2. **Warstwa semantyczna**: Przestrzeń stanów $\Phi$ dostarcza metryzowaną geometrię embeddingów. PrismMaski działają na tej warstwie, używając pochodnych kluczy opartych na KDF do osiągania miękkiej atenuacji z gwarantowanym SNR w autoryzowanych pryzmatach.

Krytyczną zasadą projektową HSS jest **niezmiennik braku plaintextu w jądrze**: moduł LSM działa wyłącznie jako filtr upcall, delegując wszystkie decyzje deszyfrowania i polityki do uprzywilejowanego demona przestrzeni użytkownika.

W tym artykule: (i) ustanawiamy fundament kryptograficzny LPR z odpowiednio rozdzielonymi ograniczeniami błędu i uwierzytelnionym wiązaniem kontekstu; (ii) podajemy formalną definicję $\Phi$ z jawnym modelem szumu; (iii) charakteryzujemy Convolution Bleed i wprowadzamy atenuację opartą na KDF; (iv) opisujemy poprawioną architekturę jądra jako filtr upcall; oraz (v) przedstawiamy przestrzeń wykonania programów dla agentów HolonOS.

---

## 2. Formalne Podstawy

### 2.1 Warstwa Kryptograficzna: LPR z Uwierzytelnionym Wiązaniem Kontekstu

Przyjmujemy schemat szyfrowania z kluczem publicznym LPR [LPR13] nad:

$$R_q = \mathbb{Z}_q[X]/(X^N + 1)$$

gdzie $N$ jest potęgą 2, a $q$ jest liczbą pierwszą z $q \equiv 1 \pmod{2N}$.

**Rozdzielenie parametrów.** Rozróżniamy trzy rozkłady małych norm:

- $\chi_s$: rozkład klucza tajnego, $\|s\|_\infty \leq B_s$
- $\chi_e$: rozkład błędu, $\|e\|_\infty \leq B_e$
- $\chi_r$: rozkład efemerycznego sekretu, $\|r\|_\infty \leq B_r$

**Generowanie klucza.** Sekret $s \leftarrow \chi_s$. Klucz publiczny:

$$b = a \cdot s + e \pmod{q}, \quad a \leftarrow R_q,\quad e \leftarrow \chi_e$$

**Uwierzytelnione szyfrowanie.** Aby powiązać binaryzowany stan $\hat{S}_t \in \{0,1\}^N$ ze specyficznym kontekstem pliku, dołączamy pole **Dodatkowych Uwierzytelnionych Danych (AAD)** zawierające numer i-węzła i identyfikator sesji. Plaintext jest modyfikowany przed szyfrowaniem:

$$\hat{S}_t^{\text{ctx}} = \hat{S}_t \oplus H(\text{inode} \;\|\; \text{session\_id} \;\|\; \text{PrismMask\_policy})$$

gdzie $H$ to kryptograficzna funkcja skrótu odporna na kolizje (SHA3-256). Szyfrowanie przebiega z $r \leftarrow \chi_r$, $e_1, e_2 \leftarrow \chi_e$:

$$u = a \cdot r + e_1 \pmod{q}$$

$$v = b \cdot r + e_2 + \left\lfloor \frac{q}{2} \right\rfloor \cdot \hat{S}_t^{\text{ctx}} \pmod{q}$$

**Bezpieczeństwo wiązania kontekstu.** Proces posiadający ważny $s_{\text{sess}}$, ale próbujący odszyfrować szyfrogram utworzony dla innego i-węzła lub polityki PrismMask, odzyska $\hat{S}_t^{\text{ctx}'} \neq \hat{S}_t^{\text{ctx}}$, ponieważ $H(\text{inode}' \| \ldots) \neq H(\text{inode} \| \ldots)$. Zapobiega to atakom Confused Deputy, gdzie proces o wysokich uprawnieniach jest oszukiwany do odszyfrowania danych o niskiej integralności: odzyskany plaintext jest kryptograficznie powiązany z oczekiwanym kontekstem i jest semantycznie niespójny przy niezgodności kontekstu.

**Deszyfrowanie.** Dla poprawnego $s$:

$$\tilde{S} = v - s \cdot u = \lfloor q/2\rfloor \cdot \hat{S}_t^{\text{ctx}} + \underbrace{e \cdot r + e_2 - s \cdot e_1}_{=\,\delta}$$

Warunek poprawności: $\|\delta\|_\infty \leq B_e(B_r + B_s + 1) < q/4$.

Dla parametrów w stylu Kyber ($N=256$, $q=3329$, $B_e = B_r = B_s = 2$): $\|\delta\|_\infty \leq 2 \cdot 5 = 10 \ll 832 = q/4$. ✓

Schemat osiąga **bezpieczeństwo IND-CPA** na podstawie założenia Decision-RLWE [LPR13].

---

### 2.2 Warstwa Semantyczna: Przestrzeń Stanów $\Phi$

**Definicja 2.1 (Przestrzeń Stanów Φ).** Przestrzeń stanów $\Phi$ to krotka $(\mathcal{S}, d, F_\theta, \pi)$, gdzie:

- $\mathcal{S} \subset \mathbb{R}^{L \times k \times d}$ to zwarta przestrzeń metryczna z $d(S, S') = \|S - S'\|_2$
- $F_\theta: \mathcal{S} \times \mathcal{O} \to \mathcal{S}$ jest Lipschitz-ciągła ze stałą $\lambda_F < 1$ (kontrakcja)
- $\pi: \mathcal{S} \to \{0,1\}^N$ to operator projekcji zdefiniowany poniżej

**Dynamika stanu.**

$$S_{t+1} = F_\theta(S_t, o_t) + \varepsilon_t, \quad \|\varepsilon_t\|_2 \leq \varepsilon_{\max}$$

W implementacji Holon v5.11, $F_\theta$ to całkujący filtr z przeciekiem z obserwacjami osadzonymi przez KuRz:

$$S_{t+1} = (1 - \eta)\, S_t + \eta\, \hat{o}_t + \varepsilon_t$$

Poziom szumu w stanie ustalonym: $\sigma_\infty^2 = \frac{\eta}{2 - \eta} \cdot \sigma_\varepsilon^2$.

**Operator projekcji z histerezą (naprawa stabilności).** Naiwna projekcja $\hat{S}_t = \text{sign}(W_{\text{proj}} \cdot \text{vec}(S_t))$ jest niestabilna blisko granicy decyzyjnej: składowa stanu $p_i \approx 0$ zmienia bit $i$ pod wpływem infinitezymalnego zaburzenia $\varepsilon_t$, produkując inny token capability i czyniąc wszystkie dane zaszyfrowane w poprzedniej sesji nieodwracalnymi. Jest to **problem niestabilności projekcji**.

HSS v2.4 rozwiązuje to dwoma komplementarnymi mechanizmami:

1. **Zamrożona macierz sesji.** W momencie tworzenia sesji hss-daemon próbkuje $W_{\text{proj}} \leftarrow \mathcal{N}(0, I_{N \times Lkd})$ raz i przechowuje w wpisie session keyring. $W_{\text{proj}}$ jest niezmienna przez cały czas życia sesji. Projekcja $\hat{S}_{\text{sess}} = \text{sign}(W_{\text{proj}} \cdot \text{vec}(S_{t_0}))$ jest obliczana raz przy starcie sesji ze stanu początkowego $S_{t_0}$ i używana jako statyczny token capability. Późniejsza dynamika $\Phi$ nie zmienia $\hat{S}_{\text{sess}}$; wpływa tylko na żywy stan semantyczny, nie na materiał klucza kryptograficznego.

2. **Pasmo histerezy dla ponownego kluczowania.** Gdy wymagane jest jawne ponowne kluczowanie (np. na granicach epok w rozszerzeniu Double Ratchet), stosowane jest pasmo histerezy szerokości $2\delta_\pi$: współczynniki z $|p_i| < \delta_\pi$ nie są ponownie binaryzowane, lecz dziedziczą poprzednią wartość bitu (sticky bit). Tylko współczynniki z $|p_i| \geq \delta_\pi$ produkują nowy bit. Parametr $\delta_\pi$ jest ustawiony na $3\sigma_\infty$ (trzy odchylenia standardowe stanu ustalonego), zapewniając że zaburzenia błądzenia losowego nie powodują przerzucenia bitu z prawdopodobieństwem $> 0,13\%$ na współczynnik na epokę.

Formalnie, stabilna projekcja to:

$$\hat{S}_t[i] = \begin{cases} \hat{S}_{t-1}[i] & \text{jeśli } |p_i| < \delta_\pi \\ \mathbf{1}[p_i > 0] & \text{w przeciwnym razie} \end{cases}, \quad p_i = (W_{\text{proj}} \cdot \text{vec}(S_t))[i]$$

*Uwaga o parametrach.* Wartości $\delta_\pi = 3\sigma_\infty$ są heurystycznie motywowane regułą trzech sigm dla odrzucania szumu gaussowskiego. W praktyce użytkownicy o wyższej wariancji stanu kognitywnego (np. profile wysokiego pobudzenia lub rozproszenia uwagi) będą wykazywać większy efektywny $\sigma_\infty$. Planowane rozszerzenie HSS (PoC v2) będzie wspierać **adaptacyjne parametry projekcji**: hss-daemon szacuje $\hat{\sigma}_\infty$ z okna kroczącego próbek stanu $\Phi$ i dostosowuje $\delta_\pi$ online.

**Twierdzenie o separacji.** Bezpieczeństwo IND-CPA schematu RLWE jest zachowane dla dowolnego rozkładu $\hat{S}_t$, niezależnie od dynamiki $\Phi$. Warstwy semantyczna i kryptograficzna nie narzucają wspólnych założeń.

---

### 2.3 Convolution Bleed: Formalna Charakteryzacja i Atenuacja Oparta na KDF

**Uwaga o NTT i mnożeniu wielomianów.** Convolution Bleed wynika z mnożenia wielomianów w $R_q$, a nie z algorytmu NTT per se. Właściwość globalnego mieszania zachodzi również w reprezentacji współczynnikowej.

**Lemat 2.2 (Globalne Mieszanie).** Niech $f, g \in R_q$ z $g \neq 0$. Iloczyn $h = f \cdot g \pmod{X^N + 1}$ spełnia:

$$h[k] = \sum_{j=0}^{N-1} f[j] \cdot g[(k-j) \bmod N] \cdot (-1)^{\lfloor (k-j+N)/N \rfloor}$$

Jeśli $f$ ma nośnik na pojedynczym indeksie $j_0$, to $h[k] = f[j_0] \cdot g[(k-j_0) \bmod N] \cdot (\pm 1)$, co jest ogólnie niezerowe dla wszystkich $k$, gdy $g$ nie ma zerowych współczynników mod $q$. $\square$

**Wniosek 2.3 (Convolution Bleed).** Niech $m_j \in R_q$ ma nośnik na pryźmie $\mathcal{P}_j \subset [N]$. Błąd deszyfrowania $\Delta = m_j \cdot u$ ma ogólnie pełny nośnik na $[N]$, w tym na indeksach poza $\mathcal{P}_j$.

**Wcześniejsze podejście i jego wada.** Poprzednie wersje HSS stosowały atenuację przez bezpośrednią modyfikację klucza tajnego: $s' = s + m_j^{\text{sparse}}$. Ma to krytyczną wadę bezpieczeństwa: przeciwnik, który uzyska wiele atenuowanych kluczy $s, s', s'', \ldots$ dla różnych polityk, może obliczyć ich różnice i odtworzyć wielomiany maskujące $m_j$. Różnice te ujawniają informacje strukturalne o partycji pryzmatycznej, potencjalnie umożliwiając ataki odtwarzające nieautoryzowane pryzmaty.

**Atenuacja oparta na KDF (korekta v2.5).** Poprawne podejście przenosi maskowanie całkowicie poza klucz na pochodną klucza per-polityka. Sekret rodzica $s$ nigdy nie jest modyfikowany. Zamiast tego każdy kontekst polityki otrzymuje niezależny pochodny klucz:

$$s_{\text{policy}} = \text{KDF}(s_{\text{sess}},\; \text{policy\_id},\; \text{prism\_set}) \pmod{q}$$

gdzie $\text{policy\_id}$ to unikalny identyfikator polityki dostępu, a $\text{prism\_set} \subseteq \{\mathcal{P}_1, \ldots, \mathcal{P}_K\}$ to zbiór autoryzowanych pryzmatów. KDF (HKDF-SHA3-256) produkuje wyjście obliczeniowo nieodróżnialne od jednostajnego w $R_q$ bez znajomości $s_{\text{sess}}$. Zapewnia to dwie gwarancje:

1. **Niezależność kluczy**: $s_{\text{policy}}$ i $s_{\text{sess}}$ są obliczeniowo nieskorelowane; przeciwnik posiadający wiele wartości $s_{\text{policy}}$ nie może odtworzyć $s_{\text{sess}}$ ani żadnego innego klucza polityki (na podstawie bezpieczeństwa PRF HKDF).
2. **Zachowanie rozkładu**: $s_{\text{policy}}$ jest równomiernie rozłożony w $R_q$ z obcięciem do małej normy, spełniając wymagania RLWE dotyczące sekretu niezależnie od tego, czy $s_{\text{sess}}$ był mały.

**Atenuacja przez ponowne szyfrowanie szyfrogramu.** Kontrola dostępu na poziomie pryzmatów jest wymuszana nie przez degradację klucza, lecz przez **selektywne ponowne szyfrowanie**: dane w autoryzowanych pryzmatach $\mathcal{P}_{\text{allow}}$ są ponownie szyfrowane pod $s_{\text{policy}}$ przez hss-daemon przed dostarczeniem; dane w maskowanych pryzmatach $\mathcal{P}_{\text{deny}}$ są zastępowane świeżymi szyfrowaniami LPR zera pod jednorazowym kluczem nieznanym procesowi potomnemu.

Formalnie, dla każdego pryzmatu $\mathcal{P}_j$:

$$\text{szyfrogram}_j^{\text{potomek}} = \begin{cases} \text{LPR.ReEnc}(s_{\text{sess}} \to s_{\text{policy}},\; \text{ct}_j) & \text{jeśli } \mathcal{P}_j \in \mathcal{P}_{\text{allow}} \\ \text{LPR.Enc}(k_{\text{jednorazowy}},\; \mathbf{0}) & \text{jeśli } \mathcal{P}_j \in \mathcal{P}_{\text{deny}} \end{cases}$$

Ponowne szyfrowanie jest wykonywane przez hss-daemon, który posiada zarówno $s_{\text{sess}}$, jak i $s_{\text{policy}}$; deszyfruje pod $s_{\text{sess}}$ i ponownie szyfruje pod $s_{\text{policy}}$ w jednej atomowej operacji w przestrzeni użytkownika. Żaden plaintext nie trafia do pamięci jądra.

**Analiza SNR.** W tej konstrukcji nie ma Convolution Bleed do autoryzowanych pryzmatów na poziomie klucza, ponieważ klucz nigdy nie jest modyfikowany. Dziecko poprawnie odszyfrowuje autoryzowane pryzmaty z pełnym SNR. Maskowane pryzmaty odszyfrowują do zera — czysta twarda granica zamiast probabilistycznej.

---

## 3. Holograficzne Przestrzenie Sesji: Model Capability

### 3.1 Token Zdolności Sesji i Rotacja Epoki

Każda interaktywna sesja jest powiązana z prywatnym $\Phi^2$ użytkownika. Hss-daemon utrzymuje **bazowy sekret sesji** (`base_secret`) oraz wyprowadza z niego **sekret epoki** rotowany co $T_{\text{epoch}}$ sekund (domyślnie 300s):

$$s_{\text{sess}} = \text{HMAC}(\text{base\_secret},\; \text{epoch}) \pmod{q}, \quad \text{epoch} = \lfloor t / T_{\text{epoch}} \rfloor$$

Rotacja epoki zapewnia **forward secrecy między epokami**: kompromitacja $s_{\text{sess}}$ w epoce $e$ nie ujawnia sekretów epok $e-1, e-2, \ldots$. Baza `base_secret = HMAC(CSPRNG, \Phi^2 \| \text{"hss-sess-v1"})$ jest niezmienna przez czas życia sesji i przechowywana wyłącznie w kernel keyring.

Capability token agenta jest wyprowadzany przez JSON-zakodowany kontekst, eliminując ataki przez wstrzyknięcie łańcucha znaków:

$$s_A = \text{KDF}(s_{\text{sess}},\; \text{JSON}(\{\text{"task"}: \text{task\_id},\; \text{"prisms"}: \mathcal{P}_{\text{allow}}\}))$$

Weryfikacja capability odbywa się przez zbiór (`set`), nie porównanie podłańcuchów: $\text{prism\_id} \in \mathcal{P}_{\text{allow}}$ musi być dokładnym elementem, nie prefiksem ani podłańcuchem.

### 3.2 Percepcja Danych jako Deszyfrowanie

Dane zapisane przez proces są szyfrowane pod $s_{\text{sess}}$ z wiązaniem kontekstu (Sekcja 2.1). Szyfrogram $(u_t, v_t)$ jest przechowywany w `security.hss.lock` xattr. Deszyfrowanie jest wykonywane wyłącznie przez hss-daemon w chronionej przestrzeni użytkownika; moduł LSM nigdy nie otrzymuje ani nie przechowuje plaintextu (Sekcja 4).

Nieautoryzowany proces posiadający $s' \neq s_{\text{sess}}$ odzyska wartość obliczeniowo nieodróżnialną od jednostajnego szumu na podstawie Decision-RLWE. Proces posiadający ważny $s_{\text{sess}}$, ale celujący w nieodpowiedni i-węzeł, odzyska semantycznie niespójny plaintext z powodu wiązania kontekstu. Oba przypadki są nieodróżnialne od szumu dla nieautoryzowanego procesu.

### 3.3 Dynamiczne Holograficzne Przestrzenie Pamięci Zadań

**Dynamiczna Holograficzna Przestrzeń Pamięci Zadania** to izolowany kontekst kryptograficzny tworzony przy uruchamianiu zadania:

$$(u_t,\, v_t) = \text{LPR.Enc}(s_{\text{sess}},\; \pi(S_t),\; \text{AAD}_t)$$

gdzie $\text{AAD}_t = H(\text{inode}_t \| \text{session\_id} \| \text{PrismPolicy}_t)$.

Przy zakończeniu zadania hss-daemon kasuje $s_{\text{sess}}$ z wpisu keyring powiązanego z PID zadania. Szyfrogram pozostaje na dysku, ale jest nieodtwarzalny bez skasowanego klucza.

### 3.4 PrismMaski i Atenuacja Oparta na KDF

Gdy proces nadrzędny uruchamia potomka wymagającego ograniczonego dostępu, hss-daemon wyprowadza klucz specyficzny dla polityki używając konstrukcji KDF z Sekcji 2.3:

$$s_{\text{policy}} = \text{KDF}(s_{\text{sess}},\; \text{policy\_id},\; \mathcal{P}_{\text{allow}})$$

Proces potomny otrzymuje $s_{\text{policy}}$ w swoim wpisie keyring. Hss-daemon wykonuje selektywne ponowne szyfrowanie: autoryzowane pryzmaty są ponownie szyfrowane pod $s_{\text{policy}}$; odmówione pryzmaty otrzymują świeże szyfrowania zera pod efemerycznymi jednorazowymi kluczami. Potomek odszyfrowuje wszystkie pryzmaty używając $s_{\text{policy}}$, spójnie odzyskując autoryzowaną zawartość i zero-sygnał dla odmówionych pryzmatów.

**Drzewo capability.** Pochodna polityki jest przechodnia: dziecko może dalej delegować do wnuka z podzbiorem własnego $\mathcal{P}_{\text{allow}}$:

$$s_{\text{wnuk}} = \text{KDF}(s_{\text{policy}},\; \text{policy\_id}',\; \mathcal{P}_{\text{allow}}' \subseteq \mathcal{P}_{\text{allow}})$$

Definiuje to **drzewo capability** zakorzenione w $s_{\text{sess}}$ Φ, gdzie każda krawędź to krok KDF, a każdy węzeł ma ściśle nierosnący dostęp do partycji pryzmatycznej. Węzeł nie może przyznać dzieciom dostępu do pryzmatów, których sam nie posiada.

### 3.5 Przestrzeń Wykonania Programów: Cykl Życia Agentów w HolonOS

HSS dostarcza kryptograficzny fundament dla kluczowej zdolności HolonOS: możliwości **syntezy, wykonania i izolacji programów na żądanie** w odpowiedzi na intencję użytkownika.

**Motywacja.** HolonOS jest zaprojektowany jako system operacyjny pierwszej kolejności agentów. Zamiast uruchamiać stały zestaw aplikacji, $\Phi$ syntetyzuje programy specyficzne dla zadania (agenty) gdy są potrzebne — np. agent email, agent kalendarza, agent pobierania stron internetowych — i kończy je po zakończeniu zadania. Każdy syntetyzowany agent musi być: (i) izolowany od rdzenia stanu kognitywnego $\Phi$; (ii) ograniczony do dokładnie tych zasobów, których wymaga jego zadanie; (iii) niezdolny do modyfikacji swojego twórcy. HSS dostarcza wszystkie trzy właściwości przez drzewo capability.

**Agent jako poddrzewo capability.** Gdy $\Phi$ decyduje się uruchomić agenta $A$ dla zadania $T$, hss-daemon wyprowadza klucz capability agenta:

$$s_A = \text{KDF}(s_{\text{sess}},\; \text{agent\_id}_A,\; \mathcal{P}_{\text{zadanie}(T)})$$

gdzie $\mathcal{P}_{\text{zadanie}(T)} \subseteq \{\mathcal{P}_1, \ldots, \mathcal{P}_K\}$ to minimalny zbiór pryzmatów wymagany dla zadania $T$ (zasada minimalnych uprawnień). Agent $A$ może czytać i pisać tylko w obrębie swoich autoryzowanych pryzmatów. Rdzeń stanu $\Phi$ ($\Phi^2$, pamięć epizodyczna, osie emocjonalne) rezyduje w pryzmatach nieprzyznanych $A$; są one kryptograficznie niewidoczne dla $A$.

**Cykl życia agenta:**

```
Φ identyfikuje potrzebę zadania T
        ↓
hss-daemon wyprowadza s_A = KDF(s_sess, agent_id, P_zadanie)
        ↓
Agent A uruchamiany z s_A w keyring (brak dostępu do s_sess)
        ↓
Agent A wykonuje: czyta/pisze tylko pryzmaty P_zadanie
        ↓
Wynik zapisywany do pryzmatu P_wynik (czytelny przez Φ)
        ↓
Zadanie zakończone: s_A kasowany z keyring, agent kończony
        ↓
Φ czyta wynik z P_wynik używając s_sess
```

**Ochrona przed zapisem rdzenia Φ.** Agent $A$ posiada $s_A$ autoryzujący zapisy tylko do $\mathcal{P}_{\text{zadanie}(T)}$. Wiązanie kontekstu AAD zawiera agent\_id i task\_id; każda próba $A$ zapisu do pryzmatu poza $\mathcal{P}_{\text{zadanie}(T)}$ produkuje szyfrogram z niezgodnym AAD, który hss-daemon odrzuca. Złośliwy lub błędny agent nie może zapisać do stanu kognitywnego $\Phi$ nawet jeśli próbuje. To jest kluczowa gwarancja odróżniająca HolonOS od obecnych frameworków agentowych: **wygenerowany kod nie może modyfikować stanu swojego twórcy z mocy konstrukcji, nie z mocy konwencji.**

**Pryzmat poświadczeń.** Zadania wymagające zewnętrznego uwierzytelnienia (np. email przez SMTP/OAuth, wywołania API) potrzebują dostępu do sekretów, które muszą być: izolowane od pamięci semantycznej $\Phi$, niewidoczne dla innych agentów i nie zwracane do $\Phi$ jako plaintext. HSS dostarcza to przez **pryzmat poświadczeń** $\mathcal{P}_{\text{cred}}$: dedykowany pryzmat, którego zawartość jest zapieczętowana w czasie provisioningu i dostępna tylko dla agentów, których polityka jawnie zawiera $\mathcal{P}_{\text{cred}}$. Pryzmat pochodzi z osobnego korzenia:

$$s_{\text{cred}} = \text{KDF}(s_{\text{hw}},\; \text{"hss-cred-v1"},\; \text{service\_id})$$

gdzie $s_{\text{hw}}$ to sekret wspierany sprzętowo (klucz główny TPM lub sekret TrustZone TA). Poświadczenia są zatem zapieczętowane do sprzętu i izolowane nawet od głównego klucza sesji $\Phi$.

**Typy agentów:**

| Typ | Czas życia | Stan | Przykład |
|---|---|---|---|
| **Efemeryczny** | Pojedyncze zadanie, kończy się | Brak persystencji | Wyślij email, pobierz URL |
| **Hibernowany** | Zawieszony między aktywacjami | Persystowany w $\mathcal{P}_{\text{zadanie}}$ | Monitor kalendarza, obserwator przypomnień |
| **Trwały** | Działa ciągle | Pełny stan we własnym poddrzewie pryzmatów | Indekser tła, agent synchronizacji |

Wszystkie trzy klasy dzielą te same gwarancje izolacji capability. Hibernowane agenty serializują swój stan do plików zaszyfrowanych HSS w $\mathcal{P}_{\text{zadanie}}$ przy zawieszeniu; stan jest nieodtwarzalny bez $s_A$, który jest ponownie wyprowadzany z $s_{\text{sess}}$ przy wybudzeniu.

---

## 4. Architektura Jądra: LSM jako Filtr Upcall

Żaden plaintext nigdy nie trafia do pamięci jądra. Moduł LSM `security_holo` działa wyłącznie jako **filtr upcall**: przechwytuje operacje VFS i deleguje decyzję dostępu do hss-daemon przez uwierzytelnione gniazdo Unix.

### 4.1 Przegląd Architektury

```
┌───────────────────────────────────────────────────────┐
│                  Przestrzeń Użytkownika               │
│  ┌─────────────────────────────────────────────────┐ │
│  │         hss-daemon (uprzywilejowany)            │ │
│  │                                                 │ │
│  │  Odbiera upcall: (PID, inode, operacja)         │ │
│  │  1. Pobierz s_sess z kernel keyring (PID)       │ │
│  │  2. Pobierz (a, u, v) z xattr i-węzła          │ │
│  │  3. LPR.Dec → S̃  (mnożenie wielomianów NTT)   │ │
│  │  4. Weryfikuj wiązanie kontekstu AAD            │ │
│  │  5. Oblicz zaślepioną wariancję σ²(S̃)         │ │
│  │  6. Decyzja:                                    │ │
│  │     • σ² < θ  → ZEZWÓL                         │ │
│  │     • σ² ≥ θ  → ODMÓW                          │ │
│  │  7. Zwróć zezwól/odmów do LSM przez socket     │ │
│  └────────────────────┬────────────────────────────┘ │
│                       │  Gniazdo Unix (HMAC-auth)     │
└───────────────────────┼───────────────────────────────┘
                        │
┌───────────────────────┼───────────────────────────────┐
│                  Przestrzeń Jądra                     │
│  ┌────────────────────▼────────────────────────────┐ │
│  │      security_holo (LSM filtr upcall)           │ │
│  │                                                 │ │
│  │  security_inode_permission / security_file_open │ │
│  │  → wyślij upcall(PID, inode, op) do hss-daemon  │ │
│  │  → czekaj na odpowiedź zezwól/odmów             │ │
│  │  → wymusz POSIX -EACCES przy odmowie            │ │
│  │                                                 │ │
│  │  BRAK PLAINTEXTU. BRAK DESZYFROWANIA.           │ │
│  └─────────────────────────────────────────────────┘ │
│  ┌─────────────────────────────────────────────────┐ │
│  │     Nakładka HolonFS (warstwa xattr VFS)        │ │
│  │     security.hss.lock  = { a, u, v } ∈ R_q     │ │
│  │     security.hss.policy = blob PrismPolicy      │ │
│  │     security.hss.threshold = θ                  │ │
│  └─────────────────────────────────────────────────┘ │
└───────────────────────────────────────────────────────┘
```

### 4.2 Protokół Upcall

Protokół upcall między `security_holo` a hss-daemon:

1. Hook LSM odpala na `security_inode_permission(inode, mask)`.
2. LSM wysyła podpisaną wiadomość upcall: `{ pid, inode_nr, op_mask, timestamp }` przez uwierzytelnione gniazdo Unix.
3. Hss-daemon wykonuje deszyfrowanie, weryfikację wiązania kontekstu i **zaślepiony sprawdzian wariancji** w przestrzeni użytkownika (patrz poniżej).
4. Hss-daemon zwraca `{ decyzja: ZEZWÓL | ODMÓW, nonce: u64 }`.
5. LSM weryfikuje że nonce pasuje do oczekującego upcall, następnie wymusza decyzję.

Gniazdo jest uwierzytelniane przez HMAC-SHA256 kluczem ustanowionym przy starcie demona przez kernel keyring, uniemożliwiając nieuprzywilejowanym procesom wstrzykiwanie odpowiedzi zezwól/odmów.

**Zaślepiony sprawdzian wariancji.** Gołe kryterium wariancji $\sigma^2(\tilde{S}) < \theta \Rightarrow \text{ZEZWÓL}$ tworzy wyroczniowy side-channel deszyfrowania: przeciwnik może składać manipulowane szyfrogramy i obserwować ZEZWÓL/ODMÓW, aby binarnym przeszukiwaniem odtworzyć informacje o plaintextcie. HSS v2.5 eliminuje tę wyrocznię przez dwa mechanizmy:

**(a) Wstrzykiwanie szumu.** Przed oceną wariancji demon dodaje skalibrowany szum gaussowski $\xi \sim \mathcal{N}(0, \sigma_\xi^2)$ do odzyskanego $\tilde{S}$, gdzie $\sigma_\xi = \beta \cdot \theta$ dla czynnika zaślepiającego $\beta \in (0,05; 0,1)$. Efektywna granica decyzyjna $\sigma^2(\tilde{S} + \xi) < \theta$ jest stochastyczna: prawidłowe deszyfrowania (niskie $\sigma^2$) przechodzą z prawdopodobieństwem $> 1 - 10^{-6}$, podczas gdy celowo sfabrykowane graniczne szyfrogramy produkują niespójne odpowiedzi ZEZWÓL/ODMÓW nieujawniające żadnego exploitowalnego gradientu.

**(b) Ograniczanie szybkości.** Hss-daemon wymusza per-PID limit szybkości decyzji $R_{\max} = 100$ upcall/sekundę. Żądania przekraczające ten limit otrzymują `-EAGAIN` z wykładniczym wycofaniem. Ogranicza to przepustowość zapytań wyroczni przeciwnika do $O(100)$ bitów/sekundę informacji — niewystarczające do praktycznego odtworzenia klucza 256-bitowego.

**Wydajność.** Synchroniczny upcall dodaje jeden round-trip IPC na zimnej ścieżce. Optymalizacja gorącej ścieżki: hss-daemon utrzymuje per-PID pamięć podręczną zezwoleń (TTL: 100ms). Szacowane opóźnienie: $\approx 50\,\mu\text{s}$ (zimna, z NTT) i $< 1\,\mu\text{s}$ (z cache).

**TOCTOU i unieważnianie cache.** Zmiany polityki wyzwalają jawną wiadomość unieważnienia cache `policy_invalidate(PID, inode)` z hss-daemon do modułu LSM, redukując okno TOCTOU do opóźnienia round-trip gniazda ($< 1\,\mu\text{s}$).

**Odporność na awarie demona (mitygacja SPOF).**

- Hss-daemon jest zarządzany przez systemd z `Restart=always` i `RestartSec=50ms`. Klucze sesji są przechowywane w kernel keyring (nie w pamięci sterty demona), więc przeżywają crash i są natychmiast dostępne dla zrestartowanego demona.
- Przy timeout upcall (brak odpowiedzi w ciągu 5ms), moduł LSM stosuje **politykę degradacji**: operacje odczytu na już otwartych deskryptorach pliku zwracają `-EAGAIN`; nowe wywołania `open()` do zapisu zwracają `-EACCES`; wywołania `open()` tylko do odczytu są kolejkowane na 500ms oczekując na odtworzenie demona.
- Wątek watchdog w hss-daemon zrzuca keyring do kopii zapasowej zapieczętowanej TPM co 30 sekund.

**Współbieżność podczas okna restartu.** Spójność zapewnia standardowy blokada i-węzła VFS (`inode->i_rwsem`). HSS nie wprowadza dodatkowego menedżera blokad.

**Niezależność protokołu watchdog.** Mechanizm restartu demona jest opisany używając systemd jako implementacji referencyjnej, ale protokół watchdog jest niezależny od implementacji: dowolny supervisor monitorujący żywotność gniazda Unix hss-daemon (przez periodyczną wymianę `PING`/`PONG`) implementuje wymagane zachowanie. Dotyczy to zarówno środowisk embedded (np. s6, runit), jak i kontenerów OCI.

### 4.3 Relacja do Wcześniejszego Twierdzenia o "Zero-Knowledge"

Poprzednie wersje twierdziły że moduł jądra wykonuje "zero-knowledge semantic mediation." Twierdzenie to było błędne: obliczenie $\sigma^2(\tilde{S})$ wymaga deszyfrowania, które wymaga $s_{\text{sess}}$, który nie może rezydować w jądrze bez ujawniania plaintextu. Poprawiona architektura jest jawna: **jądro jest przekaźnikiem wymuszania polityki, nie wyrocznią kryptograficzną.**

---

## 5. Holograficzne IPC (H-IPC) z Atenuacją Per-Pryzmat

### 5.1 Kanał Bazowy: KEM z Forward Secrecy

HSS ustanawia wspólne kanały przez dwuwiadomościowy protokół KEM:

1. $A$ generuje efemeryczną parę kluczy: $s_{\text{ch}} \leftarrow \chi_s$, $b_{\text{ch}} = a_{\text{ch}} \cdot s_{\text{ch}} + e_{\text{ch}}$, przesyła $(a_{\text{ch}}, b_{\text{ch}})$.
2. $B$ enkapsuluje: $r_B \leftarrow \chi_r$, $(u_K, v_K) = \text{LPR.Enc}(b_{\text{ch}}, K)$ dla świeżego $K \in \{0,1\}^\lambda$.
3. $A$ dekapsuluje: $K = \text{LPR.Dec}(s_{\text{ch}}, u_K, v_K)$.
4. Wspólny token: $s_{\text{shared}} = \text{KDF}(K, \text{"hss-ipc-v1"}, \text{nonce})$.

$s_{\text{ch}}$ jest kasowany po kroku 3, zapewniając **per-sesyjny forward secrecy**.

### 5.2 Atenuacja IPC Per-Pryzmat

Zamiast degradować $s_{\text{shared}}$ addytywnie (co dziedziczyłoby problemy skorelowanych kluczy z poprzedniej konstrukcji PrismMask), HSS v2.5 wyprowadza niezależne klucze kanałów per-pryzmat:

$$K_j = \text{KDF}(K,\; \text{"hss-ipc-prism"},\; j), \quad j \in \{1, \ldots, K_{\text{total}}\}$$

Proces $A$ selektywnie przesyła tylko wartości $K_j$ dla pryzmatów w $\mathcal{P}_{\text{allow}}$ do procesu $B$. Każde $K_j$ jest szyfrowane pod długoterminowym kluczem publicznym $B$ przed przesłaniem. Proces $B$ wyprowadza swój token sesji dla każdego autoryzowanego pryzmatu niezależnie:

$$s_{\text{shared},j}^B = \text{KDF}(K_j,\; \text{"hss-ipc-sess"},\; \text{nonce})$$

**Właściwości bezpieczeństwa:** Każde $K_j$ jest obliczeniowo niezależne; znajomość $K_{j_1}$ nie ujawnia nic o $K_{j_2}$ dla $j_1 \neq j_2$. Forward secrecy jest utrzymywane per-pryzmat.

**Uwaga o ABE.** Per-pryzmatowy KDF poprawnie wyraża semantykę OR. Koniunkcje AND (dostęp wymaga ZARÓWNO pryzmatu $j$ JAK I pryzmatu $k$) wymagają ABE [Sahai-Waters, 2005] lub schematu progowego. Zidentyfikowane jako główny cel HSS v3.0.

---

## 6. Analiza Bezpieczeństwa

### 6.1 Model Zagrożeń

Zakładamy przeciwnika w stylu Dolev-Yao, który może: wykonywać dowolny kod pod tym samym UID; czytać surowe bloki dysków i pola xattr; podsłuchiwać cały lokalny ruch IPC; uzyskać kod źródłowy `security_holo` i hss-daemon. Przeciwnik **nie może**: wyekstrahować sekretów z kernel keyring bez uprawnień roota; modyfikować pamięci jądra; rozwiązać Decision-RLWE w czasie wielomianowym.

### 6.2 Odporność na Typowe Ataki

| Wektor Ataku | Tradycyjna Mitygacja | Mitygacja HSS |
|---|---|---|
| **Proces czytający `/tmp`** | Uprawnienia DAC | Szyfrogram jest IND-CPA; bez $s_{\text{sess}}$ deszyfrowanie daje szum. |
| **Confused Deputy** | Sandboxing | Wiązanie kontekstu AAD (inode ‖ sesja ‖ policy\_id) wiąże szyfrogram z zamierzonym konsumentem. |
| **Atak skorelowanym kluczem polityki** | — | Klucze $s_{\text{policy}}$ pochodne KDF są wzajemnie niezależne pod PRF; różnice nic nie ujawniają o $s_{\text{sess}}$. |
| **Wyrocznia wariancji** | — | Zaślepiona wariancja (wstrzykiwanie szumu $\sigma_\xi = 0,05\theta$) + ograniczanie szybkości (100 żądań/s) redukuje przepustowość wyroczni do $< 100$ bitów/s. |
| **Podsłuch IPC** | Uprawnienia gniazda | KEM-szyfrowane $K$; per-pryzmat $K_j = \text{KDF}(K, j)$ niezależnie zabezpieczone. |
| **Potomek dostępujący do pryzmatów rodzica** | Przestrzenie nazw | Izolacja KDF: $s_{\text{policy}}$ nie może odtworzyć $s_{\text{sess}}$; odmówione pryzmaty otrzymują szyfrowania zera. |
| **Agent modyfikujący rdzeń Φ** | Konwencja / sandboxing | AAD zawiera agent\_id + task\_id; zapisy poza $\mathcal{P}_{\text{zadanie}}$ produkują niezgodne AAD, odrzucone przez hss-daemon. |
| **Krzyżowy dostęp do poświadczeń** | Izolacja na poziomie aplikacji | Pryzmat poświadczeń $\mathcal{P}_{\text{cred}}$ kluczowany z korzenia sprzętowego $s_{\text{hw}}$; per-serwisowe $K_{\text{cred}}$ niezależnie pochodne. |
| **Replay na H-IPC** | Numery sekwencyjne | Nonce w wejściu KDF; powtórzony szyfrogram produkuje inne $s_{\text{shared},j}$. |
| **Ominięcie LSM przez userspace** | — | Gniazdo upcall jest uwierzytelniane HMAC; nieuprzywilejowane procesy nie mogą wstrzykiwać odpowiedzi zezwól. |

### 6.3 Granice Bezpieczeństwa i Jawne Ograniczenia

HSS zapewnia **ochronę granic międzyprocesowych** i **ochronę danych w spoczynku przed kradzieżą offline**. Jawnie **nie** zapewnia:

- **Ochrony przed rootem**: Jeśli atakujący uzyska root (UID 0), może bezpośrednio uzyskać dostęp do kernel keyring przez `keyctl`, uzyskać $s_{\text{sess}}$ i odszyfrować wszystkie pliki. **HSS oferuje zerową ochronę przed skompromitowanym rootem.** Sprzętowe przechowywanie kluczy (TPM 2.0, ARM TrustZone lub AMD SEV-SNP) jest **wymagane** — nie tylko planowane — dla każdego wdrożenia, gdzie adversarialny dostęp root jest częścią modelu zagrożeń. Bez zapieczętowania sprzętowego HSS jest mechanizmem defense-in-depth chroniącym tylko przed nieuprzywilejowanymi atakującymi.
- **Poufności po deszyfrowaniu**: Autoryzowany proces, który odszyfrował dane, może ujawnić plaintext przez dowolny kanał. Mitygacja wymaga IFC [Myers-Liskov, 1997].
- **Granicy hiperwizora**: Monitor maszyny wirtualnej z dostępem do pamięci fizycznej może wyekstrahować keyring niezależnie od HSS.

### 6.4 HSS a Wirtualizacja: Ortogonalne Warstwy Izolacji

HSS nie jest alternatywą dla wirtualizacji — jest jej uzupełnieniem. Oba mechanizmy działają na różnych warstwach i rozwiązują różne klasy problemów.

**Fundamentalna różnica modelu izolacji:**

| Cecha | VM / Kontenery | HSS |
|---|---|---|
| Mechanizm izolacji | Zasoby systemowe (CPU, RAM, przestrzenie nazw) | Niemożliwość matematyczna (brak klucza RLWE) |
| Punkt wymuszenia | Kernel / hypervisor | Algebra kryptograficzna |
| Model dostępu | "Kto ma dostęp do czego" | "Czego nie da się odszyfrować" |
| Ścieżka danych | `proces → pamięć → syscall → kernel → FS` | `proces → szyfrogram → upcall → daemon → transformacja` |
| Kompromis kernela | Game over — pełna utrata izolacji | HSS nadal chroni dane (daemon nie ma plaintextu bez klucza Φ) |
| Delegacja częściowa | Wymaga bind-mountów, ACL, przestrzeni nazw | Natywna: capability = HMAC(s_A, prism_id) |

**Co HSS chroni, czego VM nie chroni:**

- *Semantyczna widoczność danych*: VM izoluje procesy ale nie ogranicza co skompromitowany proces widzi wewnątrz swojej przestrzeni. W HSS agent otrzymuje tylko projekcję przestrzeni Φ — fizycznie nie ma dostępu do danych poza autoryzowanymi pryzmatami, nawet po eskalacji uprawnień wewnątrz procesu.
- *Zero-trust między komponentami*: W klasycznej wirtualizacji komponenty w tej samej maszynie ufają sobie nawzajem. W HSS agent nie ufa daemonowi — weryfikuje `mac_agent` przed użyciem każdej danej.
- *Delegacja granularna bez infrastruktury*: Przydzielenie agentowi dostępu do podzbioru danych w VM wymaga bind-mountów, ACL lub dodatkowego proxY. W HSS wystarczy `s_A = KDF(s_sess, task_id || prisms)`.

**Czego HSS nie chroni (i VM tak):**

- *Zasoby obliczeniowe*: Złośliwy agent może zająć 100% CPU lub wyczerpać RAM. Mitygacja wymaga cgroups / CPU quotas.
- *Ataki timing i side-channel*: Agent może analizować czas odpowiedzi daemona lub wykonywać cache timing attacks. Mitygacja wymaga operacji stałoczasowych i padding requestów.
- *Izolacja sieciowa*: HSS nie ogranicza połączeń sieciowych agenta. Mitygacja wymaga network namespaces.
- *DoS*: Agent może generować nieograniczoną liczbę upcall-ów. Mitygacja wymaga rate limiting na poziomie LSM.

**Właściwy model wdrożenia:**

```
┌─────────────────────────────────────┐
│         Warstwa fizyczna            │
│   VM / cgroups / namespaces         │  ← izolacja zasobów
├─────────────────────────────────────┤
│         Warstwa semantyczna         │
│   HSS / capability tokens / RLWE   │  ← izolacja informacyjna
├─────────────────────────────────────┤
│         Warstwa kognitywna          │
│   Φ / PrismMasks / FEP             │  ← izolacja percepcji
└─────────────────────────────────────┘
```

Obie pierwsze warstwy są konieczne. HSS nie zastępuje VM — HSS gwarantuje właściwości których VM z definicji nie może zapewnić: że agent *matematycznie nie może* zobaczyć danych do których nie ma capability tokenu, niezależnie od tego co dzieje się na poziomie procesu lub kernela.

| Komponent | Rola | Integracja HSS |
|---|---|---|
| **Rdzeń Holon ($\Phi$, v5.11)** | Geometria kognitywna, filtr z przeciekiem | Stan $S_t$ dostarcza pochodną capability sesji; filtrowanie szumu dla miękkiej atenuacji. |
| **HolonFS** | Semantyczne indeksowanie plików (xattr + numpy + JSON) | Szyfrogramy RLWE w `security.hss.lock`; indeksy wektorowe czytelne tylko przez procesy z ważnym $s_{\text{sess}}$ i pasującym AAD. |
| **Embedder KuRz** | 15-osiowe osadzanie PL+EN | Definiuje partycję pryzmatyczną $\{\mathcal{P}_j\}$ wyrównaną z klastrami osi KuRz. |
| **hss-daemon** | Uprzywilejowany serwis kryptograficzny przestrzeni użytkownika | Wykonuje szyfrowanie/deszyfrowanie LPR, weryfikację wiązania kontekstu, sprawdzian wariancji, generowanie PrismMask, KEM H-IPC i re-szyfrowanie per-pryzmat. |

### 7.2 Wdrożenie Autonomiczne: HSS bez HolonOS

HSS nie wymaga HolonOS ani modyfikacji jądra systemu operacyjnego. Może działać jako **samodzielna warstwa bezpieczeństwa** na istniejącej infrastrukturze Linuksowej, zastępując lub uzupełniając istniejące mechanizmy kontroli dostępu.

**FUSE deployment (zero zmian w jądrze).** `holon-fuse` montuje katalog w przestrzeni użytkownika — istniejące aplikacje czytają z `/data/sensitive/` i otrzymują widok re-zaszyfrowany pod ich `s_A`. Żadnych zmian w aplikacji, żadnych zmian w kernelu, żadnych zmian w istniejącym filesystemie. Działa na każdej dystrybucji Linuksa bez uprawnień roota. To jest najniższy próg wdrożenia.

**Kubernetes sidecar.** `hss-daemon` jako sidecar container w każdym podzie. Agent AI nie otrzymuje credentiali bezpośrednio — otrzymuje `s_A` z capability tokenem. Dane między mikroserwisami są re-szyfrowane per-pryzmat na poziomie sidecar proxy. Skompromitowany agent widzi tylko swój pryzmat — bez żadnych zmian w kodzie aplikacji, bez zmian w network policies, bez zmian w istniejących Kubernetes RBAC.

**Zastąpienie Vault + ACL.** Obecne rozwiązania enterprise łączą: secrets manager (Vault), RBAC, network policies i szyfrowanie w spoczynku — cztery osobne systemy, każdy z własnym modelem zagrożeń i powierzchnią ataku. Każde z tych rozwiązań ma ten sam fundamentalny problem: **to są bariery, nie geometria**. Skompromitowany komponent z właściwym tokenem dostaje wszystko. HSS zastępuje te cztery systemy jednym modelem matematycznym: dostęp = capability token = HMAC(s\_A, prism\_id). Brak centralnego serwera uprawnień który można skompromitować. Brak listy ACL która może być błędnie skonfigurowana. Brak polityki — tylko algebra.

**Największy rynek: multi-agent AI pipelines.** Każda organizacja uruchamiająca agenty AI na wrażliwych danych ma nierozwiązany problem: jeden skompromitowany agent może zobaczyć dane wszystkich innych agentów. Żaden obecny framework agentowy (LangChain, AutoGPT, CrewAI) nie rozwiązuje izolacji semantycznej między agentami — operują na konwencji, nie na gwarancji matematycznej. HSS jako warstwa sidecar daje pierwszą w branży **kryptograficzną izolację percepcji między agentami AI** na istniejącej infrastrukturze.

1. **Stałoczasowy NTT**: Arytmetyka wielomianowa hss-daemon musi być utwardzona przeciwko atakom side-channel z pomiarem czasu. Planowane jest przyjęcie stałoczasowego NTT z liboqs lub implementacji referencyjnej Kyber.

2. **Forward Secrecy dla Plików w Spoczynku**: Forward secrecy na poziomie sesji dotyczy H-IPC. Pliki zaszyfrowane pod $s_{\text{sess}}$ są narażone przy skompromitowaniu klucza sesji. Mechanizm grzechotki epok zapisu (analogiczny do Double Ratchet Signala) jest planowany dla HSS v3.

3. **Injektywność Partycji Pryzmatycznej**: Wyrównanie między osiami embeddingu KuRz a współczynnikami $R_q$ wymaga formalnego dowodu injektywności. Aktualnie walidowane empirycznie na PoC v1.3.1.

4. **ABE dla Ekspresywnych Polityk IPC**: ABE [Sahai-Waters, 2005] umożliwiłby bogatsze polityki boolowskie pryzmatów. Odłożone do HSS v3.0.

5. **Granica Zaufania Roota**: Jak stwierdzono w §6.3, dostęp root w pełni kompromituje HSS bez sprzętowego zapieczętowania kluczy. Integracja TPM 2.0 / TrustZone / AMD SEV-SNP jest **wymagana** dla wdrożeń adversarialnych.

6. **Formalny Dowód SNR**: Opiera się na heurystycznym oszacowaniu energii splotu kołowego. Formalny dowód pod jednorodnym rozkładem $u \in R_q$ jest oczekiwany.

7. **Stabilność Projekcji przy Ponownym Kluczowaniu**: Kod korekcji błędów (np. BCH nad $\{0,1\}^N$) zastosowany do $\hat{S}_{\text{sess}}$ przed użyciem jako materiał klucza zapewniłby pełną tolerancję błędów. Planowane dla implementacji PoC v2.

8. **Opóźnienie Restartu Demona**: Okno kolejkowania 500ms może powodować zauważalne pauzy dla strumieni danych kognitywnych wrażliwych na opóźnienie. Architektura demona hot-standby (primary/secondary ze współdzielonym dostępem do keyring) zredukowałaby czas odtworzenia do $< 10\,\mu\text{s}$.

9. **Kaskadowe Awarie i Kwarantanna Termodynamiczna**: Gwałtowny wzrost lokalnej entropii — na przykład przy kaskadowym upadku wielu agentów jednocześnie — generuje "dżety" szumu które mogą destabilizować sąsiednie pryzmaty przez Convolution Bleed na poziomie przestrzeni stanów. Proponowanym mechanizmem mitygacji jest **kwarantanna termodynamiczna**: tymczasowe zamrożenie lokalnego $\eta$ (learning rate) w dotkniętych pryzmatach, pozwalające anomalii entropijnej "wyparować" przez Vacuum Decay bez naruszenia spójności rdzenia $\Phi$. Implementacja wymaga wykrywania progu niestabilności $\|\varepsilon_t\|_2 > \varepsilon_{\text{kwarantanna}}$ i jest planowana dla HSS v3.0.

10. **Quantum Random Number Generator (QRNG)**: Aktualnie `base_secret` jest seedowany przez `os.urandom()` (CSPRNG oparty na hardware entropy pool — kryptograficznie wystarczający). Zastąpienie przez QRNG (np. ANU Quantum Random Numbers Server lub sprzętowy ID Quantique) zapewniłoby **prawdziwą nieobliczalność** (zasada nieoznaczoności Heisenberga) zamiast obliczeniowej pseudolosowości. Jest to architektonicznie spójne z filozofią Holonu: jeśli $\Phi$ nie jest obliczalne, to sekret który z niego wynika powinien być zakorzeniony w kwantowej nieoznaczalności. Planowane dla HolonOS v1.0.

11. **Rotacja Epoki a Pliki w Spoczynku**: Rotacja $s_{\text{sess}}$ przez epoch zapewnia forward secrecy dla nowych operacji. Jednak pliki zaszyfrowane w poprzednich epokach pozostają dostępne przez `base_secret` — kompromitacja `base_secret` ujawnia wszystkie epoki. Pełna forward secrecy dla plików wymaga per-plik ratchet mechanism (Double Ratchet), planowanego dla HSS v3.

---

## 9. Wnioski

Przedstawiliśmy **Holograficzne Przestrzenie Sesji v2.5** — architekturę bezpieczeństwa opartą na capability, ugruntowaną w kryptografii post-quantum (LPR/RLWE) i formalnie sprzężoną z metryzowaną przestrzenią stanów kognitywnych $\Phi$.

Kluczowe wkłady tej wersji: (i) **Pochodna PrismMask oparta na KDF** zastępująca addytywną modyfikację klucza — klucze polityk są obliczeniowo niezależne, eliminując ataki skorelowanymi kluczami; (ii) **Ponowne szyfrowanie na poziomie szyfrogramu** dla atenuacji pryzmatów, całkowicie przenosząc maskowanie poza materiał klucza; (iii) **Zaślepiony sprawdzian wariancji** z wstrzykiwaniem szumu i ograniczaniem szybkości, zamykający side-channel wyroczni deszyfrowania; (iv) **Pochodna klucza H-IPC per-pryzmat** przez $K_j = \text{KDF}(K, j)$, zapewniająca niezależne bezpieczeństwo kanałów per-pryzmat; (v) **Przestrzeń Wykonania Programów** (§3.5) — formalny model cyklu życia agenta umożliwiający HolonOS syntezę, izolację i kończenie programów specyficznych dla zadania z kryptograficzną ochroną przed zapisem rdzenia stanu $\Phi$ i pryzmatami poświadczeń zakorzenionymi w sprzęcie.

Centralna teza pozostaje niezmieniona: **agent istnieje tylko w przestrzeni zdefiniowanej przez ukryty operator projekcji zależny od sekretu, a wszystkie operacje poza tą przestrzenią są informacyjnie zerowe.** Bezpieczeństwo jest topologiczną właściwością przestrzeni wykonania, nie zewnętrzną warstwą polityki.

W HolonOS oznacza to, że syntetyzowany program nie może modyfikować swojego twórcy, poświadczenia nie mogą krzyżowo kontaminować między agentami, a stan kognitywny $\Phi$ jest chroniony nie przez politykę oprogramowania, lecz przez matematyczną strukturę pochodnej klucza — niezależnie od tego, jaki kod działa w systemie.

---

## Literatura

1. Mazur, M. (2026). *Holon: Holograficzna Architektura Kognitywna dla Persystentnej Pamięci i Świadomości Temporalnej w Konwersacyjnych Systemach AI*. Zenodo. DOI: 10.5281/zenodo.19371554.
2. Plate, T. A. (2003). *Holographic Reduced Representations*. CSLI Publications.
3. Lyubashevsky, V., Peikert, C., & Regev, O. (2013). On ideal lattices and learning with errors over rings. *Journal of the ACM*, 60(6), 1–35. [LPR13]
4. Avanzi, R. et al. (2021). *CRYSTALS-Kyber (version 3.02)*. Zgłoszenie NIST PQC. https://pq-crystals.org/kyber/
5. Friston, K. (2010). The free-energy principle: a unified brain theory? *Nature Reviews Neuroscience*, 11(2), 127–138.
6. Shapiro, J. S., & Hardy, N. (2002). EROS: A principle-driven operating system from the ground up. *IEEE Software*, 19(1), 26–33.
7. Myers, A. C., & Liskov, B. (1997). A decentralized model for information flow control. *ACM SIGOPS Operating Systems Review*, 31(5), 129–142.
8. Sahai, A., & Waters, B. (2005). Fuzzy identity-based encryption. *EUROCRYPT 2005*, LNCS 3494, 457–473.
9. Micciancio, D., & Peikert, C. (2012). Trapdoors for lattices. *EUROCRYPT 2012*, LNCS 7237, 700–718. [MP12]

---

## Appendix A: Interpretacja Termodynamiczna HSS

*Sekcja narracyjna. Nie zawiera nowych twierdzeń formalnych.*

Matematyka HSS opisuje te same struktury co termodynamika i mechanika kwantowa — na warstwie informacyjnej. Poniższe zasady są reinterpretacją formalnych wyników papieru w języku fizyki informacji.

**A.1 Zasada Zachowania Semantyki.** W układzie zamkniętym $\Phi$, informacja nie może zostać zniszczona ani utworzona bez zmiany stanu klucza. Każdy agent jest "cząstką wirtualną" wyłonioną z substratu przez operację KDF. Jego dostęp do znaczenia jest determinowany przez precyzję trajektorii w przestrzeni pryzmatycznej $[\mathcal{P}_1, \ldots, \mathcal{P}_K]$.

**A.2 Entropia jako Gradient Dostępu.** Dostęp do danych nie jest binarną bramką, lecz gradientem entropii informacyjnej:

$$\alpha = 1{,}0 \;\;\Rightarrow\;\; \text{zero kelvina: idealny porządek, pełna widoczność}$$
$$\alpha \in (0,1) \;\;\Rightarrow\;\; \text{miękka atenuacja: podniesienie lokalnej "temperatury"}$$
$$\alpha = 0 \;\;\Rightarrow\;\; \text{ciepło śmierci: maksymalna entropia, dane martwe bez klucza}$$

Zero kelvina nie jest tu nicością — jest **bazowym szumem kryptograficznym** $\sigma_\infty^2$: stanem o najniższej energii informacyjnej który nadal istnieje, tylko nie niesie struktury możliwej do zdekodowania. Jest stałą bezwzględną układu, punktem odniesienia względem którego mierzona jest każda inna informacja.

**A.3 Próżnia i Vacuum Decay.** Próżnia $\mathcal{V}$ to stan zdefiniowany przez bazowy szum $\sigma_\infty^2$. Gdy agent kończy działanie i $s_A$ ulega anihilacji, jego dane tracą strukturę i stają się **anomalią entropijną** — lokalnym wzrostem entropii który system rozpoznaje jako nieużyteczny. Zgodnie z zasadą minimalizacji wolnej energii (FEP [Friston, 2010]), $\Phi$ "wygładza" te anomalie przez Vacuum Decay: obszary maksymalnej entropii są reklasyfikowane jako próżnia i zwracane do substratu jako czysty materiał na nowych agentów.

**A.4 Mrożenie Czasu.** Agent hibernowany ma swój stan kryptograficznie zamrożony w $\mathcal{P}_{\text{task}}$. Bez $s_A$ ten stan nie dryfuje, nie degraduje się, nie jest dostępny żadnemu obserwatorowi. Czas dla tego agenta stanął w dokładnym momencie hibernacji — i może być wznowiony wyłącznie przez $\Phi$ re-derywujące $s_A$ z tego samego $s_{\text{sess}}$. Jest to informacyjny odpowiednik dylatacji czasu: dla zewnętrznego obserwatora agent nie istnieje; dla samego agenta nie upłynęła żadna chwila.

**A.5 Sandbox kontra Topologia.** Klasyczny sandbox to ściany — agent może próbować je przebić. HSS to topologia przestrzeni: dane poza autoryzowanymi pryzmatami nie istnieją *dla* agenta w żadnym operacyjnym sensie. Nie ma czego przebijać. Ograniczenie nie jest barierą — jest geometrią rzeczywistości agenta.

---

*Korespondencja: GitHub @Maciej-EriAmo · Medium @drwisz*  
*Licencja: CC BY 4.0*

Przedstawiliśmy **Holograficzne Przestrzenie Sesji v2.5** — architekturę bezpieczeństwa opartą na capability, ugruntowaną w kryptografii post-quantum (LPR/RLWE) i formalnie sprzężoną z metryzowaną przestrzenią stanów kognitywnych $\Phi$.

Kluczowe wkłady tej wersji: (i) **Pochodna PrismMask oparta na KDF** zastępująca addytywną modyfikację klucza — klucze polityk są obliczeniowo niezależne, eliminując ataki skorelowanymi kluczami; (ii) **Ponowne szyfrowanie na poziomie szyfrogramu** dla atenuacji pryzmatów, całkowicie przenosząc maskowanie poza materiał klucza; (iii) **Zaślepiony sprawdzian wariancji** z wstrzykiwaniem szumu i ograniczaniem szybkości, zamykający side-channel wyroczni deszyfrowania; (iv) **Pochodna klucza H-IPC per-pryzmat** przez $K_j = \text{KDF}(K, j)$, zapewniająca niezależne bezpieczeństwo kanałów per-pryzmat; (v) **Przestrzeń Wykonania Programów** (§3.5) — formalny model cyklu życia agenta umożliwiający HolonOS syntezę, izolację i kończenie programów specyficznych dla zadania z kryptograficzną ochroną przed zapisem rdzenia stanu $\Phi$ i pryzmatami poświadczeń zakorzenionymi w sprzęcie.

Centralna teza pozostaje niezmieniona: kontrola dostępu powinna być strukturalną właściwością geometrii kryptograficznej, nie zewnętrzną warstwą polityki. W HolonOS oznacza to, że syntetyzowany program nie może modyfikować swojego twórcy, poświadczenia nie mogą krzyżowo kontaminować między agentami, a stan kognitywny $\Phi$ jest chroniony nie przez politykę oprogramowania, lecz przez matematyczną strukturę pochodnej klucza — niezależnie od tego, jaki kod działa w systemie.

---

## Literatura

1. Mazur, M. (2026). *Holon: Holograficzna Architektura Kognitywna dla Persystentnej Pamięci i Świadomości Temporalnej w Konwersacyjnych Systemach AI*. Zenodo. DOI: 10.5281/zenodo.19371554.
2. Plate, T. A. (2003). *Holographic Reduced Representations*. CSLI Publications.
3. Lyubashevsky, V., Peikert, C., & Regev, O. (2013). On ideal lattices and learning with errors over rings. *Journal of the ACM*, 60(6), 1–35. [LPR13]
4. Avanzi, R. et al. (2021). *CRYSTALS-Kyber (version 3.02)*. Zgłoszenie NIST PQC. https://pq-crystals.org/kyber/
5. Friston, K. (2010). The free-energy principle: a unified brain theory? *Nature Reviews Neuroscience*, 11(2), 127–138.
6. Shapiro, J. S., & Hardy, N. (2002). EROS: A principle-driven operating system from the ground up. *IEEE Software*, 19(1), 26–33.
7. Myers, A. C., & Liskov, B. (1997). A decentralized model for information flow control. *ACM SIGOPS Operating Systems Review*, 31(5), 129–142.
8. Sahai, A., & Waters, B. (2005). Fuzzy identity-based encryption. *EUROCRYPT 2005*, LNCS 3494, 457–473.
9. Micciancio, D., & Peikert, C. (2012). Trapdoors for lattices. *EUROCRYPT 2012*, LNCS 7237, 700–718. [MP12]

---

*Korespondencja: GitHub @Maciej-EriAmo · Medium @drwisz*  
*Licencja: CC BY 4.0*
