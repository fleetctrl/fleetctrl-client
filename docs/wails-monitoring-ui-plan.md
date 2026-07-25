# Plán: lokální Wails UI pro synchronizaci a stav aplikací

## 1. Účel dokumentu

Tento dokument popisuje návrh a postup implementace první verze lokálního
uživatelského rozhraní FleetCtrl Clientu pro Windows.

První verze má umožnit běžnému uživateli:

- zjistit, zda FleetCtrl služba běží a zda je dostupná;
- zobrazit čas poslední zahájené a poslední úspěšné synchronizace;
- zobrazit poslední chybu synchronizace;
- ručně vyvolat synchronizaci;
- zobrazit aplikace spravované FleetCtrl;
- zobrazit požadovaný a skutečně detekovaný stav aplikace;
- zjistit, kdy byla aplikace naposledy zkontrolována;
- zjistit, zda a kdy byla aplikace nainstalována FleetCtrl klientem.

UI bude vytvořeno pomocí Wails a bude distribuováno jako samostatný proces.
Stávající Windows služba zůstane jedinou komponentou, která komunikuje se
serverem, zapisuje do lokální databáze a provádí systémové operace.

## 2. Rozsah MVP

### 2.1 Součástí MVP

- samostatné Wails okno spouštěné v uživatelské session;
- obrazovka se stavem služby a poslední synchronizace;
- tlačítko pro ruční synchronizaci;
- seznam aplikací přiřazených zařízení přes FleetCtrl;
- stav každé aplikace získaný existujícími detection rules;
- lokální ukládání aktuálního stavu a stručné historie do SQLite;
- bezpečná komunikace mezi UI a Windows službou;
- zobrazení průběhu synchronizace alespoň ve stavech:
  `čeká`, `probíhá`, `úspěch`, `částečný úspěch`, `chyba`;
- instalace Wails executable společně se službou;
- základní testy na podporovaných verzích Windows.

### 2.2 Mimo rozsah MVP

- ruční instalování nebo odinstalování konkrétní aplikace z UI;
- katalog aplikací, které nejsou zařízení přiřazené;
- kompletní inventář všech aplikací nainstalovaných ve Windows;
- zobrazování živého procentuálního průběhu stahování nebo instalace;
- editace server URL, enrollment tokenu nebo DeviceID;
- zobrazování nebo spouštění libovolných PowerShell skriptů;
- administrace služby, například její zastavení nebo odinstalování;
- systémová tray ikona a notifikace;
- automatické aktualizace samotného UI nezávislé na klientovi;
- vzdálená správa UI ze serveru.

Kompletní Windows inventář lze doplnit později. Vyžadoval by samostatné
procházení 32bitového a 64bitového registru, MSI produktů, uživatelských
instalací a případně AppX/winget balíčků. Pro MVP se zobrazují pouze aplikace,
které FleetCtrl zná z odpovědi `/apps/assigned`.

## 3. Současný stav klienta

Klient již obsahuje:

- Windows službu běžící jako `LocalSystem`;
- pravidelnou synchronizaci informací o počítači;
- pravidelné načítání úloh;
- pravidelné načítání přiřazených aplikací;
- instalaci, odinstalaci a upgrade aplikací;
- Win32 a winget instalační mechanismus;
- detection rules pro zjištění, zda je release nainstalovaný;
- reportování stavů releasu serveru;
- SQLite databázi pro winget kontroly a backoff po chybách;
- MSI balíček postavený pomocí WiX.

Hlavní omezení současné implementace:

- synchronizační metody jsou nekonečné smyčky s `time.Sleep`;
- nelze je čistě spustit jednorázově na požadavek;
- čas poslední úspěšné synchronizace není lokálně uložen;
- stav spravovaných aplikací není v SQLite uložen jako snapshot;
- neexistuje IPC rozhraní pro lokální UI;
- instalace a synchronizace aplikací nejsou řízené společným koordinátorem;
- služba a případné UI nemají definovaný veřejný lokální kontrakt.

## 4. Základní architektura

```text
┌──────────────────────────────────────────────────────────┐
│ Uživatelská session                                      │
│                                                          │
│  fleetctrl-ui.exe (Wails)                                │
│  ├─ přehled synchronizace                                │
│  ├─ seznam spravovaných aplikací                         │
│  └─ požadavek „Synchronizovat nyní“                      │
└───────────────────────┬──────────────────────────────────┘
                        │
                        │ zabezpečená Windows named pipe
                        │ pouze předem definované operace
                        ▼
┌──────────────────────────────────────────────────────────┐
│ Session 0 / LocalSystem                                  │
│                                                          │
│  fleetctrl-client Windows service                        │
│  ├─ IPC server                                           │
│  ├─ SyncCoordinator                                      │
│  ├─ synchronizace počítače                               │
│  ├─ synchronizace a detekce aplikací                     │
│  ├─ instalační logika                                    │
│  └─ jediný zapisující vlastník SQLite                    │
│                 │                         │              │
│                 ▼                         ▼              │
│       C:\ProgramData\fleetctrl       FleetCtrl server    │
│             client.db                                    │
└──────────────────────────────────────────────────────────┘
```

### 4.1 Proč budou existovat dva procesy

Windows služba běží jako `LocalSystem` v Session 0. Nemůže bezpečně zobrazovat
interaktivní okno uživateli. Wails aplikace proto musí běžet jako samostatný
proces v přihlášené uživatelské session.

Navržené executable:

- `client.exe` – stávající Windows služba;
- `fleetctrl-ui.exe` – nové Wails UI.

### 4.2 Vlastnictví dat

Windows služba bude:

- jediný proces zapisující do `client.db`;
- jediný držitel autentizačních tokenů;
- jediný proces komunikující s FleetCtrl API;
- jediný proces provádějící detection rules a instalace;
- autoritativní zdroj lokálního runtime stavu.

Wails UI nebude:

- otevírat SQLite pro zápis;
- číst tokeny nebo privátní klíče;
- volat FleetCtrl API přímo;
- spouštět příkazy s administrátorským oprávněním;
- přijímat cestu ke skriptu nebo libovolný příkaz od uživatele.

## 5. Význam synchronizace

Před implementací je nutné sjednotit pojem „synchronizovat nyní“.

Navržené členění:

| Druh | Obsah |
| --- | --- |
| `device` | Odešle serveru aktuální informace o počítači a RustDesk |
| `apps_status` | Načte přiřazené aplikace a zkontroluje jejich skutečný stav |
| `apps_reconcile` | Načte přiřazení, zkontroluje stav a provede požadované instalace/odinstalace |
| `full` | Provede `device` a zvolenou variantu synchronizace aplikací |

### Doporučení pro MVP

Tlačítko v UI by mělo vyvolat:

1. synchronizaci informací o zařízení;
2. načtení `/apps/assigned`;
3. detection check přiřazených aplikací;
4. aktualizaci lokální SQLite a report stavu serveru.

Ruční tlačítko by v MVP nemělo samo o sobě zahájit novou instalaci nebo
odinstalování. Automatický `apps_reconcile` poběží dál podle stávajícího
plánu služby. Toto rozdělení snižuje překvapení uživatele: tlačítko označené
„Synchronizovat“ pouze obnoví informace.

Pokud má tlačítko naopak okamžitě aplikovat serverová přiřazení, musí být
v UI jeho dopad explicitně pojmenovaný, například „Synchronizovat a použít
změny“. Toto je produktové rozhodnutí, které musí být uzavřeno před
implementací koordinátoru.

Zpracování obecných serverových úloh (`/tasks`) nebude součástí ruční
synchronizace. Jejich samostatný polling zůstane beze změny.

## 6. Refaktor synchronizační logiky

### 6.1 Cíl

Oddělit jednorázovou operaci od jejího časování. Každý typ synchronizace musí
být možné:

- spustit automaticky tickerem;
- spustit ručně přes koordinátor;
- ukončit přes `context.Context`;
- otestovat bez nekonečné smyčky;
- zaznamenat do SQLite jednotným způsobem.

### 6.2 Navržené metody

```go
type ComputerSyncResult struct {
    CompletedAt time.Time
}

func (ms *MainService) SyncComputerOnce(
    ctx context.Context,
) (ComputerSyncResult, error)

func (ms *MainService) RefreshAssignedApplicationStates(
    ctx context.Context,
) (ApplicationSyncResult, error)

func (ms *MainService) ReconcileAssignedApplications(
    ctx context.Context,
) (ApplicationSyncResult, error)
```

Stávající startovací metody budou pouze plánovače:

```go
func (ms *MainService) StartComputerSyncLoop(ctx context.Context)
func (ms *MainService) StartApplicationSyncLoop(ctx context.Context)
```

Plánovač nebude používat dlouhé blokující `time.Sleep`. Použije ticker,
kanál manuálních požadavků a ukončovací context:

```go
for {
    select {
    case <-ticker.C:
        coordinator.Trigger(SyncRequest{Kind: SyncDevice, Trigger: Automatic})
    case <-ctx.Done():
        return
    }
}
```

### 6.3 SyncCoordinator

Nová vrstva bude odpovědná za:

- serializaci operací, které se nesmí překrývat;
- deduplikaci současných požadavků;
- vytvoření `sync_runs` záznamu;
- přechody `queued → running → success/error`;
- publikaci změny stavu IPC klientům;
- zabránění souběhu detection checku a instalace stejného releasu;
- vrácení existujícího `run_id`, pokud stejná synchronizace již běží.

Navržené chování:

- současně může běžet nejvýše jedna `apps_status` nebo `apps_reconcile`;
- synchronizace zařízení může běžet paralelně s aplikacemi;
- opakované kliknutí v UI nevytvoří neomezenou frontu;
- požadavek vrací identifikátor běhu;
- UI může podle identifikátoru načíst výsledek;
- ukončení UI nezruší operaci služby;
- restart služby označí nedokončené běhy jako přerušené.

## 7. SQLite návrh

### 7.1 Migrace

Současné vytváření tabulek bude rozšířeno o verzované migrace.

Minimální varianta:

```sql
CREATE TABLE IF NOT EXISTS schema_migrations (
    version     INTEGER PRIMARY KEY,
    applied_at  DATETIME NOT NULL
);
```

Každá migrace musí:

- být transakční;
- být idempotentní, pokud je to možné;
- nikdy nemazat existující provozní data bez explicitní migrace;
- být otestovaná na prázdné i existující databázi;
- při chybě zanechat databázi v původním stavu.

Současný self-healing mechanismus databázi při opakovaném selhání maže.
Před přidáním historie aplikací je potřeba toto chování přehodnotit, protože
historie už nebude pouhá cache. Preferované chování:

- poškozenou databázi přejmenovat na diagnostickou zálohu;
- vytvořit novou databázi;
- zalogovat cestu k záloze;
- nemazat původní soubor bez možnosti obnovy.

### 7.2 Aktuální stav aplikací

```sql
CREATE TABLE managed_app_states (
    release_id                 TEXT PRIMARY KEY,
    app_id                     TEXT NOT NULL,
    display_name               TEXT NOT NULL,
    publisher                  TEXT,
    version                    TEXT,
    installer_type             TEXT NOT NULL,
    winget_id                  TEXT,

    assign_type                TEXT NOT NULL,
    desired_action             TEXT NOT NULL,
    detected_status            TEXT NOT NULL DEFAULT 'unknown',
    operation_status           TEXT NOT NULL DEFAULT 'idle',

    first_seen_installed_at     DATETIME,
    installed_by_client_at     DATETIME,
    last_checked_at             DATETIME,
    last_seen_on_server_at      DATETIME NOT NULL,
    assignment_removed_at       DATETIME,

    last_error                  TEXT,
    created_at                  DATETIME NOT NULL,
    updated_at                  DATETIME NOT NULL
);

CREATE INDEX idx_managed_app_states_app_id
    ON managed_app_states(app_id);

CREATE INDEX idx_managed_app_states_last_seen
    ON managed_app_states(last_seen_on_server_at);
```

Význam stavů:

`detected_status`:

- `unknown` – stav ještě nebyl ověřen nebo detection check selhal;
- `installed` – aktuální detection rules prošly;
- `not_installed` – detection rules nepotvrdily instalaci.

`operation_status`:

- `idle`;
- `installing`;
- `uninstalling`;
- `upgrading`;
- `error`.

`first_seen_installed_at` znamená první okamžik, kdy klient aplikaci detekoval.
Neprokazuje, že aplikaci nainstaloval FleetCtrl.

`installed_by_client_at` se nastaví pouze po úspěšném dokončení instalace
provedené FleetCtrl klientem a následném úspěšném detection checku.

### 7.3 Historie aplikací

```sql
CREATE TABLE app_events (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    release_id   TEXT NOT NULL,
    app_id       TEXT NOT NULL,
    event_type   TEXT NOT NULL,
    source       TEXT NOT NULL,
    message      TEXT,
    details_json TEXT,
    created_at   DATETIME NOT NULL
);

CREATE INDEX idx_app_events_release_created
    ON app_events(release_id, created_at DESC);
```

Příklady `event_type`:

- `assigned`;
- `assignment_changed`;
- `assignment_removed`;
- `detection_installed`;
- `detection_not_installed`;
- `install_started`;
- `install_succeeded`;
- `install_failed`;
- `uninstall_started`;
- `uninstall_succeeded`;
- `uninstall_failed`;
- `upgrade_started`;
- `upgrade_succeeded`;
- `upgrade_failed`.

Do historie se nebude při každé synchronizaci zapisovat stejný stav.
Událost vznikne pouze při změně stavu nebo při zahájení/dokončení operace.

### 7.4 Historie synchronizací

```sql
CREATE TABLE sync_runs (
    id            TEXT PRIMARY KEY,
    kind          TEXT NOT NULL,
    trigger       TEXT NOT NULL,
    status        TEXT NOT NULL,
    started_at    DATETIME,
    completed_at  DATETIME,
    error_message TEXT,
    details_json  TEXT,
    created_at    DATETIME NOT NULL
);

CREATE INDEX idx_sync_runs_kind_created
    ON sync_runs(kind, created_at DESC);
```

`kind`:

- `device`;
- `apps_status`;
- `apps_reconcile`;
- `full`.

`trigger`:

- `automatic`;
- `manual`;
- `startup`.

`status`:

- `queued`;
- `running`;
- `success`;
- `partial`;
- `error`;
- `interrupted`.

U `full` synchronizace musí `details_json` obsahovat výsledky jednotlivých
částí, aby jedna dílčí chyba nezakryla úspěch ostatních částí.

### 7.5 Práce s přiřazeními odstraněnými ze serveru

Řádky, které již nejsou v `/apps/assigned`, se nebudou ihned mazat.

Postup:

1. během synchronizace se všem přijatým řádkům aktualizuje
   `last_seen_on_server_at`;
2. chybějící řádky dostanou `assignment_removed_at`;
3. UI je standardně skryje nebo označí jako již nespravované;
4. historie zůstane zachována;
5. volitelný úklid může snapshot smazat například po 90 dnech, ale historii
   zachová.

## 8. Databázová API uvnitř klienta

Globální databázové funkce budou postupně nahrazeny repozitářem:

```go
type Repository interface {
    BeginSyncRun(ctx context.Context, run SyncRun) error
    UpdateSyncRun(ctx context.Context, run SyncRun) error
    GetLatestSyncRuns(ctx context.Context) ([]SyncRun, error)

    UpsertAssignedApps(
        ctx context.Context,
        apps []ManagedAppState,
        observedAt time.Time,
    ) error

    UpdateDetectionState(
        ctx context.Context,
        releaseID string,
        status DetectionStatus,
        checkedAt time.Time,
        detectionError string,
    ) error

    UpdateOperationState(
        ctx context.Context,
        releaseID string,
        status OperationStatus,
        operationError string,
    ) error

    ListManagedApps(ctx context.Context) ([]ManagedAppState, error)
    AppendAppEvent(ctx context.Context, event AppEvent) error
}
```

Požadavky:

- všechny dotazy musí používat parametry;
- více souvisejících změn musí být v jedné transakci;
- databáze musí mít nastavený `busy_timeout`;
- doporučuje se WAL režim;
- UI nesmí být závislé na interních SQL názvech;
- chyby databáze se nesmí prezentovat jako stav „aplikace není nainstalovaná“.

## 9. Lokální IPC

### 9.1 Transport

Preferovaný transport je Windows named pipe, například:

```text
\\.\pipe\fleetctrl-client-ui-v1
```

Named pipe je preferovaná před lokálním HTTP serverem, protože:

- není potřeba rezervovat TCP port;
- rozhraní není dostupné síťovým procesům;
- lze nastavit Windows ACL;
- lze identifikovat lokálního uživatele;
- nevzniká browser/CSRF rozhraní na localhostu.

### 9.2 Oprávnění

Pipe musí:

- vždy povolit `SYSTEM`;
- povolit lokálním administrátorům;
- povolit přihlášeným interaktivním uživatelům pouze bezpečné UI operace;
- zakázat anonymní a síťový přístup;
- používat explicitní security descriptor;
- omezovat velikost zprávy a počet současných klientů.

MVP operace jsou bezpečné i pro běžného uživatele, protože neumožňují vybrat
release, skript, URL ani cestu k souboru. Pokud se později přidá instalace na
požádání, bude nutné doplnit autorizaci vůči serverovým pravidlům.

### 9.3 Protokol

Protokol bude verzovaný a nebude přímo vystavovat Go interní typy.

Příklad requestu:

```json
{
  "version": 1,
  "request_id": "3b258f65-7007-46f9-82ef-9f812a67504f",
  "method": "trigger_sync",
  "params": {
    "kind": "full"
  }
}
```

Příklad odpovědi:

```json
{
  "version": 1,
  "request_id": "3b258f65-7007-46f9-82ef-9f812a67504f",
  "ok": true,
  "result": {
    "run_id": "522a73ce-7549-41c7-84ea-e1d7085f1c7f",
    "status": "queued"
  }
}
```

MVP metody:

| Metoda | Účel |
| --- | --- |
| `ping` | Ověření dostupnosti a verze služby |
| `get_overview` | Stav služby a poslední synchronizace |
| `list_apps` | Aktuální snapshot spravovaných aplikací |
| `get_app_events` | Omezená historie zvoleného releasu |
| `trigger_sync` | Bezpečné vyvolání podporovaného typu synchronizace |
| `get_sync_run` | Stav konkrétního běhu |

Odpovědi musí používat stabilní error codes, například:

- `SERVICE_NOT_READY`;
- `SYNC_ALREADY_RUNNING`;
- `INVALID_REQUEST`;
- `UNSUPPORTED_VERSION`;
- `DATABASE_UNAVAILABLE`;
- `SERVER_UNAVAILABLE`;
- `INTERNAL_ERROR`.

Text chyby je určený pro diagnostiku; UI logika se bude řídit error codem.

### 9.4 Aktualizace UI

Pro MVP jsou přijatelné dvě varianty:

1. polling `get_overview` během běžící synchronizace, například každou sekundu;
2. dlouho otevřené IPC spojení s událostmi.

Doporučení pro MVP je polling, protože je jednodušší a odolnější vůči restartu
služby. Wails UI:

- při běžícím syncu polluje přibližně jednou za sekundu;
- v klidovém stavu přibližně jednou za 30 sekund;
- po dokončení znovu načte seznam aplikací;
- při nedostupné službě používá omezený exponential backoff.

## 10. Wails aplikace

### 10.1 Navržená struktura

```text
cmd/
  main/                  stávající service executable
  ui/                    vstupní bod Wails aplikace

internal/
  ipc/
    protocol/            DTO, verze protokolu, error codes
    server/              named pipe server služby
    client/              named pipe klient UI
  sync/
    coordinator.go
  database/
    migrations/
    app_states.go
    sync_runs.go

frontend/
  src/
    components/
    pages/
    services/
    types/
```

Přesné umístění Wails frontendu lze přizpůsobit jeho zvolenému template.
Pro malý tým je vhodný TypeScript template s Reactem, Vue nebo Svelte podle
existujících zkušeností. Pro samotný rozsah MVP není mezi nimi zásadní
technický rozdíl.

### 10.2 Go bindingy Wails

Frontend bude volat pouze malou Go facade:

```go
type UIBackend struct {
    ipc IPCClient
}

func (b *UIBackend) GetOverview() (OverviewDTO, error)
func (b *UIBackend) ListApplications() ([]ApplicationDTO, error)
func (b *UIBackend) TriggerSync(kind string) (SyncRunDTO, error)
func (b *UIBackend) GetSyncRun(id string) (SyncRunDTO, error)
func (b *UIBackend) GetApplicationEvents(
    releaseID string,
    limit int,
) ([]ApplicationEventDTO, error)
```

Binding nebude obsahovat instalační logiku. Jeho jedinou rolí bude validace
UI vstupu, komunikace s named pipe a převod DTO.

### 10.3 Obrazovka Přehled

Zobrazované údaje:

- stav služby: dostupná / nedostupná;
- verze služby;
- adresa serveru bez citlivých údajů;
- stav spojení při posledním pokusu;
- poslední pokus o synchronizaci;
- poslední úspěšná synchronizace;
- poslední chyba;
- právě běžící operace;
- tlačítko „Synchronizovat nyní“.

Chování tlačítka:

- během běžící synchronizace je zakázané;
- po kliknutí okamžitě zobrazí stav `queued` nebo `running`;
- nečeká blokujícím způsobem na dokončení;
- při chybě spojení se službou zobrazí srozumitelnou lokální chybu;
- nesmí umožnit opakovaným klikáním vytvořit více stejných běhů.

### 10.4 Obrazovka Aplikace

Každý řádek zobrazí:

- název aplikace;
- publisher;
- požadovanou verzi;
- typ instalátoru;
- požadovanou akci;
- detekovaný stav;
- probíhající operaci;
- čas poslední kontroly;
- čas instalace klientem, pokud je znám;
- stručnou poslední chybu.

Filtry:

- všechny;
- nainstalované;
- nenainstalované;
- chyba;
- právě zpracovávané.

Řazení:

- výchozí podle názvu;
- volitelně podle poslední kontroly nebo stavu.

Prázdné stavy:

- žádné přiřazené aplikace;
- data ještě nebyla synchronizována;
- služba není dostupná;
- databáze je dočasně nedostupná.

### 10.5 Detail aplikace

Detail může být v MVP jednoduchý dialog nebo postranní panel:

- release ID pro diagnostiku;
- aktuální a požadovaný stav;
- poslední chyba;
- posledních několik událostí;
- vysvětlení rozdílu mezi „nalezeno v systému“ a „nainstalováno klientem“.

Citlivý obsah instalačních skriptů ani autentizační údaje se nezobrazují.

### 10.6 Lokalizace a čas

- data se v databázi ukládají v UTC;
- IPC přenáší RFC3339 timestamps;
- UI zobrazuje čas v lokální časové zóně Windows;
- texty budou minimálně česky;
- texty je vhodné držet v lokalizačním souboru, aby bylo možné později přidat
  angličtinu bez přepisování komponent.

## 11. Úpravy instalačního procesu

WiX balíček bude rozšířen o:

- `fleetctrl-ui.exe` v `C:\Program Files\fleetctrl`;
- Start Menu shortcut;
- volitelně Desktop shortcut, pouze pokud je produktově požadovaný;
- odebrání shortcutů během uninstallu;
- společnou verzi služby a UI;
- kontrolu nebo instalaci požadovaného WebView2 runtime.

MVP nemusí UI spouštět automaticky po přihlášení. Preferovaný první krok je
Start Menu shortcut. Automatický start nebo tray režim lze přidat později.

Při upgradu:

- služba musí být aktualizována společně s IPC protokolem;
- UI musí umět zobrazit chybu nekompatibilní verze;
- alespoň jedna předchozí verze protokolu může být dočasně podporována, pokud
  upgrade není atomický;
- databázová migrace proběhne při startu služby, nikoliv při startu UI.

## 12. Bezpečnostní požadavky

- UI nikdy nepřijímá ani nezobrazuje refresh/access token.
- UI nečte privátní JWK.
- IPC nepodporuje obecnou operaci typu `execute`.
- `trigger_sync` přijímá pouze pevný enum podporovaných typů.
- `release_id` pro čtení detailu se používá pouze jako parametr SQL dotazu.
- Velikost IPC requestu i response je omezená.
- Historie vrací stránkované nebo limitované výsledky.
- Named pipe má explicitní ACL.
- Logy nesmí obsahovat tokeny ani celé IPC payloady s potenciálně citlivými
  daty.
- Frontend nepovolí navigaci na vzdálený obsah uvnitř privilegovaného WebView.
- Wails bindingy budou dostupné pouze lokálnímu zabalenému frontendu.
- Všechny chyby zobrazené uživateli budou oddělené od detailního diagnostického
  logu.

## 13. Spolehlivost a souběh

Je nutné ošetřit:

- restart služby během synchronizace;
- restart UI během synchronizace;
- současný automatický a ruční sync;
- detection check během instalace;
- nedostupný server;
- expirovaný token a jeho refresh;
- timeout detection rule;
- dlouhou winget operaci;
- zamčenou SQLite databázi;
- chybu jedné aplikace bez ztráty výsledků ostatních aplikací;
- odebrání přiřazení během probíhající operace;
- změnu nejnovějšího releasu mezi dvěma synchronizacemi.

Při startu služby:

1. všechny staré `queued` a `running` záznamy se označí `interrupted`;
2. spustí se databázové migrace;
3. nastartuje IPC server;
4. nastartují automatické plánovače;
5. UI může přes `ping` zjistit, že je služba připravena.

## 14. Logování a diagnostika

Každá synchronizace bude mít `run_id`. Stejný identifikátor se použije:

- v `sync_runs`;
- v logovacích zprávách;
- v IPC odpovědích;
- v `details_json` jednotlivých výsledků.

Logovat se bude:

- typ a trigger synchronizace;
- zahájení a dokončení;
- počet načtených aplikací;
- počet úspěšných a chybných detection checků;
- chyby serveru, databáze a IPC;
- připojení UI pouze na rozumné diagnostické úrovni.

UI nabídne možnost zkopírovat stručný diagnostický souhrn, nikoliv celý log
nebo tokeny.

## 15. Testovací strategie

### 15.1 Unit testy

Databáze:

- migrace prázdné databáze;
- migrace existující databáze;
- upsert přiřazených aplikací;
- zachování `installed_by_client_at`;
- změna detection stavu;
- nevytváření duplicitních událostí;
- označení odstraněného přiřazení;
- sync run lifecycle;
- obnova `running` záznamu po restartu.

Koordinátor:

- automatický požadavek;
- manuální požadavek;
- deduplikace;
- paralelní device/apps pravidla;
- partial success;
- ukončení contextem;
- panic nebo chyba workeru nesmí nechat běh ve stavu `running`.

IPC:

- validní request;
- neznámá metoda;
- nekompatibilní verze;
- příliš velká zpráva;
- malformed JSON;
- timeout;
- odpojení klienta;
- stabilní error codes.

### 15.2 Integrační testy

- fake FleetCtrl HTTP server;
- úspěšná synchronizace zařízení;
- nedostupný server;
- `/apps/assigned` s více aplikacemi;
- detection success, failure a error;
- zápis snapshotu a historie;
- Wails backend proti testovacímu IPC serveru;
- restart služby během běhu.

Detection mechanismy musí být přístupné přes rozhraní, aby testy nemusely
skutečně instalovat software.

### 15.3 Windows smoke test

Minimální matice:

- Windows 10 x64;
- Windows 11 x64;
- běžný uživatel;
- administrátor;
- jeden přihlášený uživatel;
- více současně přihlášených uživatelů;
- WebView2 přítomný;
- WebView2 chybějící nebo zastaralý;
- fresh install;
- upgrade existující instalace;
- uninstall.

Kontrolní scénář:

1. nainstalovat MSI;
2. ověřit běh služby;
3. otevřít UI bez elevace;
4. ověřit poslední synchronizaci;
5. spustit ruční synchronizaci;
6. sledovat stav až do dokončení;
7. ověřit seznam aplikací;
8. restartovat službu a znovu načíst UI;
9. restartovat Windows;
10. provést upgrade a uninstall.

## 16. Implementační etapy

### Etapa 0 – uzavření produktových rozhodnutí

- [ ] Potvrdit význam tlačítka „Synchronizovat nyní“.
- [ ] Potvrdit, zda se zobrazují pouze FleetCtrl spravované aplikace.
- [ ] Potvrdit frontend framework pro Wails.
- [ ] Potvrdit Start Menu shortcut a případný autostart.
- [ ] Potvrdit požadovanou minimální verzi Windows.
- [ ] Potvrdit způsob distribuce WebView2.

Výstup: krátký záznam rozhodnutí přidaný do tohoto dokumentu nebo ADR.

### Etapa 1 – databázová vrstva

- [ ] Přidat verzované migrace.
- [ ] Přidat `managed_app_states`.
- [ ] Přidat `app_events`.
- [ ] Přidat `sync_runs`.
- [ ] Implementovat repository API.
- [ ] Nastavit WAL a `busy_timeout`.
- [ ] Upravit self-healing tak, aby nemaže jedinou kopii historie.
- [ ] Přidat unit testy.

Výstup: služba umí bezpečně ukládat snapshot, historii a běhy synchronizací.

### Etapa 2 – jednorázové synchronizační operace

- [ ] Vyčlenit `SyncComputerOnce`.
- [ ] Vyčlenit načtení `/apps/assigned`.
- [ ] Vyčlenit status-only detection průchod.
- [ ] Oddělit status refresh od reconcile/install logiky.
- [ ] Zapisovat stav aplikací do SQLite.
- [ ] Zapisovat změny do `app_events`.
- [ ] Přidat context a timeouty.
- [ ] Zachovat současné automatické intervaly.
- [ ] Přidat unit a integrační testy.

Výstup: každou synchronizaci lze spustit jednou a otestovat izolovaně.

### Etapa 3 – SyncCoordinator

- [ ] Implementovat frontu a pravidla souběhu.
- [ ] Implementovat deduplikaci.
- [ ] Implementovat `sync_runs` lifecycle.
- [ ] Ošetřit restart služby.
- [ ] Připojit automatické plánovače.
- [ ] Přidat manuální trigger API uvnitř služby.
- [ ] Přidat testy závodů a souběhu.

Výstup: automatické i ruční požadavky používají stejnou bezpečnou cestu.

### Etapa 4 – IPC server a klient

- [ ] Definovat protokol verze 1.
- [ ] Implementovat named pipe server.
- [ ] Nastavit a otestovat ACL.
- [ ] Implementovat limity, timeouty a error codes.
- [ ] Implementovat Go klienta pro UI.
- [ ] Přidat protokolové a integrační testy.
- [ ] Ověřit chování s více uživatelskými sessions.

Výstup: neprivilegovaný lokální klient může bezpečně číst stav a vyvolat sync.

### Etapa 5 – Wails UI

- [ ] Inicializovat Wails projekt s TypeScriptem.
- [ ] Implementovat Go facade nad IPC klientem.
- [ ] Implementovat obrazovku Přehled.
- [ ] Implementovat obrazovku Aplikace.
- [ ] Implementovat detail a stručnou historii aplikace.
- [ ] Implementovat polling a reconnect.
- [ ] Implementovat loading, empty a error stavy.
- [ ] Přidat české texty a formátování lokálního času.
- [ ] Ověřit, že UI nevyžaduje elevaci.

Výstup: funkční lokální UI proti běžící službě.

### Etapa 6 – build a instalátor

- [ ] Rozšířit build o `fleetctrl-ui.exe`.
- [ ] Přidat ikonu, manifest a metadata.
- [ ] Přidat UI executable do WiX.
- [ ] Přidat Start Menu shortcut.
- [ ] Vyřešit WebView2 bootstrapper/runtime.
- [ ] Ověřit společný upgrade služby a UI.
- [ ] Ověřit čistý uninstall.
- [ ] Aktualizovat README a build instrukce.

Výstup: jeden podporovaný MSI balíček obsahující službu i UI.

### Etapa 7 – ověření a pilot

- [ ] Projít Windows smoke test.
- [ ] Otestovat výpadek serveru a reconnect.
- [ ] Otestovat restart služby během syncu.
- [ ] Otestovat existující databázi z předchozí verze.
- [ ] Otestovat více uživatelů.
- [ ] Zkontrolovat logy na citlivé údaje.
- [ ] Nasadit malému pilotnímu vzorku zařízení.
- [ ] Vyhodnotit chyby a dobu synchronizace.

Výstup: release candidate připravený k širšímu nasazení.

## 17. Odhad pracnosti

Orientační odhad pro jednoho vývojáře obeznámeného s Go a Windows:

| Oblast | Odhad |
| --- | ---: |
| Databázové migrace a repository | 0,5–1 den |
| Refaktor jednorázových synchronizací | 1–1,5 dne |
| Koordinátor a souběh | 0,5–1 den |
| Named pipe IPC | 1–1,5 dne |
| Základní Wails UI | 1–2 dny |
| WiX, WebView2 a packaging | 0,5–1 den |
| Testování a opravy na Windows | 1–2 dny |
| **Celkem produkční MVP** | **5,5–10 dní** |

Velmi jednoduchý prototyp bez historie, robustního IPC a instalační integrace
lze vytvořit rychleji, ale není vhodný pro plošné nasazení na spravovaná
zařízení.

## 18. Rizika a mitigace

| Riziko | Dopad | Mitigace |
| --- | --- | --- |
| Wails UI nelze zobrazit ze služby | kritický | samostatný UI proces v user session |
| Současný sync a instalace se překryjí | vysoký | centrální SyncCoordinator a per-release zámky |
| Uživatel přes UI spustí privilegovaný příkaz | kritický | úzký whitelist IPC metod, žádné obecné execute API |
| SQLite se poškodí a historie se smaže | vysoký | migrace, transakce, záloha poškozené DB |
| Stav `installed` je zaměněn za instalaci klientem | střední | oddělit `first_seen_installed_at` a `installed_by_client_at` |
| Chybějící WebView2 | střední | kontrola a bootstrapper v instalátoru |
| UI a služba mají jinou verzi | střední | verzovaný IPC handshake a společný MSI upgrade |
| Detection je pomalá | střední | context timeouty, partial result, neblokující UI |
| Server odebere aplikaci | střední | soft-delete přiřazení a zachování historie |
| Více přihlášených uživatelů | nízký až střední | více read-only IPC klientů, deduplikovaný trigger |

## 19. Akceptační kritéria MVP

MVP je hotové, pokud:

- UI se spustí jako běžný uživatel bez UAC promptu;
- UI správně pozná běžící a zastavenou službu;
- UI zobrazí poslední pokus a poslední úspěšnou synchronizaci;
- UI zobrazí poslední chybu bez citlivých údajů;
- tlačítko vyvolá právě jednu synchronizaci;
- opakované kliknutí nevytvoří souběžné duplicitní běhy;
- UI po dokončení zobrazí nový stav bez restartu;
- seznam obsahuje všechny aktuálně přiřazené aplikace;
- každý řádek rozlišuje požadovaný, detekovaný a operační stav;
- data přežijí restart UI i služby;
- přerušený běh nezůstane navždy jako `running`;
- UI nemá přístup k tokenům, klíčům ani obecnému spouštění příkazů;
- stávající automatická správa aplikací funguje po refaktoru stejně jako před
  ním;
- fresh install, upgrade a uninstall projdou na Windows 10/11;
- databázové a koordinátorové testy procházejí bez race conditions.

## 20. Následující rozšíření po MVP

Po ověření MVP lze v samostatných etapách přidat:

1. tray ikonu a upozornění;
2. kompletní Windows software inventory;
3. serverem řízený self-service katalog;
4. ruční instalaci povolených aplikací;
5. procentuální průběh downloadu;
6. zobrazení instalačních fází;
7. bezpečné zrušení podporovaných operací;
8. export diagnostiky;
9. více jazyků;
10. detailní health stav jednotlivých subsystémů.

Ruční instalace aplikací musí být navržena jako nové bezpečnostní rozšíření
IPC a serverového autorizačního modelu. Nemá být přidána pouhým zpřístupněním
stávající `InstallApp` funkce do Wails bindingu.

## 21. Rozhodnutí před zahájením implementace

### Implementační rozhodnutí (2026-07-25)

- „Synchronizovat nyní“ provede `full` synchronizaci zařízení a
  `apps_status`; nespouští instalace ani odinstalace.
- UI se otevírá ze Start Menu a nemá autostart.
- Zobrazují se pouze FleetCtrl spravované aplikace.
- Detail aplikace zobrazuje posledních 20 událostí.
- Historie je v MVP zachována; automatický 180denní úklid bude doplněn až po
  pilotu, aby se předčasně neztratila diagnostická data.
- Uživateli se zobrazuje stručná chyba a diagnostický kód, nikoliv citlivý
  technický obsah.
- Frontend používá React a TypeScript ve Wails v2.
- Cílové platformy jsou 64bit Windows 10 a Windows 11 s WebView2 Runtime.

Následující body zatím zůstávají otevřené:

- [ ] Znamená „Synchronizovat nyní“ pouze obnovení dat, nebo také okamžité
      provedení přiřazených instalací a odinstalací?
- [ ] Má se UI otevírat pouze ze Start Menu, nebo automaticky po přihlášení?
- [ ] Má být v MVP detail historie aplikace, nebo jen aktuální snapshot?
- [ ] Jak dlouho se má uchovávat `app_events` historie?
- [ ] Má běžný uživatel vidět detail technické chyby, nebo pouze uživatelské
      shrnutí a diagnostický kód?
- [ ] Který Wails frontend template bude použit?

Doporučené výchozí odpovědi:

- ruční synchronizace pouze obnoví data a detection stav;
- UI se spouští ze Start Menu;
- MVP zobrazí posledních 20 událostí aplikace;
- historie se uchová 180 dní;
- UI zobrazí stručnou chybu a diagnostický kód;
- použije se TypeScript template podle zkušeností týmu.
