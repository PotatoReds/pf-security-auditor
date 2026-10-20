
# Pathfinder Security Auditor v0.2

Pathfinder er en modulær, host-baseret sikkerhedsauditor til Windows, skrevet i Python med read-only PowerShell- og registreringsdatabaseforespørgsler. Projektet er udviklet som et proof of concept til at identificere, dokumentere og prioritere mulige sikkerhedssvagheder – **ikke** til at udføre penetrationstest.

## Formål

Pathfinder indsamler lokale sikkerhedsobservationer, sammenholder udvalgte fund med en projektspecifik baseline og genererer dokumentation i JSON og HTML. Arbejdsgangen er **identifikation → risikovurdering → anbefalet afhjælpning → mulig senere verifikation**.

## Funktioner

- Windows-systemoplysninger og sikkerhedsrelateret konfiguration.
- Windows Firewall, inbound-regler og korrelation med lokale TCP-lytteporte.
- Antivirus- og Microsoft Defender-observationer.
- RDP, lokale administratorer, UAC og BitLocker.
- SMB-konfiguration: SMBv1, SMBv2/v3, krav om signering og overordnet krypteringsindstilling.
- Lokale SMB-shares og passivt observerede netværksnaboer.
- Inventar over installeret software fra Windows' uninstall-registreringsnøgler.
- Begrænset opslag i NVD efter mulige CVE-referencer for udvalgte produkter.
- Projektspecifik baseline, korrelation og heuristisk eksponeringsprioritering.
- Tidsstemplede JSON- og selvstændige HTML-rapporter.

## Krav

- Windows 11 med Windows PowerShell og relevante Windows-cmdlets.
- Python 3.10 eller nyere anbefales.
- Netværksforbindelse er kun nødvendig for det NVD-baserede CVE-opslag.
- Ingen tredjeparts-Python-pakker er nødvendige for rapportgeneratoren.

Nogle Windows-oplysninger kan kræve forhøjede læserettigheder. Manglende adgang eller utilgængelige cmdlets bør fremgå som `ERROR`, ikke som et bestået sikkerhedstjek.

## Installation og kørsel

Klon projektet og åbn projektmappen i PowerShell:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python main.py
```

Rapporter gemmes i `reports/` som matchende filer:

```text
reports/
  pathfinder_YYYYMMDD_HHMMSS_microseconds.json
  pathfinder_YYYYMMDD_HHMMSS_microseconds.html
```

Åbn HTML-rapporten i en browser. Den kræver ingen webserver.

**Bemærk:** Når `VULN-001` er registreret i `main.py`, sender modulet navnene på udvalgte installerede programmer til NVD's offentlige API. Deaktiver registreringen af `check_vulnerabilities`, hvis du ønsker en helt offline scanning. NVD-opslag kan være langsomme eller blive begrænset af API-rate limits.

## Projektstruktur

```text
pf-security-auditor/
├── main.py                     # Scanner-orkestrering og rapportering
├── checks/                     # Individuelle read-only kontroller
├── core/
│   ├── findings.py             # Finding-datamodel
│   ├── scanner.py              # Registrering og fejlhåndtering
│   ├── reporter.py             # JSON- og HTML-rapporter
│   ├── correlator.py           # Tværgående fund
│   ├── firewall_policy_engine.py
│   ├── exposure_prioritizer.py
│   └── baseline.py             # Projektspecifik baseline
├── config/
│   └── baseline.json
├── tests/                       # Enhedstests
└── reports/                     # Lokale resultater; må ikke committes
```

## Fortolkning af resultater

| Status | Betydning |
|---|---|
| `PASS` | Den konkrete kontrol opfylder sin definerede betingelse. |
| `WARN` | Et forhold bør undersøges eller risikovurderes. |
| `FAIL` | Kontrollen har konstateret et forhold, der bryder dens regel. |
| `ERROR` | Kontrollen kunne ikke gennemføres pålideligt; tilstanden er ukendt. |

Alvorlighed (`INFO`, `LOW`, `MEDIUM`, `HIGH`, `CRITICAL`) er en **projektbaseret prioritering**, ikke en automatisk CVSS-score. En `WARN` er ikke i sig selv en bekræftet udnyttelig sårbarhed.

### Eksempel: SMB på TCP 445

1. **Identifikation:** `NET-001` observerer en lokal TCP-lytteport, eksempelvis 445.
2. **Konfigurationsanalyse:** `SMB-001` vurderer protokolindstillinger og SMB-signering. `COR-002` sammenholder firewallregler og lokale endepunkter.
3. **Begrænsning:** En lokal lytteport og en firewallregel dokumenterer ikke, at porten kan nås fra en anden maskine.
4. **Fremtidsperspektiv:** Autoriseret netværksverifikation fra en separat testmaskine i et isoleret miljø kan efterprøve observationen. Denne funktion er **ikke implementeret**.

## Metode og begrænsninger

- Pathfinder udfører ingen aktiv exploitation, brute force eller automatisk afhjælpning.
- Passivt observerede netværksnaboer er ikke nødvendigvis online.
- Firewallkorrelation kan returnere `INDETERMINATE`; det er ikke det samme som `OPEN` eller `BLOCKED`.
- Eksponeringsprioritering er heuristisk og bekræfter ikke reel ekstern adgang.
- `SMB-001` validerer ikke Windows-patchniveau, faktiske SMB-forhandlinger eller konkrete SMB-CVE'er.
- `VULN-001` bruger begrænsede NVD-keyword-opslag. Søgetræffere er **ikke versionsvaliderede**, og fravær af træffere beviser ikke sikkerhed.
- Softwareinventaret er baseret på Windows' uninstall-registreringsnøgler og er ikke nødvendigvis komplet.
- Projektets baseline er selvdefineret og udgør ikke en certificeret CIS-, ISO 27001- eller anden compliance-audit.

## Sikkerhed og datahåndtering

Kør kun værktøjet på systemer, du har tilladelse til at undersøge. JSON- og HTML-rapporter kan indeholde følsomme oplysninger om software, brugere, processer, netværksadresser og sikkerhedsindstillinger. Gem rapporterne lokalt, del dem kun med relevante modtagere, og undlad at publicere dem på GitHub.

Anbefalet `.gitignore`:

```gitignore
.venv/
__pycache__/
*.pyc
reports/
scan_output.txt
```

## Test

Kør de eksisterende enhedstests, hvis testmiljøet understøtter dem:

```powershell
python -m unittest discover -s tests -v
```

Kør derefter `python main.py` og verificér, at både `.json` og `.html` oprettes. Kontroller, at `ERROR`-fund vises korrekt, og at rapportens indhold svarer til den genererede JSON.

## Videreudvikling

- Versionsvalidering af CVE'er med produktidentifikation, CPE-data og leverandøradvarsler.
- Mere præcis Windows-patch- og SMB-vurdering.
- Autoriseret ekstern netværksverifikation i et isoleret testmiljø (fremtidigt `NET-006`).
- Mulig AI-assisteret analyse af evidens og prioritering; AI-agent og penetrationstest er ikke implementeret i v0.2.

## Projektstatus

**Version 0.2 — proof of concept.** Resultater kræver faglig fortolkning og bør ikke bruges som eneste grundlag for sikkerhedskritiske beslutninger.
