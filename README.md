# NW AI Domains Feed

Wlasne, automatycznie aktualizowane zrodlo domen AI/LLM dla NetWitness.
Pobiera publiczne listy (np. `abixb/llm-hosts-blocklist`), klasyfikuje wpisy
i generuje plik CSV w formacie feeda **F.07** gotowy do importu jako
**Non-IP Callback Feed** na Decoderze.

```
host,threat.category,threat.desc,threat.source
api.openai.com,llm-provider,openai api,nw-llm-v4.0
chat.openai.com,ai-consumer,openai chat,nw-llm-v4.0
api.cursor.sh,ai-coding,cursor ai api,nw-llm-v4.0
```

## Jak to dziala

1. `sources.yaml` definiuje zrodla i reguly klasyfikacji.
2. `build_feed.py` pobiera, parsuje, dedupuje i mapuje na kategorie:
   - `llm-provider` — endpointy API i strony providerow
   - `ai-consumer` — interfejsy webowe (chat.openai.com, claude.ai, gemini...)
   - `ai-coding` — asystenci kodu (Copilot, Cursor, Tabnine, Codeium)
3. `.github/workflows/update-feed.yml` uruchamia build co tydzien i commituje
   zmiany, jesli upstream dorzucil nowe domeny.

## Uruchomienie lokalne

```bash
pip install requests pyyaml
python3 build_feed.py
```

Wynik: `feed/F.07_llm_providers.csv` + `feed_summary.md` ze statystykami.

## Wlasne dostrojenie

- **Dodac zrodlo** -> dopisz blok w `sources.yaml` (format `hosts` lub `domains`).
- **Dodac domene recznie** (np. tenantowa `*.openai.azure.com`) -> `overrides/manual_add.csv`.
- **Wyciac szum** (status./docs./cdn.) -> `overrides/exclude.txt` (obsluga `prefix.*`).
- **Tylko sygnalowe hosty** -> w `sources.yaml` ustaw `include_roles: [api, chat]`.
- **Bump wersji** -> zmien `threat_source` w `sources.yaml`.

## Import na NetWitness Decoder

Konfiguracja Non-IP Callback Feed (zgodnie z F.07):

| Pole | Wartosc |
|---|---|
| Type | Non-IP |
| Index Column | `host` (kolumna 1) |
| Callback Key | `alias.host` |
| Truncate Domain | OFF |
| Ignore Case | ON |
| Kolumna 2 | `threat.category` |
| Kolumna 3 | `threat.desc` |
| Kolumna 4 | `threat.source` |
| Has Header | No |
| Separator | przecinek |

Surowy plik (do recurring feed w NetWitness wprost z GitHuba):

```
https://raw.githubusercontent.com/<twoj-user>/nw-ai-domains-feed/main/feed/F.07_llm_providers.csv
```

## Setup repo (raz)

```bash
git init
git add .
git commit -m "init: NW AI domains feed"
git branch -M main
git remote add origin git@github.com:<twoj-user>/nw-ai-domains-feed.git
git push -u origin main
```

Potem w GitHub: Settings -> Actions -> General -> Workflow permissions ->
**Read and write permissions** (zeby bot mogl commitowac). Workflow odpali sie
sam w poniedzialki albo recznie z zakladki **Actions -> Run workflow**.

## Uwaga o zrodlach

Listy upstream sa community-driven i nastawione na *blokowanie*, wiec lapia
tez sub-domeny szumowe (status, docs, cdn). Do detekcji exfiltracji zwykle
liczy sie `api.*` i interfejsy `chat`/`consumer` — reszta to kontekst.
Filtruj rolami albo `exclude.txt` wedlug tego, co realnie monitorujesz.
