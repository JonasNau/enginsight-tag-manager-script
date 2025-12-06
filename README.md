EngInsight Tag Manager
======================

Automatisches Tag-Management für EngInsight Hosts über die öffentliche API. Das Skript liest alle Hosts, prüft frei definierbare Regex-Bedingungen und fügt oder entfernt Tags entsprechend. Unterstützt Dry-Run, AND/OR-Logik für positive und negative Bedingungen sowie hierarchische Tags im Format `~key:value`.

Inhalt
------
- Was das Tool macht
- Voraussetzungen
- Installation
- Aufruf & Argumente
- Tag- und Bedingungslogik
- Beispiele
- Typischer Output
- Troubleshooting

Was das Tool macht
------------------
- Holt alle Hosts über `GET /v1/hosts`.
- Prüft Regex-Bedingungen gegen die vollständige Host-JSON-Repräsentation.
- Fügt den gewünschten Tag hinzu, wenn die Bedingung erfüllt ist und der Tag fehlt.
- Entfernt den Tag, wenn die Bedingung nicht erfüllt ist und der Tag vorhanden ist.
- Optionaler Dry-Run: zeigt nur an, was passieren würde.

Voraussetzungen
---------------
- Python 3.9+ (getestet mit Python 3.11).
- Abhängigkeit: `requests` (reines Standard-Python sonst). Installation z.B.:

```
pip install requests
```

- EngInsight API-Zugangsdaten (`x-ngs-access-key-id`, `x-ngs-access-key-secret`).

Installation
------------
1. Repository/Script lokal ablegen.
2. Abhängigkeit installieren (siehe oben).
3. Optional: Zugriffsdaten als Umgebungsvariablen setzen, sonst als Parameter übergeben.

Aufruf & Argumente
------------------
Grundaufruf:

```
python enginsight_tag_manager.py \
	--url https://api.enginsight.com \
	--key-id <YOUR_KEY_ID> \
	--key-secret <YOUR_KEY_SECRET> \
	--tag-key <TAG_KEY> \
	[--tag-value <TAG_VALUE>] \
	[--condition <REGEX>]... \
	[--negative-condition <REGEX>]... \
	[--condition-mode and|or] \
	[--negative-condition-mode and|or] \
	[--negate-conditions] \
	[--dry-run]
```

Parameterübersicht
- `--url` (pflicht): Basis-URL der EngInsight API, z.B. `https://api.enginsight.com`.
- `--key-id` / `--key-secret` (pflicht): Access Keys.
- `--tag-key` (pflicht): Tag-Schlüssel. Bei hierarchischen Tags wird daraus `~tag-key:tag-value`.
- `--tag-value` (optional): Tag-Wert. Ohne Wert wird nur der Key als einfacher Tag verwendet.
- `--condition` (mehrfach): Regex-Pattern (positiv). Standard-Modus: AND.
- `--negative-condition` (mehrfach): Regex-Pattern (negativ). Standard-Modus: AND (keines darf matchen).
- `--condition-mode`: `and` (Default) oder `or` für positive Bedingungen.
- `--negative-condition-mode`: `and` (Default) oder `or` für negative Bedingungen.
- `--negate-conditions`: Negiert das Gesamtergebnis nach positiver/negativer Auswertung.
- `--dry-run`: Zeigt nur an, welche Tags hinzugefügt/entfernt würden.

Tag- und Bedingungslogik
- Tag-Format: mit Wert -> `~<tag_key>:<tag_value>` (beides kleingeschrieben), ohne Wert -> `<tag_key>`.
- Positive Bedingungen: müssen matchen (AND) bzw. mindestens eine (OR).
- Negative Bedingungen: dürfen nicht matchen (AND) bzw. mindestens eine darf nicht matchen (OR).
- `--negate-conditions` invertiert das Gesamtergebnis. Endgültige Entscheidung:
	- Bedingung erfüllt & Tag fehlt → Tag wird hinzugefügt.
	- Bedingung nicht erfüllt & Tag vorhanden → Tag wird entfernt.
	- Sonst keine Änderung.

Beispiele
---------
PowerShell-Beispiele (analog auch in Bash nutzbar):

```
# Hierarchisches Tag nach Subnetz
python enginsight_tag_manager.py ^
	--url https://api.enginsight.com ^
	--key-id YOUR_KEY_ID ^
	--key-secret YOUR_KEY_SECRET ^
	--tag-key physischer_standort ^
	--tag-value muenchen ^
	--condition "192\.168\.178\."

# Einfacher Tag ohne Wert
python enginsight_tag_manager.py ^
	--url https://api.enginsight.com ^
	--key-id YOUR_KEY_ID ^
	--key-secret YOUR_KEY_SECRET ^
	--tag-key homeoffice ^
	--condition "192\.168\."

# Windows-Hosts erkennen
python enginsight_tag_manager.py ^
	--url https://api.enginsight.com ^
	--key-id YOUR_KEY_ID ^
	--key-secret YOUR_KEY_SECRET ^
	--tag-key betriebssystem ^
	--tag-value windows ^
	--condition "\"name\":\s*\"windows\""

# Hosts mit >8GB RAM
python enginsight_tag_manager.py ^
	--url https://api.enginsight.com ^
	--key-id YOUR_KEY_ID ^
	--key-secret YOUR_KEY_SECRET ^
	--tag-key ram_kategorie ^
	--tag-value high_ram ^
	--condition "\"ram\":\s*(8[2-9][0-9]{2}|9[0-9]{3}|[1-9][0-9]{4,})"

# Dry-Run nur anzeigen
python enginsight_tag_manager.py ^
	--url https://api.enginsight.com ^
	--key-id YOUR_KEY_ID ^
	--key-secret YOUR_KEY_SECRET ^
	--tag-key physischer_standort ^
	--tag-value muenchen ^
	--condition "192\.168\.178\." ^
	--dry-run
```

Weitere Beispielskripte finden sich in `enginsight-tag-manager-examples.sh` und `enginsight-tag-physicher-standort-example.sh`.

Typischer Output
----------------
- Zeigt pro Host: Name, IPv4-Adressen, Bedingungsstatus, Tag-Status und Aktion (hinzufügen/entfernen/keine Änderung).
- Abschließende Zusammenfassung: Anzahl hinzugefügt, entfernt, unverändert, Gesamt.

Troubleshooting
---------------
- API Error: Zugangsdaten oder URL prüfen; ggf. vollständige Response wird ausgegeben.
- Keine Hosts gefunden: API-Berechtigungen oder Filter in EngInsight prüfen.
- Regex matcht nicht: Host-Struktur per `--dry-run` inspizieren und Pattern anpassen.

HTTP-Test
---------
Eine Beispiel-HTTP-Datei liegt in `httprequest.http` (mit Platzhaltern für die Access Keys) für einfache Connectivity-Checks.

Lizenz
------
Keine Lizenzdatei enthalten; Nutzung nach Absprache mit dem Autor.
