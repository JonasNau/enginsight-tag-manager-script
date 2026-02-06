#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
EngInsight Tag Manager - Automatisches Tag-Management basierend auf Regex-Bedingungen
Dieses Skript verbindet sich mit der EngInsight API, um Hosts basierend auf
definierten Regex-Bedingungen zu taggen oder zu enttaggen.
Voraussetzungen:
- Python 3.6+
- requests-Bibliothek (pip install requests)
- Optional: python-dotenv für Umgebungsvariablen (pip install python-dotenv)


Autor: IBYKUS AG - Jonas Naumann


Lizenz: MIT
"""

import requests
import ipaddress
import argparse
import re
import json
import os
from typing import List, Dict, Any, Optional, Tuple

try:
    from dotenv import load_dotenv
except Exception:  # pragma: no cover - optional dependency
    load_dotenv = None

class EngInsightTagManager:
    def __init__(self, base_url: str, access_key_id: str, access_key_secret: str,
                 tag_key: str, tag_value: str = None,
                 conditions: List[str] = None, negative_conditions: List[str] = None,
                 value_conditions: List[Tuple[str, str]] = None,
                 negative_value_conditions: List[Tuple[str, str]] = None,
                 dry_run: bool = False, negate_conditions: bool = False,
                 condition_mode: str = "and", negative_condition_mode: str = "and"):
        """
        Initialisiert den EngInsight Tag Manager.
        
        Args:
            base_url: Die Basis-URL der EngInsight API
            access_key_id: Der Access Key ID für die Authentifizierung
            access_key_secret: Der Access Key Secret für die Authentifizierung
            tag_key: Der Tag-Schlüssel (z.B. PHYSISCHER_STANDORT)
            tag_value: Der Tag-Wert (z.B. MÜNCHEN), optional
            conditions: Liste von Regex-Patterns für die Bedingungen (alle müssen erfüllt sein)
            negative_conditions: Liste von Regex-Patterns für die negativen Bedingungen (keines darf erfüllt sein)
            dry_run: Nur Anzeige ohne tatsächliche Änderungen
        """
        self.base_url = base_url.rstrip('/')
        self.headers = {
            'content-type': 'application/json',
            'x-ngs-access-key-id': access_key_id,
            'x-ngs-access-key-secret': access_key_secret
        }
        self.tag_key = tag_key
        self.tag_value = tag_value
        self.dry_run = dry_run
        self.negate_conditions = negate_conditions
        self.condition_mode = condition_mode.lower()
        self.negative_condition_mode = negative_condition_mode.lower()
        
        # Tag formatieren: ~key:value oder nur key
        if tag_value:
            self.full_tag = f"~{self.tag_key.lower()}:{self.tag_value.lower()}"
        else:
            self.full_tag = self.tag_key.lower()
        
        self.condition_patterns = [re.compile(c) for c in (conditions or [])]
        self.negative_condition_patterns = [re.compile(c) for c in (negative_conditions or [])]
        self.value_condition_patterns = [
            (k, re.compile(p)) for k, p in (value_conditions or [])
        ]
        self.negative_value_condition_patterns = [
            (k, re.compile(p)) for k, p in (negative_value_conditions or [])
        ]
        
    def _make_request(self, method: str, endpoint: str, data: Dict[str, Any] = None) -> Dict[str, Any]:
        """Macht HTTP-Requests zur EngInsight API."""
        url = f"{self.base_url}{endpoint}"
        try:
            response = requests.request(
                method=method.upper(),
                url=url,
                headers=self.headers,
                json=data
            )
            response.raise_for_status()
            return response.json() if response.text else {}
        except requests.exceptions.RequestException as e:
            print(f"API Error: {e}")
            if hasattr(e, 'response') and hasattr(e.response, 'text'):
                print(f"   Response: {e.response.text}")
            return {}
    
    def get_all_hosts(self) -> List[Dict[str, Any]]:
        """Ruft alle Hosts aus der EngInsight API ab."""
        print("Rufe alle Hosts ab...")
        response = self._make_request('GET', '/v1/hosts?limit=-1')
        hosts = response.get('hosts', [])
        print(f"{len(hosts)} Hosts gefunden\n")
        return hosts
    
    def has_tag(self, host: Dict[str, Any]) -> bool:
        """Prüft, ob ein Host den Tag bereits hat."""
        tags = host.get('tags', [])
        return self.full_tag in tags
    
    def update_host_tags(self, host_id: str, tags: List[str]) -> bool:
        """Aktualisiert die Tags eines Hosts."""
        try:
            payload = {
                'host': {
                    'tags': tags
                }
            }
            self._make_request('PUT', f'/v1/hosts/{host_id}', payload)
            return True
        except Exception as e:
            print(f"  Fehler beim Update: {e}")
            return False
    
    def add_tag(self, host: Dict[str, Any]) -> bool:
        """Fügt einen Tag zu einem Host hinzu."""
        host_id = host.get('_id')
        hostname = host.get('displayName') or host.get('hostname', 'Unknown')
        
        current_tags = host.get('tags', [])
        if self.full_tag not in current_tags:
            new_tags = current_tags + [self.full_tag]
            
            if self.dry_run:
                print(f"[DRY-RUN] Tag würde hinzugefügt: {hostname}")
                print(f"Neuer Tag: {self.full_tag}")
                return True
            else:
                if self.update_host_tags(host_id, new_tags):
                    print(f"Tag hinzugefügt: {hostname}")
                    print(f"Tag: {self.full_tag}")
                    return True
        return False
    
    def remove_tag(self, host: Dict[str, Any]) -> bool:
        """Entfernt einen Tag von einem Host."""
        host_id = host.get('_id')
        hostname = host.get('displayName') or host.get('hostname', 'Unknown')
        
        current_tags = host.get('tags', [])
        if self.full_tag in current_tags:
            new_tags = [tag for tag in current_tags if tag != self.full_tag]
            
            if self.dry_run:
                print(f"[DRY-RUN] Tag würde entfernt: {hostname}")
                print(f"Entfernter Tag: {self.full_tag}")
                return True
            else:
                if self.update_host_tags(host_id, new_tags):
                    print(f"Tag entfernt: {hostname}")
                    print(f"Tag: {self.full_tag}")
                    return True
        return False
    
    def get_host_ips(self, host: Dict[str, Any]) -> List[str]:
        """Extrahiert alle IPs eines Hosts für die Anzeige."""
        ips = []
        nics = host.get('nics') or []
        for nic in nics:
            if not isinstance(nic, dict):
                continue
            addresses = nic.get('addresses') or []
            for address in addresses:
                if not isinstance(address, str):
                    continue
                try:
                    ip_str = address.split('/')[0]
                    ip = ipaddress.ip_address(ip_str)
                    if isinstance(ip, ipaddress.IPv4Address):
                        ips.append(str(ip))
                except (ValueError, IndexError):
                    continue
        return ips

    def _extract_values_for_key(self, data: Any, key: str) -> List[Any]:
        """Sammelt alle Werte für einen Key (rekursiv in dict/list)."""
        values = []
        if isinstance(data, dict):
            for k, v in data.items():
                if k == key:
                    values.append(v)
                values.extend(self._extract_values_for_key(v, key))
        elif isinstance(data, list):
            for item in data:
                values.extend(self._extract_values_for_key(item, key))
        return values
    
    def evaluate_conditions(self, host: Dict[str, Any]) -> Dict[str, Any]:
        """Prüft, ob der Host die Regex-Bedingungen erfüllt und liefert Debug-Details."""
        try:
            host_json = json.dumps(host, indent=2, default=str)
        except Exception:
            host_json = str(host)

        positive_results = []
        for p in self.condition_patterns:
            matched = p.search(host_json) is not None
            positive_results.append({"pattern": p.pattern, "matched": matched})

        value_positive_results = []
        for key, pattern in self.value_condition_patterns:
            values = self._extract_values_for_key(host, key)
            matched = any(pattern.search(str(v)) is not None for v in values)
            value_positive_results.append({
                "key": key,
                "pattern": pattern.pattern,
                "matched": matched
            })

        negative_results = []
        for n in self.negative_condition_patterns:
            matched = n.search(host_json) is not None
            negative_results.append({"pattern": n.pattern, "matched": matched})

        value_negative_results = []
        for key, pattern in self.negative_value_condition_patterns:
            values = self._extract_values_for_key(host, key)
            matched = any(pattern.search(str(v)) is not None for v in values)
            value_negative_results.append({
                "key": key,
                "pattern": pattern.pattern,
                "matched": matched
            })

        if self.condition_mode == "or":
            positive_ok = any(
                r["matched"] for r in (positive_results + value_positive_results)
            ) if (positive_results or value_positive_results) else True
        else:
            positive_ok = all(
                r["matched"] for r in (positive_results + value_positive_results)
            ) if (positive_results or value_positive_results) else True

        all_negative_results = negative_results + value_negative_results
        if self.negative_condition_mode == "or" and all_negative_results:
            negative_ok = not any(r["matched"] for r in all_negative_results)
        else:
            negative_ok = all(not r["matched"] for r in all_negative_results) if all_negative_results else True

        condition_met = positive_ok and negative_ok

        return {
            "positive_results": positive_results,
            "value_positive_results": value_positive_results,
            "negative_results": negative_results,
            "value_negative_results": value_negative_results,
            "positive_ok": positive_ok,
            "negative_ok": negative_ok,
            "condition_met": condition_met
        }
    
    def process_hosts(self) -> None:
        """Verarbeitet alle Hosts und verwaltet Tags basierend auf der Bedingung."""
        hosts = self.get_all_hosts()
        
        if not hosts:
            print("Keine Hosts gefunden!")
            return
        
        added_count = 0
        removed_count = 0
        unchanged_count = 0
        matched_count = 0
        
        print(f"{'='*80}")
        if self.condition_patterns or self.negative_condition_patterns:
            print(f"Bedingungen (+): {[p.pattern for p in self.condition_patterns] or ['(keine)']} (Mode: {self.condition_mode.upper()})")
            print(f"Bedingungen (-): {[p.pattern for p in self.negative_condition_patterns] or ['(keine)']} (Mode: {self.negative_condition_mode.upper()})")
        else:
            print("Bedingung: Keine (alle Hosts)")
        if self.value_condition_patterns:
            print(f"Value-Bedingungen (+): {[f'{k}={p.pattern}' for k, p in self.value_condition_patterns]}")
        if self.negative_value_condition_patterns:
            print(f"Value-Bedingungen (-): {[f'{k}={p.pattern}' for k, p in self.negative_value_condition_patterns]}")
        print(f"Tag: {self.full_tag}")
        if self.negate_conditions:
            print("Bedingungen werden negiert: yes")
        if self.dry_run:
            print("Modus: DRY-RUN (nur Anzeige)")
        print(f"{'='*80}\n")
        
        for host in hosts:
            try:
                host_id = host.get('_id') if isinstance(host, dict) else None
                hostname = (
                    host.get('displayName') if isinstance(host, dict) else None
                ) or (
                    host.get('hostname') if isinstance(host, dict) else None
                ) or 'Unknown'
                ips = self.get_host_ips(host if isinstance(host, dict) else {})
                condition_details = self.evaluate_conditions(host if isinstance(host, dict) else {})
                condition_met = condition_details["condition_met"]
                if self.negate_conditions:
                    condition_met = not condition_met
                has_tag = self.has_tag(host) if isinstance(host, dict) else False
                
                print(f"Hostname: {hostname}")
                print(f"   IPs: {', '.join(ips) if ips else 'Keine IPv4-Adressen'}")
                if condition_details["positive_results"]:
                    print("   Positive Regex Checks:")
                    for result in condition_details["positive_results"]:
                        print(f"      - {result['pattern']}: {'yes' if result['matched'] else 'no'}")
                else:
                    print("   Positive Regex Checks: (keine)")
                if condition_details["value_positive_results"]:
                    print("   Positive Value Checks:")
                    for result in condition_details["value_positive_results"]:
                        print(f"      - {result['key']}={result['pattern']}: {'yes' if result['matched'] else 'no'}")
                else:
                    print("   Positive Value Checks: (keine)")
                if condition_details["negative_results"]:
                    print("   Negative Regex Checks:")
                    for result in condition_details["negative_results"]:
                        print(f"      - {result['pattern']}: {'yes' if result['matched'] else 'no'}")
                else:
                    print("   Negative Regex Checks: (keine)")
                if condition_details["value_negative_results"]:
                    print("   Negative Value Checks:")
                    for result in condition_details["value_negative_results"]:
                        print(f"      - {result['key']}={result['pattern']}: {'yes' if result['matched'] else 'no'}")
                else:
                    print("   Negative Value Checks: (keine)")
                if self.negate_conditions:
                    print(f"   Bedingung erfüllt (vor Negation): {'yes' if condition_details['condition_met'] else 'no'}")
                print(f"   Bedingung erfüllt: {'yes' if condition_met else 'no'}")
                print(f"   Hat Tag: {'yes' if has_tag else 'no'}")
                if condition_met:
                    matched_count += 1
                
                if condition_met and not has_tag:
                    # Bedingung erfüllt und Tag fehlt → Tag hinzufügen
                    if self.add_tag(host):
                        added_count += 1
                elif not condition_met and has_tag:
                    # Bedingung nicht erfüllt und Tag vorhanden → Tag entfernen
                    if self.remove_tag(host):
                        removed_count += 1
                else:
                    # Keine Änderung nötig
                    status = "Tag bereits vorhanden" if has_tag else "Tag nicht erforderlich"
                    print(f"  → {status}")
                    unchanged_count += 1
            except Exception as e:
                print(f"Host konnte nicht verarbeitet werden: {e}")
                unchanged_count += 1
            
            print()
        
        print(f"{'='*80}")
        print("Zusammenfassung:")
        print(f"   Tags added:        {added_count}")
        print(f"   Tags removed:      {removed_count}")
        print(f"   Total hosts that match: {matched_count}")
        print(f"   Unchanged:         {unchanged_count}")
        print(f"   Total:             {len(hosts)}")
        print(f"{'='*80}")


def _env_or_arg(arg_value: Optional[str], env_key: str) -> Optional[str]:
    return arg_value or os.getenv(env_key)


def _load_config_file(path: Optional[str]) -> Dict[str, Any]:
    if not path:
        return {}
    try:
        with open(path, 'r', encoding='utf-8') as file:
            return json.load(file) or {}
    except Exception as e:
        print(f"Config konnte nicht geladen werden: {e}")
        return {}


def _parse_value_regex(pairs: List[str]) -> List[Tuple[str, str]]:
    parsed = []
    for item in pairs or []:
        if '=' not in item:
            continue
        key, pattern = item.split('=', 1)
        key = key.strip()
        pattern = pattern.strip()
        if key and pattern:
            parsed.append((key, pattern))
    return parsed


def main():
    if load_dotenv:
        load_dotenv()
    parser = argparse.ArgumentParser(
        description='EngInsight Tag Manager - Automatisches Tag-Management basierend auf Regex-Bedingungen',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Beispiele:
  # Hierarchisches Tag: ~physischer_standort:gera
  python enginsight_tag_manager.py \\
    --url https://api.enginsight.com \\
    --key-id YOUR_KEY_ID \\
    --key-secret YOUR_KEY_SECRET \\
    --tag-key physischer_standort \\
    --tag-value gera \\
    --condition "192\\.168\\.178\\."

  # Einfacher Tag ohne Wert: homeoffice
  python enginsight_tag_manager.py \\
    --url https://api.enginsight.com \\
    --key-id YOUR_KEY_ID \\
    --key-secret YOUR_KEY_SECRET \\
    --tag-key homeoffice \\
    --condition "192\\.168\\."

  # Windows-Hosts mit hierarchischem Tag
  python enginsight_tag_manager.py \\
    --url https://api.enginsight.com \\
    --key-id YOUR_KEY_ID \\
    --key-secret YOUR_KEY_SECRET \\
    --tag-key betriebssystem \\
    --tag-value windows \\
    --condition "\\"name\\":\\s*\\"windows\\""

  # Hosts mit mehr als 8GB RAM
  python enginsight_tag_manager.py \\
    --url https://api.enginsight.com \\
    --key-id YOUR_KEY_ID \\
    --key-secret YOUR_KEY_SECRET \\
    --tag-key ram_kategorie \\
    --tag-value high_ram \\
    --condition "\\"ram\\":\\s*(8[2-9][0-9]{2}|9[0-9]{3}|[1-9][0-9]{4,})"

  # Debian-Hosts
  python enginsight_tag_manager.py \\
    --url https://api.enginsight.com \\
    --key-id YOUR_KEY_ID \\
    --key-secret YOUR_KEY_SECRET \\
    --tag-key distribution \\
    --tag-value debian \\
    --condition "\\"platform\\":\\s*\\"debian\\""

  # Hosts mit Intel CPU
  python enginsight_tag_manager.py \\
    --url https://api.enginsight.com \\
    --key-id YOUR_KEY_ID \\
    --key-secret YOUR_KEY_SECRET \\
    --tag-key cpu_vendor \\
    --tag-value intel \\
    --condition "\\"vendorId\\":\\s*\\"GenuineIntel\\""

  # DRY-RUN: Nur anzeigen, was geändert würde
  python enginsight_tag_manager.py \\
    --url https://api.enginsight.com \\
    --key-id YOUR_KEY_ID \\
    --key-secret YOUR_KEY_SECRET \\
    --tag-key physischer_standort \\
    --tag-value münchen \\
    --condition "192\\.168\\.178\\." \\
    --dry-run

  # Alle Hosts mit beliebiger Bedingung (kein Pattern)
  python enginsight_tag_manager.py \\
    --url https://api.enginsight.com \\
    --key-id YOUR_KEY_ID \\
    --key-secret YOUR_KEY_SECRET \\
    --tag-key production
        '''
    )
    
    parser.add_argument(
        '--url',
        required=False,
        help='EngInsight API Base-URL (z.B. https://api.enginsight.com)'
    )

    parser.add_argument(
        '--config',
        required=False,
        help='Pfad zu einer JSON-Config-Datei (optional, nur für Bedingungen)'
    )
    
    parser.add_argument(
        '--key-id',
        required=False,
        help='EngInsight Access Key ID'
    )
    
    parser.add_argument(
        '--key-secret',
        required=False,
        help='EngInsight Access Key Secret'
    )
    
    parser.add_argument(
        '--tag-key',
        required=False,
        help='Tag-Schlüssel (z.B. physischer_standort)'
    )
    
    parser.add_argument(
        '--tag-value',
        default=None,
        help='Tag-Wert (z.B. gera). Optional - wenn nicht angegeben, wird nur der Key als Tag verwendet'
    )
    
    parser.add_argument(
        '--condition',
        action='append',
        default=[],
        help='Regex-Pattern (positiv). Kann mehrfach angegeben werden; alle müssen matchen.'
    )
    parser.add_argument(
        '--negative-condition',
        action='append',
        default=[],
        help='Regex-Pattern (negativ). Kann mehrfach angegeben werden; keiner darf matchen.'
    )
    parser.add_argument(
        '--value-regex',
        action='append',
        default=[],
        help='Regex nur für einen Key-Wert, Format: key=regex (mehrfach möglich)'
    )
    parser.add_argument(
        '--negative-value-regex',
        action='append',
        default=[],
        help='Negativer Regex nur für einen Key-Wert, Format: key=regex (mehrfach möglich)'
    )
    parser.add_argument(
        '--negate-conditions',
        action='store_true',
        help='Invertiert das Gesamtergebnis der Bedingungen (nach positiv/negativ-Auswertung)'
    )
    parser.add_argument(
        '--condition-mode',
        choices=['and', 'or'],
        default=None,
        help='Logik für positive Bedingungen: and (alle müssen matchen) oder or (mindestens eine)'
    )
    parser.add_argument(
        '--negative-condition-mode',
        choices=['and', 'or'],
        default=None,
        help='Logik für negative Bedingungen: and (keine darf matchen) oder or (mindestens eine darf nicht matchen)'
    )
    
    parser.add_argument(
        '--dry-run',
        action='store_true',
        help='Zeige nur an, was geändert würde, ohne tatsächlich zu ändern'
    )
    
    args = parser.parse_args()

    config = _load_config_file(args.config)

    config_conditions = config.get('conditions', []) if isinstance(config, dict) else []
    config_negative_conditions = config.get('negative_conditions', []) if isinstance(config, dict) else []
    config_value_conditions = config.get('value_conditions', []) if isinstance(config, dict) else []
    config_negative_value_conditions = config.get('negative_value_conditions', []) if isinstance(config, dict) else []

    value_conditions = _parse_value_regex(args.value_regex)
    negative_value_conditions = _parse_value_regex(args.negative_value_regex)

    if isinstance(config_value_conditions, dict):
        value_conditions = value_conditions + [(k, v) for k, v in config_value_conditions.items()]
    elif isinstance(config_value_conditions, list):
        value_conditions = value_conditions + [tuple(item) for item in config_value_conditions if isinstance(item, (list, tuple)) and len(item) == 2]

    if isinstance(config_negative_value_conditions, dict):
        negative_value_conditions = negative_value_conditions + [(k, v) for k, v in config_negative_value_conditions.items()]
    elif isinstance(config_negative_value_conditions, list):
        negative_value_conditions = negative_value_conditions + [tuple(item) for item in config_negative_value_conditions if isinstance(item, (list, tuple)) and len(item) == 2]

    base_url = _env_or_arg(args.url, "ENGINSIGHT_API_URL")
    access_key_id = _env_or_arg(args.key_id, "ENGINSIGHT_ACCESS_KEY_ID")
    access_key_secret = _env_or_arg(args.key_secret, "ENGINSIGHT_ACCESS_KEY_SECRET")

    missing = []
    if not base_url:
        missing.append("ENGINSIGHT_API_URL or --url")
    if not access_key_id:
        missing.append("ENGINSIGHT_ACCESS_KEY_ID or --key-id")
    if not access_key_secret:
        missing.append("ENGINSIGHT_ACCESS_KEY_SECRET or --key-secret")
    if not args.tag_key:
        missing.append("--tag-key")
    if missing:
        parser.error("Missing required configuration: " + ", ".join(missing))
    
    print("EngInsight Tag Manager gestartet\n")
    
    manager = EngInsightTagManager(
        base_url=base_url,
        access_key_id=access_key_id,
        access_key_secret=access_key_secret,
        tag_key=args.tag_key,
        tag_value=args.tag_value,
        conditions=(config_conditions or []) + (args.condition or []),
        negative_conditions=(config_negative_conditions or []) + (args.negative_condition or []),
        value_conditions=value_conditions,
        negative_value_conditions=negative_value_conditions,
        dry_run=args.dry_run,
        negate_conditions=args.negate_conditions,
        condition_mode=args.condition_mode or 'and',
        negative_condition_mode=args.negative_condition_mode or 'and'
    )
    
    manager.process_hosts()
    
    print("\nVerarbeitung abgeschlossen")


if __name__ == '__main__':
    main()
