import requests
import ipaddress
import argparse
import re
import json
from typing import List, Dict, Any

class EngInsightTagManager:
    def __init__(self, base_url: str, access_key_id: str, access_key_secret: str,
                 tag_key: str, tag_value: str = None,
                 conditions: List[str] = None, negative_conditions: List[str] = None,
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
            print(f"❌ API Error: {e}")
            if hasattr(e, 'response') and hasattr(e.response, 'text'):
                print(f"   Response: {e.response.text}")
            return {}
    
    def get_all_hosts(self) -> List[Dict[str, Any]]:
        """Ruft alle Hosts aus der EngInsight API ab."""
        print("📡 Rufe alle Hosts ab...")
        response = self._make_request('GET', '/v1/hosts')
        hosts = response.get('hosts', [])
        print(f"✓ {len(hosts)} Hosts gefunden\n")
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
            print(f"  ✗ Fehler beim Update: {e}")
            return False
    
    def add_tag(self, host: Dict[str, Any]) -> bool:
        """Fügt einen Tag zu einem Host hinzu."""
        host_id = host.get('_id')
        hostname = host.get('displayName') or host.get('hostname', 'Unknown')
        
        current_tags = host.get('tags', [])
        if self.full_tag not in current_tags:
            new_tags = current_tags + [self.full_tag]
            
            if self.dry_run:
                print(f"  ℹ️  [DRY-RUN] Tag würde hinzugefügt: {hostname}")
                print(f"       Neuer Tag: {self.full_tag}")
                return True
            else:
                if self.update_host_tags(host_id, new_tags):
                    print(f"  ✓ Tag hinzugefügt: {hostname}")
                    print(f"     Tag: {self.full_tag}")
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
                print(f"  ℹ️  [DRY-RUN] Tag würde entfernt: {hostname}")
                print(f"       Entfernter Tag: {self.full_tag}")
                return True
            else:
                if self.update_host_tags(host_id, new_tags):
                    print(f"  ✓ Tag entfernt: {hostname}")
                    print(f"     Tag: {self.full_tag}")
                    return True
        return False
    
    def get_host_ips(self, host: Dict[str, Any]) -> List[str]:
        """Extrahiert alle IPs eines Hosts für die Anzeige."""
        ips = []
        for nic in host.get('nics', []):
            for address in nic.get('addresses', []):
                try:
                    ip_str = address.split('/')[0]
                    ip = ipaddress.ip_address(ip_str)
                    if isinstance(ip, ipaddress.IPv4Address):
                        ips.append(str(ip))
                except (ValueError, IndexError):
                    continue
        return ips
    
    def check_condition(self, host: Dict[str, Any]) -> bool:
        """Prüft, ob der Host die Regex-Bedingungen erfüllt."""
        host_json = json.dumps(host, indent=2)
        if self.condition_mode == "or":
            positive_ok = any(p.search(host_json) is not None for p in self.condition_patterns) if self.condition_patterns else True
        else:  # AND (default)
            positive_ok = all(p.search(host_json) is not None for p in self.condition_patterns) if self.condition_patterns else True
        negative_ok = all(n.search(host_json) is None for n in self.negative_condition_patterns) \
                      if self.negative_condition_patterns else True
        if self.negative_condition_mode == "or" and self.negative_condition_patterns:
            negative_ok = not any(n.search(host_json) is not None for n in self.negative_condition_patterns)

        return positive_ok and negative_ok
    
    def process_hosts(self) -> None:
        """Verarbeitet alle Hosts und verwaltet Tags basierend auf der Bedingung."""
        hosts = self.get_all_hosts()
        
        if not hosts:
            print("⚠️  Keine Hosts gefunden!")
            return
        
        added_count = 0
        removed_count = 0
        unchanged_count = 0
        
        print(f"{'='*80}")
        if self.condition_patterns or self.negative_condition_patterns:
            print(f"Bedingungen (+): {[p.pattern for p in self.condition_patterns] or ['(keine)']} (Mode: {self.condition_mode.upper()})")
            print(f"Bedingungen (-): {[p.pattern for p in self.negative_condition_patterns] or ['(keine)']} (Mode: {self.negative_condition_mode.upper()})")
        else:
            print("Bedingung: Keine (alle Hosts)")
        print(f"Tag: {self.full_tag}")
        if self.negate_conditions:
            print("Bedingungen werden negiert: Ja")
        if self.dry_run:
            print("Modus: 🔍 DRY-RUN (nur Anzeige)")
        print(f"{'='*80}\n")
        
        for host in hosts:
            host_id = host.get('_id')
            hostname = host.get('displayName') or host.get('hostname', 'Unknown')
            ips = self.get_host_ips(host)
            condition_met = self.check_condition(host)
            if self.negate_conditions:
                condition_met = not condition_met
            has_tag = self.has_tag(host)
            
            print(f"🖥️  {hostname}")
            print(f"   IPs: {', '.join(ips) if ips else 'Keine IPv4-Adressen'}")
            print(f"   Bedingung erfüllt: {'✓' if condition_met else '✗'}")
            print(f"   Hat Tag: {'✓' if has_tag else '✗'}")
            
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
            
            print()
        
        print(f"{'='*80}")
        print(f"📊 Zusammenfassung:")
        print(f"   Tags hinzugefügt:  {added_count}")
        print(f"   Tags entfernt:     {removed_count}")
        print(f"   Unverändert:       {unchanged_count}")
        print(f"   Gesamt:            {len(hosts)}")
        print(f"{'='*80}")


def main():
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
        required=True,
        help='EngInsight API Base-URL (z.B. https://api.enginsight.com)'
    )
    
    parser.add_argument(
        '--key-id',
        required=True,
        help='EngInsight Access Key ID'
    )
    
    parser.add_argument(
        '--key-secret',
        required=True,
        help='EngInsight Access Key Secret'
    )
    
    parser.add_argument(
        '--tag-key',
        required=True,
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
        '--negate-conditions',
        action='store_true',
        help='Invertiert das Gesamtergebnis der Bedingungen (nach positiv/negativ-Auswertung)'
    )
    parser.add_argument(
        '--condition-mode',
        choices=['and', 'or'],
        default='and',
        help='Logik für positive Bedingungen: and (alle müssen matchen) oder or (mindestens eine)'
    )
    parser.add_argument(
        '--negative-condition-mode',
        choices=['and', 'or'],
        default='and',
        help='Logik für negative Bedingungen: and (keine darf matchen) oder or (mindestens eine darf nicht matchen)'
    )
    
    parser.add_argument(
        '--dry-run',
        action='store_true',
        help='Zeige nur an, was geändert würde, ohne tatsächlich zu ändern'
    )
    
    args = parser.parse_args()
    
    print("🚀 EngInsight Tag Manager gestartet\n")
    
    manager = EngInsightTagManager(
        base_url=args.url,
        access_key_id=args.key_id,
        access_key_secret=args.key_secret,
        tag_key=args.tag_key,
        tag_value=args.tag_value,
        conditions=args.condition,
        negative_conditions=args.negative_condition,
        dry_run=args.dry_run,
        negate_conditions=args.negate_conditions,
        condition_mode=args.condition_mode,
        negative_condition_mode=args.negative_condition_mode
    )
    
    manager.process_hosts()
    
    print("\n✅ Verarbeitung abgeschlossen")


if __name__ == '__main__':
    main()
