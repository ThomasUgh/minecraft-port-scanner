# 🎮 MC Server Scanner

[![Python](https://img.shields.io/badge/Python-3.7%2B-blue.svg)](https://www.python.org/downloads/)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Version](https://img.shields.io/badge/Version-1.0.0-orange.svg)](https://github.com/yourusername/mc-server-scanner)

Ein leistungsstarker und benutzerfreundlicher Minecraft Server Scanner mit Port-Scanning-Funktionalität (TCP/UDP) und API-Integration für Server-Status-Abfragen.

## ✨ Features

- **🔍 Port-Range-Scanning**: Scannt TCP und/oder UDP Ports in einem angegebenen Bereich
- **📦 Vordefinierte Port-Ranges**: Eingebaute Ranges für Java, Bedrock, Geyser und mehr
- **📊 Server-Status API**: Holt detaillierte Server-Informationen über die mcsrvstat.us API
- **🌐 Domain-Auflösung**: Automatische Auflösung von Domains zu IP-Adressen
- **⚡ Multi-Threading**: Schnelles Scanning mit konfigurierbaren Threads
- **🎮 Multi-Edition Support**: Unterstützt Java Edition, Bedrock Edition und Geyser

## 📋 Voraussetzungen

- Python 3.7 oder höher
- pip (Python Package Manager)

## 🚀 Installation

### 1. Repository klonen

```bash
git clone https://github.com/ThomasUgh/minecraft-port-scanner.git
```

### 2. Ausführbar machen (Linux/macOS)

```bash
chmod +x mc_scanner.py
```

### 3. Starten

```bash
python mc_scanner.py
```

## 📖 Verwendung

Das Tool bietet drei Hauptmodi: `scan`, `status` und `interactive`.

### 🎯 Vordefinierte Port-Ranges

Das Tool enthält vordefinierte Port-Ranges für verschiedene Minecraft Server-Typen:

| Range Name | Port-Bereich | Beschreibung |
|------------|--------------|--------------|
| `default` | 25000-26000 | Standard-Suchbereich |
| `java` | 25565 | Standard Java Edition Port |
| `bedrock` | 19132 | Standard Bedrock Edition Port |
| `geyser` | 19100-19900 | Geyser/Bedrock Proxy Bereich |
| `bungeecord` | 25577 | Standard BungeeCord Proxy Port |
| `velocity` | 25565-25577 | Velocity Proxy Bereich |
| `common` | 25565-25600 | Häufig verwendete Server-Ports |
| `extended` | 25000-30000 | Erweiterter Suchbereich |
| `full` | 19000-30000 | Vollständiger Scan (Bedrock + Java) |

### 🔍 Port-Scanning Modus

**Standard-Bereich scannen (25000-26000):**
```bash
python mc_scanner.py scan 192.168.1.100
```

**Vollständigen Bereich scannen (19000-30000):**
```bash
python mc_scanner.py scan 192.168.1.100 -r full
```

**Benutzerdefinierten Port-Bereich scannen:**
```bash
python mc_scanner.py scan 192.168.1.100 -p 25565-25575
```

**Nur TCP/UDP-Ports scannen:**
```bash
python mc_scanner.py scan 192.168.1.100 --tcp
```

### 📊 Server-Status Modus

**Server-Status abrufen:**
```bash
python mc_scanner.py status play.example.com
```

### 🔄 Interaktiver Modus

```bash
python mc_scanner.py interactive
```

Im interaktiven Modus können Sie:
1. Port-Bereiche scannen
2. Server-Status abrufen
3. Beides kombinieren
4. Mehrere Operationen nacheinander ausführen

## 🎯 Beispiele

### Beispiel 1: Lokales Netzwerk scannen
```bash
# Scannt alle Ports im Standard-Bereich für einen lokalen Server
python mc_scanner.py scan 192.168.178.50
```

### Beispiel 2: Geyser/Bedrock Server suchen
```bash
# Scannt den Geyser Port-Bereich (19100-19900)
python mc_scanner.py scan 192.168.178.50 -r geyser
```

### Beispiel 3: Java und Bedrock Ports prüfen
```bash
# Scannt sowohl Java als auch Bedrock Standard-Ports
python mc_scanner.py scan myserver.com -r full
```

## 🛠️ Kommandozeilen-Optionen

### Scan-Modus Optionen

| Option | Beschreibung | Standard |
|--------|--------------|----------|
| `target` | Ziel-IP oder Domain | - |
| `-p, --ports` | Port-Bereich: START-END, PORT, oder Preset-Name | default |
| `-r, --range` | Vordefinierte Range verwenden (java/bedrock/geyser/etc.) | - |
| `--tcp` | Nur TCP-Ports scannen | Beide |
| `--udp` | Nur UDP-Ports scannen | Beide |
| `-t, --timeout` | Verbindungs-Timeout in Sekunden | 0.5 |
| `--threads` | Anzahl der Threads | 100 |

### Status-Modus Optionen

| Option | Beschreibung | Standard |
|--------|--------------|----------|
| `server` | Server-Adresse (IP:Port oder Domain) | - |
| `--scan` | Führt zusätzlich einen Port-Scan durch | Nein |
| `-p, --ports` | Port-Bereich: START-END, PORT, oder Preset-Name | default |
| `-r, --range` | Vordefinierte Range für Scan (java/bedrock/geyser/etc.) | - |


## 🔒 Sicherheitshinweise

- **Verantwortungsvolle Nutzung**: Scannen Sie nur Server, für die Sie die Erlaubnis haben
- **Netzwerklast**: Hohe Thread-Zahlen können Netzwerke belasten
- **Firewall-Regeln**: Einige Firewalls können Port-Scans blockieren oder als Angriff werten
- **Rate-Limiting**: Die API hat möglicherweise Rate-Limits bei zu vielen Anfragen

## 📄 Lizenz

Dieses Projekt ist unter der MIT-Lizenz lizenziert - siehe [LICENSE](LICENSE) für Details.

## 🙏 Credits

- API bereitgestellt von [mcsrvstat.us](https://mcsrvstat.us/)
- Entwickelt mit ❤️ für die Minecraft-Community

---

**Hinweis**: Verwenden Sie dieses Tool verantwortungsvoll und nur für Server, für die Sie die Berechtigung haben. Der Entwickler übernimmt keine Verantwortung für Missbrauch.
