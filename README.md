# Python TeamSpeak 3 Client

Ein experimenteller TeamSpeak-3-Client in Python. Der Client implementiert den
TS3-UDP-Handshake, Command-Pakete, Events, Keepalive, sauberen Disconnect,
Voice-Echo, Pitch-Echo und ein einfaches Musikbot-Feature.

Der relevante Einstieg ist [`ts3_client.py`](ts3_client.py).

## Features

- Verbindung zu einem TeamSpeak-3-Server per UDP
- TS3-Handshake inklusive `initivexpand2`, `clientek` und `clientinit`
- QuickLZ-Dekompression für Server-Commands
- Event-Ausgabe für Chatnachrichten und weitere `notify...` Events
- Keepalive mit Ping/Pong und korrekten ACK-Paket-IDs
- sauberer Disconnect mit Leave-Message
- Echo-Test für eingehende Voice-Pakete
- optionaler Pitch-Effekt für Echo-Test
- Musikbot-Modus über Datei oder Audio-Link

## Voraussetzungen

- Python 3.11 oder neuer
- `ffmpeg` für `--play-link`
- Python-Pakete:
  - `pycryptodome`
  - `opuslib` für `--echo-pitch` und `--play-link`

Auf macOS:

```bash
brew install ffmpeg
```

Optional für YouTube oder Plattformlinks:

```bash
brew install yt-dlp
```

Direkte Audio-URLs und lokale Audiodateien funktionieren ohne `yt-dlp`.

## Setup

Empfohlen ist eine lokale virtuelle Python-Umgebung im Projekt:

```bash
python3 -m venv .venv
.venv/bin/python -m pip install --upgrade pip
.venv/bin/python -m pip install pycryptodome opuslib
```

Danach immer die Python-Version aus der venv nutzen:

```bash
.venv/bin/python ts3_client.py --help
```

Wenn du stattdessen `python3 ts3_client.py ...` nutzt und Fehler wie
`ModuleNotFoundError: No module named 'Crypto'` bekommst, verwendest du nicht die
venv oder die Dependencies sind in dieser Python-Umgebung nicht installiert.

## Lokalen Testserver Starten

Im Repository liegt ein lokaler TS3-Server unter `server/`.

```bash
cd server
./ts3server license_accepted=1
```

In einem zweiten Terminal den Client starten:

```bash
.venv/bin/python -u ts3_client.py localhost -n PythonClient
```

`-u` ist hilfreich, damit Python die Ausgabe sofort in die Konsole schreibt.

## Basisnutzung

Mit Standardport `9987` verbinden:

```bash
.venv/bin/python -u ts3_client.py example.com -n PythonClient
```

Mit Port:

```bash
.venv/bin/python -u ts3_client.py example.com -p 9987 -n PythonClient
```

Mit Serverpasswort:

```bash
.venv/bin/python -u ts3_client.py example.com -n PythonClient --password "secret"
```

Nur kurz verbinden und danach trennen:

```bash
.venv/bin/python -u ts3_client.py localhost -n PythonClient --stay-seconds 5
```

Mehr Debug-Ausgabe:

```bash
.venv/bin/python -u ts3_client.py localhost -n PythonClient -vv
```

## Events und Chatnachrichten

Der Client verarbeitet Server-Events im laufenden Listen-Loop. Chatnachrichten
werden lesbar ausgegeben:

```text
[MSG:channel] Benutzername: Hallo
[MSG:privat] Benutzername: Hi
[MSG:server] Benutzername: Nachricht
```

Mit `-v` oder `-vv` werden weitere `notify...` Events angezeigt.

## Sauberer Disconnect

Mit `Ctrl+C` sendet der Client vor dem Schliessen:

```text
clientdisconnect reasonid=8 reasonmsg=Python Client say's good bye!
```

Der Client wartet danach auf `notifyclientleftview` für die eigene Client-ID und
schließt erst dann den Socket. Dadurch sieht der Server keinen Timeout, sondern
einen normalen Leave.

## Echo-Test

Eingehende Voice-Pakete werden direkt wieder in den Channel gesendet:

```bash
.venv/bin/python -u ts3_client.py localhost -n EchoBot --echo-test
```

Mit Debug-Ausgabe:

```bash
.venv/bin/python -u ts3_client.py localhost -n EchoBot --echo-test -vv
```

Beispielausgabe:

```text
[VOICE] from=1 voice_id=56422 codec=4 bytes=63 plain
[ECHO] voice_id=1 codec=4 bytes=63 plain
```

Der Echo-Test spiegelt den Opus-Payload. Eigene Voice-Pakete werden ignoriert,
damit kein Echo-Loop entsteht.

## Pitch-Echo

Mit `--echo-pitch` kann die Stimme im Echo-Test höher oder tiefer gemacht
werden.

Normal:

```bash
.venv/bin/python -u ts3_client.py localhost -n EchoBot --echo-test --echo-pitch 1.0
```

Höhere Stimme:

```bash
.venv/bin/python -u ts3_client.py localhost -n EchoBot --echo-test --echo-pitch 1.6
```

Tiefere Stimme:

```bash
.venv/bin/python -u ts3_client.py localhost -n EchoBot --echo-test --echo-pitch 0.65
```

Echo leiser oder lauter ausgeben:

```bash
.venv/bin/python -u ts3_client.py localhost -n EchoBot --echo-test --volume 0.5
.venv/bin/python -u ts3_client.py localhost -n EchoBot --echo-test --volume 2.0
```

`--echo-pitch 1.0` nutzt den direkten Echo ohne Decode/Re-Encode. Sobald der
Wert von `1.0` abweicht, braucht der Client `opuslib`, dekodiert Opus zu PCM,
verschiebt die Tonhöhe und kodiert wieder Opus.

Wenn `--volume` von `1.0` abweicht, wird ebenfalls dekodiert und neu kodiert,
damit die Lautstärke angepasst werden kann.

## Musikbot

Mit `--play-link` spielt der Client eine lokale Datei oder einen Audio-Link ab.
Intern wird `ffmpeg` genutzt, um Audio nach 48 kHz mono PCM zu wandeln. Danach
kodiert `opuslib` die Daten als Opus und der Client sendet TS3-Voice-Pakete.

Der Client erkennt den Codec des aktuellen Channels dynamisch:

- Channel mit `OpusVoice`: Sendung als Codec `4` mit Voice-Profil
- Channel mit `OpusMusic`: Sendung als Codec `5` mit Music-Profil

Bei `OpusMusic` nutzt der Encoder `APPLICATION_AUDIO`, VBR und Complexity `10`.
Damit wird Musik besser behandelt als im normalen Voice-Profil. Der aktuelle
Audiopfad ist weiterhin mono; echtes Stereo-/3D-Audio ist noch nicht umgesetzt.

Lokale Datei:

```bash
.venv/bin/python -u ts3_client.py localhost -n MusicBot --play-link /pfad/song.mp3
```

Direkter Audio-Link:

```bash
.venv/bin/python -u ts3_client.py localhost -n MusicBot --play-link "https://example.com/audio.mp3"
```

Nach der Wiedergabe noch 10 Sekunden verbunden bleiben:

```bash
.venv/bin/python -u ts3_client.py localhost -n MusicBot --play-link /pfad/song.mp3 --stay-seconds 10
```

Lautstärke des Musikbots setzen:

```bash
.venv/bin/python -u ts3_client.py localhost -n MusicBot --play-link /pfad/song.mp3 --volume 0.5
.venv/bin/python -u ts3_client.py localhost -n MusicBot --play-link /pfad/song.mp3 --volume 1.5
```

YouTube oder andere Plattformlinks brauchen meistens `yt-dlp`:

```bash
brew install yt-dlp
.venv/bin/python -u ts3_client.py localhost -n MusicBot --play-link "https://www.youtube.com/watch?v=..."
```

Wenn `yt-dlp` nicht installiert ist, versucht der Client den Link direkt an
`ffmpeg` zu geben. Das funktioniert nur bei URLs, die `ffmpeg` selbst lesen kann.

## CLI Referenz

```text
usage: ts3_client.py [-h] [-p PORT] [-n NICKNAME] [--password PASSWORD]
                     [--stay-seconds STAY_SECONDS] [--play-link PLAY_LINK]
                     [--echo-test] [--echo-pitch ECHO_PITCH] [--volume VOLUME]
                     [-v]
                     [host]
```

Optionen:

- `host`: Serverhost, Standard `localhost`
- `-p`, `--port`: UDP-Port, Standard `9987`
- `-n`, `--nickname`: Nickname des Clients
- `--password`: Serverpasswort
- `--stay-seconds`: nach Connect oder Wiedergabe nur diese Sekunden laufen
- `--play-link`: Datei oder Link als Musikbot abspielen
- `--echo-test`: eingehende Voice-Pakete zurückspielen
- `--echo-pitch`: Pitch-Faktor für Echo-Test, Standard `1.0`
- `--volume`: Ausgabe-Lautstärke, Standard `1.0`, z.B. `0.5` leiser oder `2.0` lauter
- `-v`: Verbose-Ausgabe, mehrfach nutzbar

## Troubleshooting

### `ModuleNotFoundError: No module named 'Crypto'`

`pycryptodome` fehlt in der verwendeten Python-Umgebung.

```bash
.venv/bin/python -m pip install pycryptodome
.venv/bin/python -u ts3_client.py localhost -n PythonClient
```

### `Pitch-Echo braucht opuslib`

`opuslib` fehlt in der verwendeten Python-Umgebung.

```bash
.venv/bin/python -m pip install opuslib
```

### `--play-link braucht ffmpeg im PATH`

`ffmpeg` ist nicht installiert oder nicht im `PATH`.

```bash
brew install ffmpeg
```

### Der Client scheint zu laufen, zeigt aber keine Ausgabe

Starte Python mit `-u`, damit stdout nicht gepuffert wird:

```bash
.venv/bin/python -u ts3_client.py localhost -n PythonClient
```

### YouTube-Link funktioniert nicht

Installiere `yt-dlp`:

```bash
brew install yt-dlp
```

Danach erneut starten.

## Hinweise

Das Projekt ist ein experimenteller TS3-Protokollclient. Es ist kein offizieller
TeamSpeak-Client und nicht für produktive Audioqualität optimiert. Voice wird
als Opus-Paketstream behandelt; Audio-Jitterbuffer, Lautstärkeregelung,
Playlist-Management und komfortable Bot-Steuerung sind aktuell nicht enthalten.
