NETCAT.R4X
==========

NETCAT.R4X ist ein Terminalwerkzeug fuer einfache TCP-Datenuebertragung.

Projektstruktur seit 0.51.19:
- `build.zig` baut die App als eigenes SDK-Projekt.
- `build.zig.zon` bindet `r4os_sdk` als Paket.
- `module.R4MF` beschreibt Artefakt, Zielpfad, Imports und Contract.

Build:

    cd Code\System\Software\NetCat
    ..\..\..\DevTools\Zig\zig.exe build

Ergebnis:

    Code\System\Software\NetCat\zig-out\NETCAT.R4X

Contract:
- R4XStart-Entry: `netcat_main`
- App-Klasse: `console`
- R4L-Imports: `R4SYS`, `R4DESK`, `R4NET`
- Zielpfad im Image: `C:\R4OS\SOFTWARE\TERMINAL\NETCAT.R4X`

