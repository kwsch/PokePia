# PokePia

C#/.NET 10 port of the original Python project: [lincoln-lm/swsh-lan-client](https://github.com/lincoln-lm/swsh-lan-client), an implementation of [Pia](https://github.com/kinnay/NintendoClients/wiki/Pia-Overview).

This client implements Pokémon Sword/Shield LAN trade protocol flow over UDP:

- Matchmaking (`BrowseRequest` / `BrowseReply`)
- Host handshake (`HostRequest` / `HostMessage`)
- Station connection
- Mesh join
- Initial trade broadcast capture
- Party dump to `.pk8` files

Dumped files can be opened by PKHeX.

## Requirements to Run

- .NET Runtime 10.0+
- Nintendo Switch with Sword / Shield
- Computer to run this application on the same local network as the Switch

## Usage

1. Double click PokePia.exe and have it listen.
1. Go into LAN mode on SWSH (L + R + Left Stick in Options).
1. Start a local trade with no Link Code.
1. The program should detect your SWSH game and analyze/dump your party.

  <img width="640" height="360" alt="Screenshot of SWSH when LAN mode is successfully enabled" src="https://github.com/user-attachments/assets/394082a7-eafc-4e36-ba36-f81206203ec5" />


## Notes

- PKHeX.Core is used for PK8 and save-related structures.
- Protocol handling is based on the upstream Python implementation and protocol docs used by that project.

## License

**GNU General Public License v3.0 (GPL-3.0)**.
