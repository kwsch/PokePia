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

## Requirements to Build

- .NET SDK 10.0+
- Nintendo Switch with Sword / Shield
- Computer to run this application on the same local network as the Switch

## Usage

- The Nintendo Switch must be in LAN mode and on the same local network. Search for a trade.
- Run the executable that is built.
- The client will automatically discover the host, connect, and dump the party Pokémon.

## Notes

- PKHeX.Core is used for PK8 and save-related structures.
- Protocol handling is based on the upstream Python implementation and protocol docs used by that project.

## License

**GNU General Public License v3.0 (GPL-3.0)**.
