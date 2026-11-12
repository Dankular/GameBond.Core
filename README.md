# GameBond.Core

Shared code for the GameBond client and server:

- `bond`: the GB03 bonded transport (codec, receiver, sender, FEC, BFD, session).
- `buildinfo`: the build id (git commit) both sides report.
- `hwmon`: hardware monitoring used by the client UI and the server admin portal.

Used by [GameBond.Client](https://github.com/Dankular/GameBond.Client) and
[GameBond.Server](https://github.com/Dankular/GameBond.Server). A change to the wire protocol
goes here first, is tagged, and both repos then bump their `require`.
