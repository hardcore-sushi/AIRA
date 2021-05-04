# AIRA
AIRA is peer-to-peer encrypted communication tool for local networks built on the [PSEC protocol](https://forge.chapril.org/hardcoresushi/PSEC). It allows to securely send text messages and files without any server or Internet access. AIRA automatically discovers and connects to other peers on your network, so you don't need any prior configuration to start communicating.

![Screenshot of a conversation between Alice and Bob on AIRA](/screenshot.png)

# Rationale
When people want to send a file from one computer to another located only meters apart, they usually send it via mail. This mail usually goes through many servers around the world before reaching its final destination.

Likewise, when people are lazy, they talk sometimes to their friends in the next room using centralized mobiles apps like Whatsapp. Their messages can be exported thousands of kilometers away to reach Facebook's servers where they are analysed with the aim of offering personalized ads and selling your data before being sent on the same way back to your friend's smartphone.

All this practices generate useless traffic, overload servers, often breach privacy but above all pollute a lot. This is why I decided to build a more ecological and private way to communicate with near devices.

# Similar works
There are already some great projects that allow offline P2P communications, but they require that the peer you want to communicate with be a known contact, usually by first adding their public key to your contact list.

- [Briar](https://briarproject.org)
- [berty](https://berty.tech)
- [BeeBEEP](https://www.beebeep.net)
- Add your own !

# Disclaimer
AIRA is still under developement and is not ready for production usage yet. Not all features have been implemented and bugs are expected. Neither the code or the PSEC protocol received any security audit and therefore shouldn't be considered fully secure. AIRA is provided "as is", without any warranty of any kind.

# Features
- Cross-platform
- End-to-End encryption using the [PSEC protocol](https://forge.chapril.org/hardcoresushi/PSEC)
- Automatic peer discovery using mDNS
- Manual peer connection
- File transferts
- Encrypted database
- Contact verification
- IPv4/v6 compatibility
- Web frontend that directly runs in browser
- Free/Libre and Open Source

# Download
AIRA releases are availables in the "Release" section. All files MUST be signed with my PGP key. Don't execute them if the verification fails.

To download my key:
`gpg --keyserver hkp://pool.sks-keyservers.net --recv-keys 007F84120107191E` \
Fingerprint: `BD56 2147 9E7B 74D3 6A40  5BE8 007F 8412 0107 191E` \
Email: `Hardcore Sushi <hardcore.sushi@disroot.org>`

Then, verify release file: `gpg --verify aira.elf.asc aira.elf`

# Build
### Install Rust
```
curl --proto '=https' --tlsv1.3 -sSf https://sh.rustup.rs | sh
```
### Download AIRA
```
git clone --depth=1 https://forge.chapril.org/hardcoresushi/AIRA.git && cd AIRA
```
### Verify commit
```
git verify-commit HEAD
```
### Build AIRA
```
cargo build --release
```

## What does AIRA stand for ?
AIRA Is a Recursive Acronym.