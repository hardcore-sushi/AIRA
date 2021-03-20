# AIRA
AIRA is peer-to-peer encrypted communication tool for local networks built on the [PSEC protocol](https://forge.chapril.org/hardcoresushi/PSEC). It allows to securely send text messages and files without any server or Internet access.

<img src="https://forge.chapril.org/hardcoresushi/AIRA/raw/branch/master/screenshot.png">

# Rationale
When people want to send a file from one computer to another located only meters apart, they usually send it via mail. This mail usually goes through many servers around the world before reaching its final destination.

Likewise, when people are lazy, they talk sometimes to their friends in the next room using centralized mobiles apps like Whatsapp. Their messages can be exported thousands of kilometers away to reach Facebook's servers where they are analysed with the aim of offering personalized ads and selling your data before being sent on the same way back to your friend's smartphone.

All this practices generate useless traffic, overload servers, often breach privacy but above all pollute a lot. This is why I decided to build a more ecological and private way to communicate with near devices. There are many awesome P2P projects built on top of the Internet, but none of them provide local-network communications that work even totally disconnected from the rest of the world. AIRA is the first to provide this capability.

# Disclaimer
AIRA is still under developement and is not ready for production usage yet. Not all features have been implemented and bugs are expected. Neither the code or the PSEC protocol received any security audit and therefore shouldn't be considered fully secure. AIRA is provided "as is", without any warranty of any kind.

# Features
- Cross-platform
- End-to-End encryption using the [PSEC protocol](https://forge.chapril.org/hardcoresushi/PSEC)
- Automatic peer discovery using mDNS
- Manual peer connection
- File transferts
- Notifications
- Encrypted database
- Contact verification
- IPv4/v6 compatibility
- Web frontend that directly runs in browser
- Free/Libre and Open Source

# Build
### Install Rust
```
curl --proto '=https' --tlsv1.3 -sSf https://sh.rustup.rs | sh
```
### Download AIRA
```
git clone --depth=1 https://forge.chapril.org/hardcoresushi/AIRA.git && cd AIRA
```
### Build AIRA
```
cargo build --release
```

## What does AIRA stand for ?
AIRA Is a Recursive Acronym.