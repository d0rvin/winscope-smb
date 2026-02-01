# WinScope-SMB

WinScope-SMB is a lightweight Windows version detection tool built on top of the SMB protocol.
It supports SMB v1 and SMB v2/3 negotiation paths and is designed to be easy to learn, read, and extend.

## Example output

```bash
> winscope-smb -host 192.0.2.10
SMBv1:
  Native Lan Man:         Windows Server (R) 2008 Enterprise without Hyper-V 6.0
  Native OS:              Windows Server (R) 2008 Enterprise without Hyper-V 6003 Service Pack 2
  Windows Build Version:  6.0.6003
  Windows Version:        Windows Server 2008, Service Pack 2, Rollup KB4489887
  NB Computer Name:       DORVIN
  NB Domain Name:         DORVIN
  DNS Computer Name:      dorvin
  DNS Domain Name:        dorvin
  DNS Tree Name:
  Target Name:
```

## Why this project is easy to learn

- Small, focused codebase: only the pieces needed for SMB negotiation and NTLMSSP parsing are implemented.
- Clear separation between protocol layers (NetBIOS, SMB, NTLMSSP), which makes the flow easy to follow.
- A minimal CLI and a reusable SDK so you can start with the tool and then embed the logic in your own code.

## How it works

1. Establish a TCP connection to the SMB service (default port 445).
2. Perform SMB negotiation (SMBv1 or SMBv2+).
3. Trigger an unauthenticated session setup to obtain the NTLMSSP challenge.
4. Parse the NTLMSSP challenge to extract:
   - Windows build version (major, minor, build)
   - Target information (NetBIOS and DNS names)
5. Optionally map the build number to a human-readable Windows version.

This mirrors the SMB protocol design where the server advertises platform details during
negotiation and NTLMSSP session setup.

## Features

- SMBv1 and SMBv2/3 negotiation paths
- Windows build and version mapping
- NetBIOS and DNS target info parsing
- Optional SOCKS5 proxy support
- SDK-style packages for embedding in other tools

## Install

```bash
go install github.com/d0rvin/winscope-smb@latest
```

## CLI usage

```text
winscope-smb -host <host> [-port <port>] [-proxy <url>]
```

Arguments:

- `-host` (required): SMB host, IP or hostname
- `-port` (default 445): SMB port
- `-proxy` (optional): Proxy URL, e.g. `socks5://127.0.0.1:7897`

Behavior:

- The tool attempts SMBv1 first; if SMBv1 fails it falls back to SMBv2/3.
- On success, it prints the detected Windows build/version and target info.
- On failure, it prints the SMBv1 and SMBv2/3 errors and exits with code `1`.
- If `-host` is missing, it prints usage and exits with code `2`.

Examples:

```bash
# Basic scan
winscope-smb -host 192.0.2.10

# Custom port
winscope-smb -host 192.0.2.10 -port 1445

# Through a SOCKS5 proxy
winscope-smb -host 192.0.2.10 -proxy socks5://127.0.0.1:7897
```

## SDK usage (Go)

Minimal example using SMBv2:

```go
package main

import (
	"fmt"
	"github.com/d0rvin/winscope-smb/pkg/protocol"
	v2 "github.com/d0rvin/winscope-smb/pkg/protocol/smb/v2"
)

func main() {
	cfg := protocol.Config{
		Host: "192.0.2.10",
		Port: 445,
	}

	s, err := v2.NewSession(cfg)
	if err != nil {
		panic(err)
	}
	defer s.Close()

	if err := s.Negotiate(); err != nil {
		panic(err)
	}

	challenge, err := s.Setup1()
	if err != nil {
		panic(err)
	}

	fmt.Printf("Build: %d.%d.%d\n",
		challenge.Version.Major,
		challenge.Version.Minor,
		challenge.Version.Build,
	)
	if osName, ok := challenge.Version.ParseToOS(); ok {
		fmt.Printf("Windows: %s\n", osName)
	}
}
```

SMBv1 example is similar; use `pkg/protocol/smb/v1` and call:
`Negotiate()` then `SessionSetupAndX()`.

## Project layout

- `cmd/`: CLI entrypoint
- `pkg/protocol/`: connection, config, and protocol layers
- `pkg/protocol/smb/v1`: SMBv1 session flow
- `pkg/protocol/smb/v2`: SMBv2/3 session flow
- `pkg/protocol/ntlmssp`: NTLMSSP parsing and Windows version mapping

## References

- [stacktitan/smb](https://github.com/stacktitan/smb)
- [MS-SMB: Server Message Block (SMB) Protocol](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb)
- [MS-SMB2: Server Message Block (SMB) Protocol Version 2 and 3](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2)
- [Windows version numbers](https://www.gaijin.at/en/infos/windows-version-numbers)
