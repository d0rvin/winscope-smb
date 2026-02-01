package main

import (
	"flag"
	"fmt"
	"os"
	"text/tabwriter"

	"github.com/d0rvin/winscope-smb/pkg/protocol"
	"github.com/d0rvin/winscope-smb/pkg/protocol/ntlmssp"
	v1 "github.com/d0rvin/winscope-smb/pkg/protocol/smb/v1"
	v2 "github.com/d0rvin/winscope-smb/pkg/protocol/smb/v2"
)

func main() {
	host := flag.String("host", "", "SMB host (required)")
	port := flag.Uint("port", 445, "SMB port")
	proxy := flag.String("proxy", "", "Proxy URL, e.g. socks5://127.0.0.1:7897")
	flag.Parse()

	if *host == "" {
		fmt.Fprintln(os.Stderr, "host is required")
		flag.Usage()
		os.Exit(2)
	}

	opts := []protocol.Option{}
	if *proxy != "" {
		opts = append(opts, protocol.WithProxy(*proxy))
	}

	cfg := protocol.Config{
		Host:    *host,
		Port:    uint16(*port),
		Options: opts,
	}

	if err := runV1(cfg); err != nil {
		v1Err := err
		if err := runV2(cfg); err != nil {
			fmt.Fprintf(os.Stderr, "SMBv1 error: %v\n", v1Err)
			fmt.Fprintf(os.Stderr, "SMBv2 error: %v\n", err)
			os.Exit(1)
		}
	}
}

func runV1(cfg protocol.Config) error {
	s, err := v1.NewSession(cfg)
	if err != nil {
		return err
	}
	defer s.Close()

	if err := s.Negotiate(); err != nil {
		return fmt.Errorf("negotiate: %w", err)
	}

	sRes, challenge, err := s.SessionSetupAndX()
	if err != nil {
		return fmt.Errorf("session setup: %w", err)
	}

	fmt.Println("SMBv1:")
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintf(w, "\tNative Lan Man:\t%s\n", sRes.NativeLanMan)
	fmt.Fprintf(w, "\tNative OS:\t%s\n", sRes.NativeOS)
	fmt.Fprintf(w, "\tWindows Build Version:\t%d.%d.%d\n", challenge.Version.Major, challenge.Version.Minor, challenge.Version.Build)
	if os, ok := challenge.Version.ParseToOS(); ok {
		fmt.Fprintf(w, "\tWindows Version:\t%s\n", os)
	}

	printTargetInfo(w, challenge.TargetInfo)
	_ = w.Flush()
	challenge.Version.ParseToOS()
	fmt.Println()

	return nil
}

func runV2(cfg protocol.Config) error {
	s, err := v2.NewSession(cfg)
	if err != nil {
		return err
	}
	defer s.Close()

	if err := s.Negotiate(); err != nil {
		return fmt.Errorf("negotiate: %w", err)
	}

	challenge, err := s.Setup1()
	if err != nil {
		return fmt.Errorf("session setup: %w", err)
	}

	fmt.Println("SMBv2:")
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintf(w, "\tWindows Build Version:\t%d.%d.%d\n", challenge.Version.Major, challenge.Version.Minor, challenge.Version.Build)
	if os, ok := challenge.Version.ParseToOS(); ok {
		fmt.Fprintf(w, "\tWindows Version:\t%s\n", os)
	}
	printTargetInfo(w, challenge.TargetInfo)
	_ = w.Flush()
	fmt.Println()

	return nil
}

func printTargetInfo(w *tabwriter.Writer, targetInfo *ntlmssp.AvPairSlice) {
	if targetInfo == nil {
		return
	}

	detail := targetInfo.Parse()
	fmt.Fprintf(w, "\tNB Computer Name:\t%s\n", detail.NBComputerName)
	fmt.Fprintf(w, "\tNB Domain Name:\t%s\n", detail.NBDomainName)
	fmt.Fprintf(w, "\tDNS Computer Name:\t%s\n", detail.DNSComputerName)
	fmt.Fprintf(w, "\tDNS Domain Name:\t%s\n", detail.DNSDomainName)
	fmt.Fprintf(w, "\tDNS Tree Name:\t%s\n", detail.DNSTreeName)
	fmt.Fprintf(w, "\tTarget Name:\t%s\n", detail.TargetName)
}
