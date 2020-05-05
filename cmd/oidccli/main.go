package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/pardot/oidc"
	"github.com/pardot/oidc/clitoken"
	"github.com/pardot/oidc/tokencache"
	"golang.org/x/net/context"
)

type subCommand struct {
	Flags       *flag.FlagSet
	Description string
}

type baseOpts struct {
	Issuer       string
	ClientID     string
	ClientSecret string
	Offline      bool
	SkipCache    bool
}

type rawOpts struct{}

type kubeOpts struct{}

type infoOpts struct{}

func main() {
	ctx := context.Background()

	baseFlags := baseOpts{
		Offline: false,
	}
	baseFs := flag.NewFlagSet("oidccli", flag.ExitOnError)
	baseFs.StringVar(&baseFlags.Issuer, "issuer", baseFlags.Issuer, "OIDC Issuer URL (required)")
	baseFs.StringVar(&baseFlags.ClientID, "client-id", baseFlags.ClientID, "OIDC Client ID (required)")
	baseFs.StringVar(&baseFlags.ClientSecret, "client-secret", baseFlags.ClientSecret, "OIDC Client Secret")
	baseFs.BoolVar(&baseFlags.Offline, "offline", baseFlags.Offline, "Offline use (request refresh token). This token will be cached locally, can be used to avoid re-launching the auth flow when the token expires")

	var subcommands []*subCommand

	rawFlags := rawOpts{}
	rawFs := flag.NewFlagSet("raw", flag.ExitOnError)
	subcommands = append(subcommands, &subCommand{
		Flags:       rawFs,
		Description: "Output a raw JWT for this client",
	})

	kubeFlags := kubeOpts{}
	kubeFs := flag.NewFlagSet("kubernetes", flag.ExitOnError)
	subcommands = append(subcommands, &subCommand{
		Flags:       kubeFs,
		Description: "Output credentials in a format that can be consumed by kubectl/client-go",
	})

	infoFlags := infoOpts{}
	infoFs := flag.NewFlagSet("info", flag.ExitOnError)
	subcommands = append(subcommands, &subCommand{
		Flags:       infoFs,
		Description: "Output information about the auth response in human-readable format",
	})

	if err := baseFs.Parse(os.Args[1:]); err != nil {
		fmt.Printf("failed parsing args: %v", err)
		os.Exit(1)
	}

	if len(baseFs.Args()) < 1 {
		fmt.Print("error: subcommand required\n\n")
		printFullUsage(baseFs, subcommands)
		os.Exit(1)
	}

	var missingFlags []string
	if baseFlags.Issuer == "" {
		missingFlags = append(missingFlags, "issuer")
	}
	if baseFlags.ClientID == "" {
		missingFlags = append(missingFlags, "client-id")
	}

	var execFn func(context.Context, oidc.TokenSource) error

	switch baseFs.Arg(0) {
	case "raw":
		if err := rawFs.Parse(baseFs.Args()[1:]); err != nil {
			fmt.Printf("failed parsing raw args: %v", err)
			os.Exit(1)
		}
		execFn = func(ctx context.Context, ts oidc.TokenSource) error {
			return raw(ctx, ts, rawFlags)
		}
	case "kubernetes":
		if err := kubeFs.Parse(baseFs.Args()[1:]); err != nil {
			fmt.Printf("failed parsing kube args: %v", err)
			os.Exit(1)
		}
		execFn = func(ctx context.Context, ts oidc.TokenSource) error {
			return kubernetes(ctx, ts, kubeFlags)
		}
	case "info":
		if err := infoFs.Parse(baseFs.Args()[1:]); err != nil {
			fmt.Printf("failed parsing info args: %v", err)
			os.Exit(1)
		}
		execFn = func(ctx context.Context, ts oidc.TokenSource) error {
			return info(ctx, ts, infoFlags)
		}
	default:
		fmt.Printf("error: invalid subcommand %s\n\n", baseFs.Arg(0))
		printFullUsage(baseFs, subcommands)
		os.Exit(1)
	}

	if len(missingFlags) > 0 {
		fmt.Printf("error: %s are required flags\n\n", strings.Join(missingFlags, ", "))
		printFullUsage(baseFs, subcommands)
		os.Exit(1)
	}

	var opts []oidc.ClientOpt
	if baseFlags.Offline {
		opts = append(opts, oidc.WithAdditionalScopes([]string{oidc.ScopeOfflineAccess}))
	}

	client, err := oidc.DiscoverClient(ctx, baseFlags.Issuer, baseFlags.ClientID, baseFlags.ClientSecret, "", opts...)
	if err != nil {
		fmt.Printf("failed to discover issuer: %v", err)
		os.Exit(1)
	}

	clis, err := clitoken.NewSource(client)
	if err != nil {
		fmt.Printf("getting cli token source: %v", err)
		os.Exit(1)
	}

	var tsOpts []tokencache.TokenSourceOpt
	if baseFlags.Offline {
		tsOpts = append(tsOpts, tokencache.WithRefreshClient(client))
	}

	ts := tokencache.TokenSource(clis, baseFlags.Issuer, baseFlags.ClientID, tsOpts...)

	if err := execFn(ctx, ts); err != nil {
		fmt.Printf("error: %+v", err)
		os.Exit(1)
	}
}

func printFullUsage(baseFs *flag.FlagSet, subcommands []*subCommand) {
	fmt.Printf("Usage: %s <base flags> <subcommand> <subcommand flags>\n", os.Args[0])
	fmt.Print("\n")
	fmt.Print("Base Flags:\n")
	fmt.Print("\n")
	baseFs.PrintDefaults()
	fmt.Print("\n")
	fmt.Print("Subcommands:\n")
	fmt.Print("\n")
	for _, sc := range subcommands {
		fmt.Printf("%s\n", sc.Flags.Name())
		fmt.Print("\n")
		fmt.Printf("  %s\n", sc.Description)
		fmt.Print("\n")
		sc.Flags.PrintDefaults()
		fmt.Print("\n")
	}
}

func raw(ctx context.Context, ts oidc.TokenSource, _ rawOpts) error {
	tok, err := ts.Token(ctx)
	if err != nil {
		return fmt.Errorf("fetching token: %v", err)
	}
	fmt.Print(tok.IDToken)
	return nil
}

// https://kubernetes.io/docs/reference/access-authn-authz/authentication/#client-go-credential-plugins

type kubeToken struct {
	Token               string     `json:"token,omitempty"`
	ExpirationTimestamp *time.Time `json:"expirationTimestamp,omitempty"`
}

const (
	apiVersion   = "client.authentication.k8s.io/v1beta1"
	execCredKind = "ExecCredential"
)

type kubeExecCred struct {
	APIVersion string    `json:"apiVersion,omitempty"`
	Kind       string    `json:"kind,omitempty"`
	Status     kubeToken `json:"status"`
}

func kubernetes(ctx context.Context, ts oidc.TokenSource, _ kubeOpts) error {
	tok, err := ts.Token(ctx)
	if err != nil {
		return fmt.Errorf("fetching token: %v", err)
	}
	creds := kubeExecCred{
		APIVersion: apiVersion,
		Kind:       execCredKind,
		Status: kubeToken{
			Token:               tok.IDToken,
			ExpirationTimestamp: &tok.Expiry,
		},
	}
	return json.NewEncoder(os.Stdout).Encode(&creds)
}

func info(ctx context.Context, ts oidc.TokenSource, _ infoOpts) error {
	tok, err := ts.Token(ctx)
	if err != nil {
		return fmt.Errorf("fetching token: %v", err)
	}

	fmt.Printf("Access Token: %s\n", tok.AccessToken)
	fmt.Printf("Refresh Token: %s\n", tok.RefreshToken)
	fmt.Printf("Access Token expires: %s\n", tok.Expiry.String())
	fmt.Printf("ID token: %s\n", tok.IDToken)
	fmt.Printf("Claims expires: %s\n", tok.Claims.Expiry.Time().String())
	fmt.Printf("Claims: %v\n", tok.Claims)

	return nil
}
