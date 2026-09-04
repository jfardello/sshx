package main

import (
	"fmt"
	"net/url"
	"path"
	"strings"
	"unicode"
)

type credentialCandidate struct {
	credential credentialRef
	err        error
}

func prepareCredentialCandidates(query string, credentials []credentialRef) []credentialCandidate {
	candidates := make([]credentialCandidate, 0, len(credentials))
	for _, credential := range credentials {
		target, err := credentialTarget(credential, query)
		if err == nil {
			credential.Target = target
		}
		candidates = append(candidates, credentialCandidate{credential: credential, err: err})
	}
	return candidates
}

func matchCredentials(query string, credentials []credentialRef) ([]credentialRef, error) {
	return matchCredentialCandidates(query, prepareCredentialCandidates(query, credentials), true)
}

func credentialsForListing(query string, credentials []credentialRef) []credentialRef {
	candidates := prepareCredentialCandidates(query, credentials)
	if query == "" {
		result := make([]credentialRef, 0, len(candidates))
		for _, candidate := range candidates {
			result = append(result, candidate.credential)
		}
		return result
	}

	result, _ := matchCredentialCandidates(query, candidates, false)
	return result
}

func matchCredentialCandidates(
	query string,
	candidates []credentialCandidate,
	rejectInvalidTarget bool,
) ([]credentialRef, error) {
	stages := []func(credentialRef) bool{
		func(credential credentialRef) bool {
			return credential.Attributes != nil && credential.Attributes["sshx.target"] == query
		},
		func(credential credentialRef) bool { return credential.Label == query },
		func(credential credentialRef) bool { return credentialIdentity(credential) == query },
		func(credential credentialRef) bool {
			lowerQuery := strings.ToLower(query)
			return strings.Contains(strings.ToLower(credential.Target), lowerQuery) ||
				strings.Contains(strings.ToLower(credential.Label), lowerQuery)
		},
	}

	for _, matches := range stages {
		matched := make([]credentialRef, 0)
		for _, candidate := range candidates {
			if !matches(candidate.credential) {
				continue
			}
			if candidate.err != nil && rejectInvalidTarget {
				return nil, candidate.err
			}
			matched = append(matched, candidate.credential)
		}
		if len(matched) > 0 {
			return matched, nil
		}
	}
	return nil, nil
}

func credentialTarget(credential credentialRef, query string) (string, error) {
	if credential.Backend == credentialBackendGopass {
		target := credential.Target
		if target == "" {
			target = query
		}
		if target == "" {
			target = credential.Label
		}
		if target == "" {
			target = path.Base(credential.ID)
		}
		return validateCredentialTarget(target, "gopass credential target")
	}
	if credential.Backend != credentialBackendSecretService {
		return "", fmt.Errorf("unsupported credential backend %q", credential.Backend)
	}

	if target, ok := credential.Attributes["sshx.target"]; ok {
		return validateCredentialTarget(target, "Secret Service sshx.target attribute")
	}
	if rawURL, ok := credential.Attributes["URL"]; ok {
		parsed, err := url.Parse(rawURL)
		if err != nil {
			return "", fmt.Errorf("invalid Secret Service SSH URL for %q: %w", credentialIdentity(credential), err)
		}
		if strings.EqualFold(parsed.Scheme, "ssh") {
			host := parsed.Hostname()
			if host == "" {
				return "", fmt.Errorf("invalid Secret Service SSH URL for %q: host is empty", credentialIdentity(credential))
			}
			if strings.Contains(host, ":") {
				host = "[" + host + "]"
			}
			username := ""
			if parsed.User != nil {
				username = parsed.User.Username()
			}
			if username == "" {
				username = credential.Attributes["UserName"]
			}
			if username != "" {
				host = username + "@" + host
			}
			return validateCredentialTarget(host, "Secret Service SSH URL target")
		}
	}
	return validateCredentialTarget(credential.Label, "Secret Service credential label")
}

func validateCredentialTarget(target, source string) (string, error) {
	if target == "" {
		return "", fmt.Errorf("%s cannot be empty", source)
	}
	if strings.HasPrefix(target, "-") {
		return "", fmt.Errorf("%s %q cannot begin with '-'", source, target)
	}
	if strings.IndexFunc(target, func(value rune) bool {
		return unicode.IsSpace(value) || unicode.IsControl(value)
	}) >= 0 {
		return "", fmt.Errorf("%s %q must not contain whitespace or control characters", source, target)
	}
	return target, nil
}

func credentialIdentity(credential credentialRef) string {
	if credential.Backend == credentialBackendSecretService {
		if credential.Collection != "" && credential.Label != "" {
			return credential.Collection + "/" + credential.Label
		}
		if credential.Label != "" {
			return credential.Label
		}
	}
	return credential.ID
}
