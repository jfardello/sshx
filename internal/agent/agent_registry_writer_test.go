package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/jfardello/sshx/internal/fileupdate"
	"golang.org/x/sys/unix"
)

func writerJSON(t *testing.T, version int, records ...RegistryRecord) []byte {
	t.Helper()
	data, err := json.Marshal(agentRegistryDocument{Version: version, Keys: records})
	if err != nil {
		t.Fatal(err)
	}
	return data
}
func writerPut(t *testing.T, name string, data []byte) {
	t.Helper()
	if err := os.WriteFile(name, data, 0600); err != nil {
		t.Fatal(err)
	}
}
func writerRead(t *testing.T, name string) []byte {
	t.Helper()
	data, err := os.ReadFile(name)
	if err != nil {
		t.Fatal(err)
	}
	return data
}
func writerResult(t *testing.T, got fileupdate.Publication, err error, want fileupdate.Publication, wantErr error) {
	t.Helper()
	if got != want || !errors.Is(err, wantErr) {
		t.Fatalf("publication/error = %v/%v, want %v/%v", got, err, want, wantErr)
	}
}
func writerUnchanged(t *testing.T, name string, before os.FileInfo, data []byte) {
	t.Helper()
	after, err := os.Stat(name)
	if err != nil {
		t.Fatal(err)
	}
	if !os.SameFile(before, after) || !before.ModTime().Equal(after.ModTime()) || !bytes.Equal(data, writerRead(t, name)) {
		t.Fatal("rejected operation or no-op rewrote original bytes/inode/mtime")
	}
}

func TestAgentRegistryWriterPath(t *testing.T) {
	base := agentTestDirectory(t)
	t.Setenv("XDG_CONFIG_HOME", base)
	name, err := RegistryPath()
	if err != nil || name != filepath.Join(base, "sshx", "agent.json") {
		t.Fatalf("path = %q, %v", name, err)
	}
	if _, err := os.Stat(filepath.Dir(name)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("path lookup created directory: %v", err)
	}
	t.Setenv("XDG_CONFIG_HOME", "relative")
	t.Setenv("HOME", base)
	name, err = RegistryPath()
	if err != nil || name != filepath.Join(base, ".config", "sshx", "agent.json") {
		t.Fatalf("fallback = %q, %v", name, err)
	}
}

func TestAgentRegistryWriterSourcePreservation(t *testing.T) {
	first, _ := testAgentKey(t)
	alias := first
	alias.ID = "alias"
	alias.Comment = "alias label"
	disabled, _ := testAgentKey(t)
	disabled.ID = "disabled"
	disabled.Enabled = false
	disabled.Backend = credentialBackendSecretService
	disabled.Reference = "item"
	disabled.Collection = "collection"
	original := []RegistryRecord{first, alias, disabled}
	data := writerJSON(t, 1, original...)
	doc, err := parseRegistryDocument(data)
	if err != nil || !reflect.DeepEqual(doc.Keys, original) {
		t.Fatalf("source aliases lost: %+v, %v", doc, err)
	}
	runtime, err := parseAgentRegistry(data)
	if err != nil || len(runtime.keys) != 2 {
		t.Fatalf("runtime aliases: %+v, %v", runtime, err)
	}
	name := filepath.Join(agentTestDirectory(t), "agent.json")
	writerPut(t, name, data)
	added, _ := testAgentKey(t)
	added.ID = "appended"
	pub, err := UpsertRegistryRecord(context.Background(), name, added, false)
	writerResult(t, pub, err, fileupdate.Published, nil)
	next, err := parseRegistryDocument(writerRead(t, name))
	if err != nil || next.Version != 2 || !reflect.DeepEqual(next.Keys, append(append([]RegistryRecord{}, original...), added)) {
		t.Fatalf("upgrade/source preservation: %+v, %v", next, err)
	}
	lock, err := os.Stat(name + ".lock")
	if err != nil {
		t.Fatal(err)
	}
	alias.Comment = "replaced alias only"
	pub, err = UpsertRegistryRecord(context.Background(), name, alias, true)
	writerResult(t, pub, err, fileupdate.Published, nil)
	next, err = parseRegistryDocument(writerRead(t, name))
	want := []RegistryRecord{first, alias, disabled, added}
	if err != nil || !reflect.DeepEqual(next.Keys, want) {
		t.Fatalf("replacement changed other IDs/order: %+v, %v", next, err)
	}
	after, err := os.Stat(name + ".lock")
	if err != nil {
		t.Fatal(err)
	}
	if !os.SameFile(lock, after) {
		t.Fatal("publication replaced stable lock")
	}
	info, err := os.Stat(name)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0600 {
		t.Fatalf("published mode = %o", info.Mode().Perm())
	}
}

func TestAgentRegistryWriterSemanticNoops(t *testing.T) {
	record, _ := testAgentKey(t)
	record.Enabled = false
	for _, version := range []int{1, 2} {
		for _, explicit := range []bool{false, true} {
			t.Run(fmt.Sprintf("v%d/explicit-%t", version, explicit), func(t *testing.T) {
				data := writerJSON(t, version, record)
				data = bytes.ReplaceAll(data, []byte(`,"enabled":false`), nil)
				if explicit {
					data = bytes.Replace(data, []byte(`"id":`), []byte(`"confirm":false,"comment":"","collection":"","id":`), 1)
				}
				var spaced bytes.Buffer
				if err := json.Indent(&spaced, data, "", "\t"); err != nil {
					t.Fatal(err)
				}
				data = append([]byte(" \n"), spaced.Bytes()...)
				data = append(data, '\n', ' ')
				name := filepath.Join(agentTestDirectory(t), "agent.json")
				writerPut(t, name, data)
				before, err := os.Stat(name)
				if err != nil {
					t.Fatal(err)
				}
				for _, replace := range []bool{false, true} {
					pub, err := UpsertRegistryRecord(context.Background(), name, record, replace)
					writerResult(t, pub, err, fileupdate.Unchanged, nil)
					writerUnchanged(t, name, before, data)
				}
			})
		}
	}
}

func TestAgentRegistryWriterEmptyOriginHostKeysNoop(t *testing.T) {
	record, _ := testAgentKey(t)
	host, _ := testAgentKey(t)
	record.Policy = "destination-constrained"
	record.Destinations = &DestinationPolicy{Version: 1, Edges: []DestinationEdge{
		{To: DestinationHop{Hostname: "destination", HostKeys: []string{host.PublicKey}}},
	}}
	for _, withAlias := range []bool{false, true} {
		t.Run(fmt.Sprintf("aliases-%t", withAlias), func(t *testing.T) {
			records := []RegistryRecord{record}
			if withAlias {
				alias := record
				alias.ID = "equivalent-alias"
				alias.Comment = "alias label"
				records = append(records, alias)
			}
			// All source aliases must have the same explicit empty slice: the
			// runtime alias validator still distinguishes nil from nonnil slices.
			data := writerJSON(t, 2, records...)
			if bytes.Count(data, []byte(`"from":{}`)) != len(records) {
				t.Fatal("fixture did not omit origin host_keys")
			}
			data = bytes.ReplaceAll(data, []byte(`"from":{}`), []byte(`"from":{"host_keys":[]}`))
			doc, err := parseRegistryDocument(data)
			if err != nil {
				t.Fatalf("explicit-empty source must remain valid: %v", err)
			}
			for _, source := range doc.Keys {
				pins := source.Destinations.Edges[0].From.HostKeys
				if pins == nil || len(pins) != 0 {
					t.Fatal("fixture did not decode explicit host_keys as a nonnil empty slice")
				}
			}
			name := filepath.Join(agentTestDirectory(t), "agent.json")
			writerPut(t, name, data)
			before, err := os.Stat(name)
			if err != nil {
				t.Fatal(err)
			}
			for _, proposal := range records {
				if proposal.Destinations.Edges[0].From.HostKeys != nil {
					t.Fatal("proposal must omit origin host_keys")
				}
				for _, replace := range []bool{false, true} {
					pub, err := UpsertRegistryRecord(context.Background(), name, proposal, replace)
					writerResult(t, pub, err, fileupdate.Unchanged, nil)
					writerUnchanged(t, name, before, data)
				}
			}
		})
	}
}

func TestAgentRegistryWriterRejectsInvalidOriginal(t *testing.T) {
	record, _ := testAgentKey(t)
	alias := record
	alias.ID = "alias"
	alias.Reference = "conflicting/reference"
	invalid := map[string][]byte{
		"empty": {}, "null": []byte("null"), "array": []byte("[]"),
		"unknown":         []byte(`{"version":1,"keys":[],"extra":true}`),
		"duplicate-field": []byte(`{"version":1,"version":2,"keys":[]}`),
		"trailing":        append(writerJSON(t, 1, record), []byte(` {}`)...),
		"version":         writerJSON(t, 3, record), "duplicate-id": writerJSON(t, 1, record, record),
		"alias-conflict": writerJSON(t, 1, record, alias),
	}
	for label, data := range invalid {
		t.Run(label, func(t *testing.T) {
			if _, err := parseRegistryDocument(data); !errors.Is(err, ErrRegistryInvalid) {
				t.Fatalf("parser error = %v", err)
			}
			name := filepath.Join(agentTestDirectory(t), "agent.json")
			writerPut(t, name, data)
			before, err := os.Stat(name)
			if err != nil {
				t.Fatal(err)
			}
			for _, replace := range []bool{false, true} {
				pub, err := UpsertRegistryRecord(context.Background(), name, record, replace)
				writerResult(t, pub, err, fileupdate.Unchanged, ErrRegistryInvalid)
				writerUnchanged(t, name, before, data)
			}
		})
	}
	badDoc := agentRegistryDocument{Version: 1, Keys: []RegistryRecord{record, alias}}
	if _, changed, err := upsertRegistryRecord(badDoc, record, true); changed || !errors.Is(err, ErrRegistryInvalid) {
		t.Fatalf("direct upsert accepted invalid original: %t, %v", changed, err)
	}
}

func TestAgentRegistryWriterProposalAndAliasConflicts(t *testing.T) {
	record, _ := testAgentKey(t)
	alias := record
	alias.ID = "alias"
	for _, mode := range []string{"replace-required", "invalid-id", "invalid-public", "invalid-backend", "invalid-policy", "alias-reference", "alias-enabled", "alias-confirm", "alias-replace"} {
		t.Run(mode, func(t *testing.T) {
			data := writerJSON(t, 2, record, alias)
			name := filepath.Join(agentTestDirectory(t), "agent.json")
			writerPut(t, name, data)
			before, err := os.Stat(name)
			if err != nil {
				t.Fatal(err)
			}
			proposal := record
			proposal.ID = "new-alias"
			replace := false
			wantErr := ErrRegistryInvalid
			switch mode {
			case "replace-required":
				proposal = record
				proposal.Comment = "changed"
				wantErr = ErrRegistryReplaceRequired
			case "invalid-id":
				proposal.ID = "../bad"
			case "invalid-public":
				proposal.PublicKey += " comment"
			case "invalid-backend":
				proposal.Backend = "unsupported"
			case "invalid-policy":
				proposal.Policy = "unsupported"
			case "alias-reference":
				proposal.Reference = "other/key"
			case "alias-enabled":
				proposal.Enabled = false
			case "alias-confirm":
				proposal.Confirm = true
			case "alias-replace":
				proposal = alias
				proposal.Reference = "other/key"
				replace = true
			}
			pub, err := UpsertRegistryRecord(context.Background(), name, proposal, replace)
			writerResult(t, pub, err, fileupdate.Unchanged, wantErr)
			writerUnchanged(t, name, before, data)
			doc, err := parseRegistryDocument(data)
			if err != nil {
				t.Fatal(err)
			}
			original := append([]RegistryRecord{}, doc.Keys...)
			_, changed, err := upsertRegistryRecord(doc, proposal, replace)
			if changed || !errors.Is(err, wantErr) || !reflect.DeepEqual(doc.Keys, original) {
				t.Fatalf("direct rejection mutated caller: %t, %v", changed, err)
			}
		})
	}
}

func TestAgentRegistryWriterDestinationOrder(t *testing.T) {
	record, _ := testAgentKey(t)
	host, _ := testAgentKey(t)
	record.Policy = "destination-constrained"
	record.Destinations = &DestinationPolicy{Version: 1, Edges: []DestinationEdge{
		{To: DestinationHop{Hostname: "one", HostKeys: []string{host.PublicKey}}},
		{To: DestinationHop{Hostname: "two", HostKeys: []string{host.PublicKey}}},
	}}
	name := filepath.Join(agentTestDirectory(t), "agent.json")
	data := writerJSON(t, 2, record)
	writerPut(t, name, data)
	before, err := os.Stat(name)
	if err != nil {
		t.Fatal(err)
	}
	reordered := record
	reordered.Destinations = &DestinationPolicy{Version: 1, Edges: []DestinationEdge{record.Destinations.Edges[1], record.Destinations.Edges[0]}}
	pub, err := UpsertRegistryRecord(context.Background(), name, reordered, false)
	writerResult(t, pub, err, fileupdate.Unchanged, ErrRegistryReplaceRequired)
	writerUnchanged(t, name, before, data)
	alias := reordered
	alias.ID = "alias"
	pub, err = UpsertRegistryRecord(context.Background(), name, alias, false)
	writerResult(t, pub, err, fileupdate.Unchanged, ErrRegistryInvalid)
	writerUnchanged(t, name, before, data)
	doc, err := parseRegistryDocument(data)
	if err != nil {
		t.Fatal(err)
	}
	next, changed, err := upsertRegistryRecord(doc, reordered, true)
	if err != nil || !changed || !reflect.DeepEqual(doc.Keys[0], record) || !reflect.DeepEqual(next.Keys[0], reordered) {
		t.Fatalf("structural replacement/caller ownership: %t, %v", changed, err)
	}
	pub, err = UpsertRegistryRecord(context.Background(), name, reordered, true)
	writerResult(t, pub, err, fileupdate.Published, nil)
}

func TestAgentRegistryWriterMissingAndBounds(t *testing.T) {
	record, _ := testAgentKey(t)
	t.Run("missing", func(t *testing.T) {
		name := filepath.Join(agentTestDirectory(t), "nested", "agent.json")
		pub, err := UpsertRegistryRecord(context.Background(), name, record, false)
		writerResult(t, pub, err, fileupdate.Published, nil)
		doc, err := parseRegistryDocument(writerRead(t, name))
		if err != nil || doc.Version != 2 || !reflect.DeepEqual(doc.Keys, []RegistryRecord{record}) {
			t.Fatalf("created document: %+v, %v", doc, err)
		}
	})
	t.Run("oversized-input", func(t *testing.T) {
		name := filepath.Join(agentTestDirectory(t), "agent.json")
		data := append(writerJSON(t, 1, record), bytes.Repeat([]byte(" "), maxAgentRegistryBytes)...)
		writerPut(t, name, data)
		before, err := os.Stat(name)
		if err != nil {
			t.Fatal(err)
		}
		pub, err := UpsertRegistryRecord(context.Background(), name, record, false)
		writerResult(t, pub, err, fileupdate.Unchanged, fileupdate.ErrInvalid)
		writerUnchanged(t, name, before, data)
	})
	t.Run("oversized-output", func(t *testing.T) {
		records := make([]RegistryRecord, 8192)
		for i := range records {
			records[i] = record
			records[i].ID = fmt.Sprintf("alias-%d", i)
			records[i].Comment = strings.Repeat("x", 128)
		}
		// Find the largest source whose indented publication fits, without
		// repeatedly serializing every growing prefix of a megabyte fixture.
		low, high := 0, len(records)
		for low+1 < high {
			mid := (low + high) / 2
			pretty, err := json.MarshalIndent(agentRegistryDocument{Version: 2, Keys: records[:mid]}, "", "  ")
			if err != nil {
				t.Fatal(err)
			}
			if len(pretty)+1 <= maxAgentRegistryBytes {
				low = mid
			} else {
				high = mid
			}
		}
		records = records[:low]
		data := writerJSON(t, 2, records...)
		if len(data) > maxAgentRegistryBytes {
			t.Fatal("fixture input exceeds limit")
		}
		name := filepath.Join(agentTestDirectory(t), "agent.json")
		writerPut(t, name, data)
		before, err := os.Stat(name)
		if err != nil {
			t.Fatal(err)
		}
		proposal := record
		proposal.ID = "overflow"
		proposal.Comment = strings.Repeat("x", 128)
		pub, err := UpsertRegistryRecord(context.Background(), name, proposal, false)
		writerResult(t, pub, err, fileupdate.Unchanged, ErrRegistryInvalid)
		writerUnchanged(t, name, before, data)
	})
}

func TestAgentRegistryWriterFilesystemSecurity(t *testing.T) {
	record, _ := testAgentKey(t)
	for _, mode := range []string{"busy", "cancel", "directory", "fifo", "hardlink", "symlink", "ancestor-symlink", "permissions", "parent-permissions", "lock-symlink", "lock-hardlink", "lock-permissions", "owner"} {
		t.Run(mode, func(t *testing.T) {
			dir := agentTestDirectory(t)
			name := filepath.Join(dir, "agent.json")
			data := writerJSON(t, 1, record)
			writerPut(t, name, data)
			original := name
			before, err := os.Stat(original)
			if err != nil {
				t.Fatal(err)
			}
			ctx := context.Background()
			want := fileupdate.ErrInvalid
			switch mode {
			case "busy":
				lock, err := os.OpenFile(name+".lock", os.O_CREATE|os.O_RDWR, 0600)
				if err != nil {
					t.Fatal(err)
				}
				defer lock.Close()
				if err := unix.Flock(int(lock.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
					t.Fatal(err)
				}
				want = fileupdate.ErrBusy
			case "cancel":
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
				want = context.Canceled
			case "directory", "fifo":
				name += ".bad"
				if mode == "directory" {
					err = os.Mkdir(name, 0700)
				} else {
					err = unix.Mkfifo(name, 0600)
				}
				if err != nil {
					t.Fatal(err)
				}
			case "hardlink":
				if err := os.Link(name, name+".other"); err != nil {
					t.Fatal(err)
				}
			case "symlink":
				name += ".link"
				if err := os.Symlink(original, name); err != nil {
					t.Fatal(err)
				}
			case "ancestor-symlink":
				link := filepath.Join(dir, "link")
				if err := os.Symlink(dir, link); err != nil {
					t.Fatal(err)
				}
				name = filepath.Join(link, "agent.json")
			case "permissions":
				if err := os.Chmod(name, 0644); err != nil {
					t.Fatal(err)
				}
			case "parent-permissions":
				if err := os.Chmod(dir, 0770); err != nil {
					t.Fatal(err)
				}
			case "lock-symlink":
				if err := os.Symlink(name, name+".lock"); err != nil {
					t.Fatal(err)
				}
			case "lock-hardlink":
				if err := os.Link(name, name+".lock"); err != nil {
					t.Fatal(err)
				}
			case "lock-permissions":
				writerPut(t, name+".lock", nil)
				if err := os.Chmod(name+".lock", 0644); err != nil {
					t.Fatal(err)
				}
			case "owner":
				if os.Geteuid() != 0 {
					t.Skip("changing ownership requires root")
				}
				if err := os.Chown(name, 1, -1); err != nil {
					t.Fatal(err)
				}
			}
			proposal := record
			proposal.Comment = "mutation"
			pub, err := UpsertRegistryRecord(ctx, name, proposal, true)
			writerResult(t, pub, err, fileupdate.Unchanged, want)
			writerUnchanged(t, original, before, data)
		})
	}
}
