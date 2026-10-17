package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"

	"github.com/jfardello/sshx/internal/fileupdate"
)

// RegistryRecord contains public metadata only. Private material must be fully
// validated against PublicKey before calling UpsertRegistryRecord.
// These aliases are internal sshx boundaries, not the future public age API.
type RegistryRecord = agentKeyRecord
type DestinationPolicy = agentDestinationPolicy
type DestinationEdge = agentDestinationEdge
type DestinationHop = agentDestinationHop

var (
	ErrRegistryInvalid         = errAgentRegistry
	ErrRegistryReplaceRequired = errors.New("registry ID already exists with different fields; explicit replacement is required")
)

// RegistryPath locates the public registry without reading or creating it.
func RegistryPath() (string, error) { return agentRegistryPath() }

// parseRegistryDocument retains every validated source record, including aliases.
// The deduplicated runtime registry must never be serialized as the source document.
func parseRegistryDocument(data []byte) (agentRegistryDocument, error) {
	if _, err := parseAgentRegistry(data); err != nil {
		return agentRegistryDocument{}, err
	}
	var doc agentRegistryDocument
	if err := json.Unmarshal(data, &doc); err != nil {
		return agentRegistryDocument{}, errAgentRegistry
	}
	return doc, nil
}

func validateRegistryDocument(doc agentRegistryDocument) error {
	data, err := json.Marshal(doc)
	if err != nil {
		return errAgentRegistry
	}
	_, err = parseAgentRegistry(data)
	return err
}

// Compare decoded fields in canonical JSON form: omitted default scalars and
// empty optional slices agree, but edge and pin ordering remains significant.
// This comparison does not change the runtime validator's alias rules.
func sameRegistryRecord(a, b agentKeyRecord) bool {
	left, leftErr := json.Marshal(a)
	right, rightErr := json.Marshal(b)
	return leftErr == nil && rightErr == nil && bytes.Equal(left, right)
}

func upsertRegistryRecord(doc agentRegistryDocument, record agentKeyRecord, replace bool) (agentRegistryDocument, bool, error) {
	if err := validateRegistryDocument(doc); err != nil {
		return agentRegistryDocument{}, false, err
	}
	if err := validateRegistryDocument(agentRegistryDocument{Version: 2, Keys: []agentKeyRecord{record}}); err != nil {
		return agentRegistryDocument{}, false, err
	}
	index := -1
	for i, existing := range doc.Keys {
		if existing.ID == record.ID {
			if sameRegistryRecord(existing, record) {
				return doc, false, nil
			}
			if !replace {
				return agentRegistryDocument{}, false, ErrRegistryReplaceRequired
			}
			index = i
			break
		}
	}
	// Never mutate the caller's source slice. Destination graph ordering is part
	// of structural equality, as in the existing runtime alias validator.
	next := agentRegistryDocument{Version: 2, Keys: append([]agentKeyRecord{}, doc.Keys...)}
	if index < 0 {
		next.Keys = append(next.Keys, record)
	} else {
		next.Keys[index] = record
	}
	if err := validateRegistryDocument(next); err != nil {
		return agentRegistryDocument{}, false, err
	}
	return next, true, nil
}

// UpsertRegistryRecord adds one public record or explicitly replaces its ID.
// Provider calls, private-key validation, and prompts must finish before entry.
// An identical record is a no-op, including with replace=true. Conflicting
// aliases fail the complete transaction; unrelated records retain their order.
// A DurabilityUncertain result means replacement happened despite the error.
func UpsertRegistryRecord(ctx context.Context, name string, record RegistryRecord, replace bool) (fileupdate.Publication, error) {
	// Validate and clone caller-owned graph slices before holding the file lock.
	data, err := json.Marshal(agentRegistryDocument{Version: 2, Keys: []agentKeyRecord{record}})
	if err != nil {
		return fileupdate.Unchanged, errAgentRegistry
	}
	validated, err := parseRegistryDocument(data)
	if err != nil {
		return fileupdate.Unchanged, err
	}
	record = validated.Keys[0]
	var editErr error
	publication, err := fileupdate.Update(ctx, name, fileupdate.Policy{MaxBytes: maxAgentRegistryBytes, Private: true}, func(current []byte, exists bool) ([]byte, bool, error) {
		doc := agentRegistryDocument{Version: 2, Keys: []agentKeyRecord{}}
		if exists {
			doc, editErr = parseRegistryDocument(current)
			if editErr != nil {
				return nil, false, editErr
			}
		}
		var next agentRegistryDocument
		var changed bool
		next, changed, editErr = upsertRegistryRecord(doc, record, replace)
		if editErr != nil || !changed {
			return nil, false, editErr
		}
		output, marshalErr := json.MarshalIndent(next, "", "  ")
		if marshalErr != nil {
			editErr = errAgentRegistry
			return nil, false, editErr
		}
		output = append(output, '\n')
		if _, editErr = parseRegistryDocument(output); editErr != nil {
			return nil, false, editErr
		}
		return output, true, nil
	})
	// The filesystem layer deliberately sanitizes callback errors. Restore only
	// our known public-document errors, never raw JSON or provider diagnostics.
	if editErr != nil {
		return publication, editErr
	}
	return publication, err
}
