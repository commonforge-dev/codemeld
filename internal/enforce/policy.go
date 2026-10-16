package enforce

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"unicode/utf8"
)

const (
	HelperCommand          = "__codemeld_confine"
	ProbeArg               = "--probe"
	ControlArg             = "--control"
	SetupFailureExitCode   = 125
	ModePlan               = "plan"
	ModeAutoEdits          = "auto_edits"
	NetworkAccessAuthority = "network access"
	MaxPolicyFrameBytes    = 64 * 1024
)

type Policy struct {
	Mode                 string   `json:"mode"`
	ExceptionalAuthority string   `json:"exceptional_authority"`
	BlockedPaths         []string `json:"blocked_paths"`
	WriteRoots           []string `json:"write_roots"`
	NoWritePaths         []string `json:"no_write_paths"`
	TmpDir               string   `json:"tmp_dir"`
}

var errPolicyFrameTooLarge = fmt.Errorf("policy frame exceeds %d bytes", MaxPolicyFrameBytes)

func WritePolicyFrame(w io.Writer, p Policy) error {
	if err := p.validate(); err != nil {
		return err
	}
	payload, err := json.Marshal(p)
	if err != nil {
		return err
	}
	if len(payload) > MaxPolicyFrameBytes {
		return errPolicyFrameTooLarge
	}
	frame := make([]byte, 4, 4+len(payload))
	binary.BigEndian.PutUint32(frame, uint32(len(payload)))
	_, err = w.Write(append(frame, payload...))
	return err
}

func ReadPolicyFrame(r io.Reader) (Policy, error) {
	var header [4]byte
	if _, err := io.ReadFull(r, header[:]); err != nil {
		return Policy{}, fmt.Errorf("read policy frame length: %w", err)
	}
	n := binary.BigEndian.Uint32(header[:])
	if n > MaxPolicyFrameBytes {
		return Policy{}, errPolicyFrameTooLarge
	}
	payload := make([]byte, n)
	if _, err := io.ReadFull(r, payload); err != nil {
		return Policy{}, fmt.Errorf("read policy frame payload: %w", err)
	}
	dec := json.NewDecoder(bytes.NewReader(payload))
	dec.DisallowUnknownFields()
	var p Policy
	if err := dec.Decode(&p); err != nil {
		return Policy{}, fmt.Errorf("decode policy frame: %w", err)
	}
	if err := dec.Decode(&json.RawMessage{}); !errors.Is(err, io.EOF) {
		return Policy{}, errors.New("decode policy frame: trailing data after policy")
	}
	if err := p.validate(); err != nil {
		return Policy{}, err
	}
	return p, nil
}

func (p Policy) validate() error {
	switch p.Mode {
	case ModePlan:
		if p.TmpDir != "" || len(p.WriteRoots) > 0 || len(p.NoWritePaths) > 0 || p.ExceptionalAuthority != "" {
			return errors.New("policy: plan mode carries no tmp_dir, write_roots, no_write_paths or exceptional_authority")
		}
	case ModeAutoEdits:
		if p.TmpDir == "" {
			return errors.New("policy: auto_edits requires tmp_dir")
		}
		if p.ExceptionalAuthority != "" && p.ExceptionalAuthority != NetworkAccessAuthority {
			return fmt.Errorf("policy: unknown exceptional_authority %q", p.ExceptionalAuthority)
		}
	default:
		return fmt.Errorf("policy: unknown mode %q", p.Mode)
	}
	if len(p.BlockedPaths) == 0 {
		return errors.New("policy: blocked_paths is empty")
	}
	for _, list := range [][]string{p.BlockedPaths, p.WriteRoots, p.NoWritePaths} {
		for _, path := range list {
			if err := checkPolicyPath(path); err != nil {
				return err
			}
		}
	}
	if p.TmpDir != "" {
		return checkPolicyPath(p.TmpDir)
	}
	return nil
}

func checkPolicyPath(path string) error {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return fmt.Errorf("policy: path %q is not absolute and clean", path)
	}
	if !utf8.ValidString(path) {
		return fmt.Errorf("policy: path %q is not valid UTF-8", path)
	}
	return nil
}
