// Operation-neutral prepared-child activation lifecycle: creates a child session
// from the active parent and transitions the running app onto it.
package bootstrap

import (
	"context"
	"fmt"
	"strings"

	"codemeld.dev/codemeld/internal/enforce"
	"codemeld.dev/codemeld/internal/fserrors"
	"codemeld.dev/codemeld/internal/sessionfork"
	"codemeld.dev/codemeld/internal/sessions"
	"codemeld.dev/codemeld/internal/tui"
)

type preparedChildLifecycle struct {
	ctx      context.Context
	home     string
	app      *tui.App
	holder   *resumeLockHolder
	banner   func() []string
	recorder *capabilityRecorder
	conf     *confinement
}

type preparedChild struct {
	store      *sessions.Store
	release    func()
	tmpDir     string
	rollback   func() error
	capability enforce.Resolution
}

func (p preparedChild) discard() error {
	err := p.rollback()
	p.release()
	return err
}

func (l preparedChildLifecycle) Prepare(parent *sessions.Store, title string, childRecords, terminalParentRecords []sessions.Record, notices tui.NoticeRenderer) (preparedChild, error) {
	if parent == nil {
		return preparedChild{}, fmt.Errorf("no parent session to create a child from")
	}
	if parent != l.app.ActiveStore() {
		return preparedChild{}, fmt.Errorf("parent session %s is not the active session", parent.SessionID())
	}
	var initialWriteDetail error
	onWriteFailure := func(path string, cat fserrors.Category, reason sessions.WriteReason, err error) {
		initialWriteDetail = fmt.Errorf("child session %s was not written (category %s, reason %s): %w", path, cat, reason, err)
	}
	var tmpDir string
	var rollback func() error
	var capability enforce.Resolution
	postLaunch := func(child *sessions.Store) (func() error, error) {
		folder, undo, err := l.conf.prepareReplacement()
		rollback = undo
		if err != nil {
			return undo, err
		}
		tmpDir = folder
		capability = l.recorder.current()
		return undo, recordExecutionCapability(l.ctx, child, capability, notices)
	}
	owned, err := sessionfork.CreateOwnedChild(l.ctx, l.home, parent.MetadataSnapshot(), parent,
		sessionfork.Child{Title: title, Records: childRecords}, terminalParentRecords, postLaunch, onWriteFailure)
	if err != nil {
		if initialWriteDetail != nil {
			return preparedChild{}, initialWriteDetail
		}
		return preparedChild{}, err
	}
	return preparedChild{store: owned.Store, release: owned.Release, tmpDir: tmpDir, rollback: rollback, capability: capability}, nil
}

func (l preparedChildLifecycle) Activate(prepared preparedChild) string {
	warnings := l.recorder.reconcile(l.ctx, l.app, prepared.store, prepared.capability)
	l.conf.commitReplacement(prepared.tmpDir)
	if l.holder != nil {
		if source := l.holder.handoff(prepared.release); source != nil {
			source()
		}
	} else {
		prepared.release()
	}
	l.app.ResetTranscript()
	l.app.AppendBanner(l.banner()...)
	l.app.ReplaySessionRecords(prepared.store.Records())
	if warning := l.conf.takeCleanupWarning(); warning != "" {
		warnings = append(heldNotices{warning}, warnings...)
	}
	return strings.Join(warnings, "; ")
}

func (l preparedChildLifecycle) CreateAndActivate(parent *sessions.Store, title string, records, terminalParentRecords []sessions.Record) (string, error) {
	prepared, err := l.Prepare(parent, title, records, terminalParentRecords, l.app)
	if err != nil {
		return "", err
	}
	return l.Activate(prepared), nil
}
