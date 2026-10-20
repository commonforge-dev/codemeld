package config

import (
	"bytes"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/goccy/go-yaml"
	"github.com/goccy/go-yaml/ast"
	"github.com/goccy/go-yaml/lexer"
	"github.com/goccy/go-yaml/parser"
	"github.com/goccy/go-yaml/token"

	"codemeld.dev/codemeld/internal/fserrors"
	"codemeld.dev/codemeld/internal/fsutil"
	"codemeld.dev/codemeld/internal/permissions"
	"codemeld.dev/codemeld/internal/provider"
)

// Codemeld-owned YAML keys per §Reserved Values "Codemeld-owned YAML keys".
const (
	KeyPermissions   = "permissions"
	KeyModelActive   = "model.active"
	KeyModelLastUsed = "model.last_used"
	// KeyAuthOpenAIChatGPT is the codemeld-owned, global-only ChatGPT session
	// state stored under auth.openai-chatgpt. Pass a yaml-marshalable mapping value
	// to set it, or the AuthDelete sentinel to remove it (logout).
	KeyAuthOpenAIChatGPT = "auth.openai-chatgpt"
	KeyAttribution       = "attribution"
	KeyRetentionDays     = "sessions.retention_days"
	keyModelFavorites    = "model.favorites"
)

const favoritesSub = "favorites"

// auth container/sub-key names for the nested auth.openai-chatgpt mapping.
const (
	authKey        = "auth"
	authChatGPTSub = "openai-chatgpt"
)

const KeyProviderPrefix = "provider."

const (
	KeyOpenRouterRoutingDataCollection = "provider.openrouter.routing.data_collection"
	KeyOpenRouterRoutingSort           = "provider.openrouter.routing.sort"
	KeyOpenRouterRoutingMaxPrice       = "provider.openrouter.routing.max_price"
)

const (
	openRouterProviderID = "openrouter"
	routingKey           = "routing"
	routingSortDefault   = "default"
	maxPriceKey          = "max_price"
)

type OpenRouterMaxPrice struct {
	Model string
	Price provider.MaxPrice
}

var errNoOpenRouterEntry = errors.New("config.RewriteKey: the settings file has no provider.openrouter entry")

// providerKey is the top-level container key holding the provider.<name> map.
const providerKey = "provider"

// ErrReservedProviderID is returned by RewriteKey/Persist when a caller tries to
// write provider.openai-chatgpt. That provider id is built-in and reserved; a
// user-defined provider.openai-chatgpt entry is rejected at load, and its session
// credentials are stored only under auth.openai-chatgpt. The writer refuses it
// regardless of caller so the credential-write path is fail-closed.
var ErrReservedProviderID = errors.New("provider.openai-chatgpt is reserved; its credentials are stored under auth.openai-chatgpt, not as a provider entry")

// authDeleteValue is the sentinel newValue type that RewriteKey/Persist treat as
// "delete auth.openai-chatgpt" rather than "set it", so logout deletes reuse the
// same sidecar lock and atomic-write path as writes.
type authDeleteValue struct{}

// AuthDelete is the newValue sentinel passed to Persist/RewriteKey with
// KeyAuthOpenAIChatGPT to delete the stored ChatGPT session instead of writing
// one. Deleting an absent session is a no-op success that creates no file.
var AuthDelete any = authDeleteValue{}

// permissionDeleteValue is the sentinel newValue type that RewriteKey/Persist
// treat as "remove the permission entry matching this DedupKey" under
// KeyPermissions rather than "append one", so a revoke reuses the same sidecar
// lock and atomic-write path as an append. Deleting an absent entry is
// a no-op success that writes nothing.
type permissionDeleteValue struct {
	key permissions.DedupKey
}

// PermissionDelete is the newValue passed to Persist/RewriteKey with
// KeyPermissions to remove the permission entry whose identity matches dedupKey,
// instead of appending one. Removing an entry that is absent — no file, no
// permissions: key, or no matching entry — is a no-op success that creates no
// file.
func PermissionDelete(dedupKey permissions.DedupKey) any {
	return permissionDeleteValue{key: dedupKey}
}

type PermissionDeleteOp struct {
	Key     permissions.DedupKey
	Removed bool
}

// modelActiveCommentBlock is the comment block inserted immediately
// above model.active when this writer creates that key or first inserts it
// into an existing file. Replacements of an existing key leave whatever
// leading comment is on disk untouched via byte-splice.
const modelActiveCommentBlock = "# This file holds this machine's own settings for this project; it is not shared with the team.\n" +
	"# model.active is rewritten whenever you pick a model in this project.\n" +
	"# Manual edits to this key will be overwritten the next time you pick a model here.\n"

// modelMapCommentBlock is the comment block written above the model:
// map when this writer creates a settings file from absence on a
// model.last_used path. The first-run global file already carries this comment
// per canonicalModelBlock in internal/bootstrap; this constant exists only for
// the create-from-absence path that the shared persistence function's
// create-file-if-absent rule covers.
const modelMapCommentBlock = "# model.last_used is managed automatically by codemeld.\n" +
	"# It records the most recent model and effort you picked in any project,\n" +
	"# and is used as the default for folders you have not yet used with codemeld.\n" +
	"# Manual edits to this key will be overwritten the next time you pick a model.\n"

// settingsFileMode matches the 0600 mode used elsewhere for
// settings.yaml so a settings file this helper creates from absence does not
// expose plaintext API keys.
const settingsFileMode os.FileMode = 0o600

// RewriteKey persists one codemeld-owned YAML key (KeyPermissions,
// KeyModelActive, KeyModelLastUsed, KeyAuthOpenAIChatGPT, KeyAttribution, or a
// KeyProviderPrefix+name provider entry) into the file at path, preserving every
// other top-level or nested key, comment, and adjacent whitespace byte-for-byte
// per step (3). newValue is a permissions.PermissionEntry for
// KeyPermissions, or any yaml.Marshal-able payload (typically yaml.MapSlice
// with provider/id/effort in that order) for the two model keys. For a
// KeyProviderPrefix+name key newValue is a yaml.Marshal-able provider.ProviderEntry
// shape, schema-validated before any write; writing provider.openai-chatgpt is
// refused (ErrReservedProviderID). Returns
// (zero, zero, nil) on success; fsutil.WriteAtomic's (step, cat, err)
// unchanged on atomic-write failure; or (fsutil.LoadStep, best-effort cat, err)
// for any pre-write failure with the on-disk file untouched.
func RewriteKey(path, key string, newValue any) (fsutil.AtomicWriteStep, fserrors.Category, error) {
	return rewriteKey(&settingsRewrite{path: path}, key, newValue)
}

func rewriteKeyAt(dir *os.File, path string, source fsutil.FileSnapshot, key string, newValue any) (fsutil.AtomicWriteStep, fserrors.Category, error) {
	return rewriteKey(&settingsRewrite{path: path, dir: dir, source: source.Data, exists: source.Exists, supplied: true}, key, newValue)
}

type settingsRewrite struct {
	path      string
	dir       *os.File
	source    []byte
	exists    bool
	supplied  bool
	published []byte
}

func (r *settingsRewrite) read() ([]byte, bool, fsutil.AtomicWriteStep, fserrors.Category, error) {
	if r.supplied {
		return r.source, r.exists, "", "", nil
	}
	return readOrAbsent(r.path)
}

func (r *settingsRewrite) publish(body []byte) (fsutil.AtomicWriteStep, fserrors.Category, error) {
	r.published = append([]byte{}, body...)
	if r.dir != nil {
		step, cat, _, err := fsutil.WriteAtomicReplaceAt(r.dir, filepath.Base(r.path), r.published, settingsFileMode, nil, nil)
		return step, cat, err
	}
	return fsutil.WriteAtomic(r.path, r.published, settingsFileMode)
}

func rewriteKey(r *settingsRewrite, key string, newValue any) (fsutil.AtomicWriteStep, fserrors.Category, error) {
	switch key {
	case KeyPermissions:
		switch v := newValue.(type) {
		case permissions.PermissionEntry:
			return rewritePermissions(r, v)
		case permissionDeleteValue:
			return removePermissionEntry(r, &PermissionDeleteOp{Key: v.key})
		case *PermissionDeleteOp:
			if v == nil {
				return fsutil.LoadStep, "", fmt.Errorf("config.RewriteKey: %q delete payload is nil", key)
			}
			return removePermissionEntry(r, v)
		default:
			return fsutil.LoadStep, "", fmt.Errorf("config.RewriteKey: %q requires a permissions.PermissionEntry or PermissionDelete payload, got %T", key, newValue)
		}
	case KeyModelActive:
		return rewriteModelSubkey(r, "active", newValue)
	case KeyModelLastUsed:
		return rewriteModelSubkey(r, "last_used", newValue)
	case keyModelFavorites:
		op, ok := newValue.(*favoriteToggleValue)
		if !ok {
			return fsutil.LoadStep, "", fmt.Errorf("config.RewriteKey: %q requires a prepared favorite toggle payload, got %T", key, newValue)
		}
		return rewriteModelFavorites(r, op)
	case KeyAuthOpenAIChatGPT:
		if _, isDelete := newValue.(authDeleteValue); isDelete {
			return deleteAuthChatGPT(r)
		}
		return setAuthChatGPT(r, newValue)
	case KeyAttribution:
		on, ok := newValue.(bool)
		if !ok {
			return fsutil.LoadStep, "", fmt.Errorf("config.RewriteKey: %q requires a bool payload, got %T", key, newValue)
		}
		return setAttribution(r, on)
	case KeyRetentionDays:
		days, ok := newValue.(int)
		if !ok || days < 1 {
			return fsutil.LoadStep, "", fmt.Errorf("config.RewriteKey: %q requires an int >= 1, got %T %v", key, newValue, newValue)
		}
		return setNestedScalar(r, "sessions", "retention_days", strconv.Itoa(days))
	case blockedPathsKey:
		return rewriteBlockedPaths(r, newValue)
	case KeyOpenRouterRoutingDataCollection, KeyOpenRouterRoutingSort:
		v, ok := newValue.(string)
		if !ok {
			return fsutil.LoadStep, "", fmt.Errorf("config.RewriteKey: %q requires a string payload, got %T", key, newValue)
		}
		return setOpenRouterRouting(r, key[strings.LastIndexByte(key, '.')+1:], v)
	case KeyOpenRouterRoutingMaxPrice:
		v, ok := newValue.(OpenRouterMaxPrice)
		if !ok || v.Model == "" {
			return fsutil.LoadStep, "", fmt.Errorf("config.RewriteKey: %q requires an OpenRouterMaxPrice payload with a model id, got %T", key, newValue)
		}
		return setOpenRouterMaxPrice(r, v.Model, v.Price)
	default:
		if name, ok := strings.CutPrefix(key, KeyProviderPrefix); ok && name != "" {
			return setProviderEntry(r, name, newValue)
		}
		return fsutil.LoadStep, "", fmt.Errorf("config.RewriteKey: key %q is not in §Reserved Values \"Codemeld-owned YAML keys\"", key)
	}
}

// readOrAbsent returns the file's bytes plus exists=false on ErrNotExist; all
// other read errors are surfaced as LoadStep with the categorized errno.
func readOrAbsent(path string) (data []byte, exists bool, step fsutil.AtomicWriteStep, cat fserrors.Category, err error) {
	b, rerr := os.ReadFile(path)
	if rerr != nil {
		if errors.Is(rerr, fs.ErrNotExist) {
			return nil, false, "", "", nil
		}
		return nil, false, fsutil.LoadStep, fserrors.CategorizeErrno(rerr), rerr
	}
	return b, true, "", "", nil
}

// rootValues returns the slice of top-level MappingValueNodes for the first
// document of doc. A null or empty body yields a nil slice with no error.
func rootValues(doc *ast.File) ([]*ast.MappingValueNode, error) {
	if doc == nil || len(doc.Docs) == 0 {
		return nil, nil
	}
	body := doc.Docs[0].Body
	if body == nil {
		return nil, nil
	}
	switch v := body.(type) {
	case *ast.MappingNode:
		return v.Values, nil
	case *ast.MappingValueNode:
		return []*ast.MappingValueNode{v}, nil
	case *ast.NullNode:
		return nil, nil
	default:
		return nil, fmt.Errorf("config.RewriteKey: root is not a mapping (got %T)", body)
	}
}

// findMV returns the MappingValueNode whose key string matches key, or nil.
func findMV(vals []*ast.MappingValueNode, key string) *ast.MappingValueNode {
	for _, mv := range vals {
		if mappingKeyString(mv) == key {
			return mv
		}
	}
	return nil
}

func mappingKeyString(mv *ast.MappingValueNode) string {
	if sn, ok := mv.Key.(*ast.StringNode); ok {
		return sn.Value
	}
	return mv.Key.String()
}

// startOfLine returns the byte offset of the first byte of the line containing
// the 0-based byte index offset.
func startOfLine(data []byte, offset int) int {
	if offset > len(data) {
		offset = len(data)
	}
	if offset <= 0 {
		return 0
	}
	return bytes.LastIndexAny(data[:offset], "\r\n") + 1
}

// lineColumnOffset returns the 0-based byte index in data for a 1-based
// (line, column). goccy/go-yaml's Position.Offset is unreliable across comment
// lines (each scanned comment loses one offset unit because the scanner
// advances past '#' without updating its offset counter), so Line+Column is
// the trustworthy way to locate a token's start byte.
func lineColumnOffset(data []byte, line, column int) int {
	if line < 1 {
		return 0
	}
	if column < 1 {
		column = 1
	}
	curLine := 1
	curCol := 1
	for i := 0; i < len(data); {
		if curLine == line && curCol == column {
			return i
		}
		if data[i] == '\n' || (data[i] == '\r' && (i+1 == len(data) || data[i+1] != '\n')) {
			curLine++
			curCol = 1
			i++
			continue
		}
		_, size := utf8.DecodeRune(data[i:])
		i += size
		curCol++
	}
	return len(data)
}

// tokenOffset returns the 0-based byte offset where the token begins.
func tokenOffset(data []byte, t *token.Token) int {
	if t == nil || t.Position == nil {
		return 0
	}
	return lineColumnOffset(data, t.Position.Line, t.Position.Column)
}

func exactTokenOffset(data []byte, t *token.Token) int {
	offset := tokenOffset(data, t)
	if t == nil || t.Value == "" || bytes.HasPrefix(data[offset:], []byte(t.Value)) {
		return offset
	}
	lineEnd := lineEndAfter(data, offset)
	if i := bytes.Index(data[offset:lineEnd], []byte(t.Value)); i >= 0 {
		return offset + i
	}
	return offset
}

// dashColumnFromSource returns the 0-based column where the first '-' of the
// block sequence's first entry sits, by scanning the line of the first entry's
// first token. Returns -1 when no '-' is found before the token (unexpected
// for a block sequence).
func dashColumnFromSource(data []byte, seq *ast.SequenceNode) int {
	if len(seq.Values) == 0 {
		return -1
	}
	tok := seq.Values[0].GetToken()
	if tok == nil || tok.Position == nil {
		return -1
	}
	tokenIdx := tokenOffset(data, tok)
	lineStart := startOfLine(data, tokenIdx)
	for i := lineStart; i < tokenIdx && i < len(data); i++ {
		if data[i] == '-' {
			return i - lineStart
		}
	}
	return -1
}

// leadingEdge returns the start-of-line offset of mv's leading comment block, or of mv's key line when no comment is attached.
func leadingEdge(data []byte, mv *ast.MappingValueNode) int {
	if mv.Comment != nil && len(mv.Comment.Comments) > 0 {
		first := mv.Comment.Comments[0].GetToken()
		if first != nil && first.Position != nil {
			return startOfLine(data, tokenOffset(data, first))
		}
	}
	keyTok := mv.Key.GetToken()
	if keyTok != nil && keyTok.Position != nil {
		return startOfLine(data, tokenOffset(data, keyTok))
	}
	return 0
}

// blockEnd returns the byte offset where the block whose first mapping value
// is at siblings[idx] ends. With a next sibling, that is the next sibling's
// leading edge; without one, the end-of-file.
func blockEnd(data []byte, siblings []*ast.MappingValueNode, idx int) int {
	if idx+1 < len(siblings) {
		return leadingEdge(data, siblings[idx+1])
	}
	return len(data)
}

// indexInValues returns mv's index in siblings, or -1 if absent.
func indexInValues(siblings []*ast.MappingValueNode, mv *ast.MappingValueNode) int {
	for i, x := range siblings {
		if x == mv {
			return i
		}
	}
	return -1
}

// rewritePermissions appends entry to permissions: per step (3)
// dedup-on-existing-entry leaves the existing entry where it is.
func rewritePermissions(r *settingsRewrite, entry permissions.PermissionEntry) (fsutil.AtomicWriteStep, fserrors.Category, error) {
	entryBytes, mErr := permissions.MarshalEntry(entry)
	if mErr != nil {
		return fsutil.LoadStep, "", fmt.Errorf("config.RewriteKey: marshal permission entry: %w", mErr)
	}
	entryLines := strings.Split(strings.TrimRight(string(entryBytes), "\n"), "\n")

	data, exists, step, cat, rerr := r.read()
	if rerr != nil {
		return step, cat, rerr
	}

	if !exists || len(bytes.TrimSpace(data)) == 0 {
		body := buildMinimalPermissionsFile(entryLines)
		return r.publish(body)
	}

	doc, perr := parser.ParseBytes(data, parser.ParseComments)
	if perr != nil {
		return fsutil.LoadStep, fserrors.IOError, perr
	}
	vals, verr := rootValues(doc)
	if verr != nil {
		return fsutil.LoadStep, "", verr
	}
	permsMV := findMV(vals, "permissions")

	if permsMV == nil {
		body := appendBlockAtEnd(data, buildPermissionsBlock(entryLines, 0))
		return r.publish(body)
	}

	existing, perr := readExistingPermissions(data, r.path)
	if perr != nil {
		return fsutil.LoadStep, fserrors.IOError, perr
	}
	target := entry.DedupKey()
	for _, e := range existing {
		if e.DedupKey() == target {
			return "", "", nil
		}
	}

	idx := indexInValues(vals, permsMV)
	body, sErr := splicePermissionAppend(data, permsMV, vals, idx, entryLines)
	if sErr != nil {
		return fsutil.LoadStep, "", sErr
	}
	return r.publish(body)
}

// removePermissionEntry removes the permission entry whose DedupKey matches key
// from permissions:, preserving every unrelated entry, key, comment, and adjacent
// whitespace byte-for-byte — the destructive counterpart of rewritePermissions.
// An absent file, an absent permissions: key, or a key that matches no entry is a
// clean no-op that writes nothing. Removing the only entry drops the whole
// permissions: block (mirroring deleteAuthChatGPT's empty-container removal) so no
// stray permissions: [] artifact is left behind. Existing entries are re-validated
// first, so a malformed permission list is refused rather than rewritten.
func removePermissionEntry(r *settingsRewrite, op *PermissionDeleteOp) (fsutil.AtomicWriteStep, fserrors.Category, error) {
	op.Removed = false
	key := op.Key
	publish := func(body []byte) (fsutil.AtomicWriteStep, fserrors.Category, error) {
		step, cat, err := r.publish(body)
		op.Removed = err == nil
		return step, cat, err
	}
	data, exists, step, cat, rerr := r.read()
	if rerr != nil {
		return step, cat, rerr
	}
	if !exists || len(bytes.TrimSpace(data)) == 0 {
		return "", "", nil
	}

	existing, perr := readExistingPermissions(data, r.path)
	if perr != nil {
		return fsutil.LoadStep, fserrors.IOError, perr
	}
	target := -1
	for i, e := range existing {
		if e.DedupKey() == key {
			target = i
			break
		}
	}
	if target < 0 {
		return "", "", nil
	}

	doc, perr := parser.ParseBytes(data, parser.ParseComments)
	if perr != nil {
		return fsutil.LoadStep, fserrors.IOError, perr
	}
	vals, verr := rootValues(doc)
	if verr != nil {
		return fsutil.LoadStep, "", verr
	}
	permsMV := findMV(vals, "permissions")
	if permsMV == nil {
		return "", "", nil
	}
	seq, ok := permsMV.Value.(*ast.SequenceNode)
	if !ok || len(seq.Values) == 0 {
		return "", "", nil
	}
	if target >= len(seq.Values) {
		return fsutil.LoadStep, "", fmt.Errorf("config.RewriteKey: permission entry %d out of range for %d sequence values", target, len(seq.Values))
	}

	// Removing the only entry would leave an empty sequence; drop the whole
	// permissions: block instead of leaving `permissions: []` behind.
	if len(seq.Values) == 1 {
		return publish(removeTopLevelBlock(data, permsMV, vals))
	}

	permsIdx := indexInValues(vals, permsMV)
	if seq.IsFlowStyle {
		body, fErr := removeFlowSequenceEntry(data, seq, target)
		if fErr != nil {
			return fsutil.LoadStep, "", fErr
		}
		return publish(body)
	}
	return publish(removeBlockSequenceEntry(data, seq, vals, permsIdx, target))
}

// removeBlockSequenceEntry returns data with block-sequence entry j — together
// with its own leading head comment, if any — removed, preserving every other
// entry's bytes, ordering, and comments. For a non-final entry the removal stops
// at the next entry's leading edge (so that entry's head comment survives); for
// the final entry it stops just past the newline ending the entry's last line, so
// a blank-line separator before any following key and trailing bytes survive. The
// first entry's start is taken from the line after the permissions: key, not its
// leading edge: goccy attaches a comment between the key and the first dash to the
// block region rather than to entry 0, so this is what lets that comment go with
// the entry it labels. Caller guarantees len(seq.Values) > 1 and
// 0 <= j < len(seq.Values).
func removeBlockSequenceEntry(data []byte, seq *ast.SequenceNode, rootSiblings []*ast.MappingValueNode, permsIdx, j int) []byte {
	var start int
	if j == 0 {
		start = lineAfterKey(data, rootSiblings[permsIdx])
	} else {
		start = seqEntryLeadingEdge(data, seq, j)
	}
	var end int
	if j+1 < len(seq.Values) {
		end = seqEntryLeadingEdge(data, seq, j+1)
	} else {
		end, _ = appendInsertionPoint(data, blockEnd(data, rootSiblings, permsIdx))
	}
	return spliceBytes(data, start, end, "")
}

// lineAfterKey returns the byte offset of the start of the line immediately after
// mv's key line — i.e. just past the newline that ends "<key>:". Used to bound a
// first-entry removal at the line below permissions: so a comment goccy parked in
// the block region (between the key and the first dash) is taken with entry 0.
func lineAfterKey(data []byte, mv *ast.MappingValueNode) int {
	keyTok := mv.Key.GetToken()
	if keyTok == nil || keyTok.Position == nil {
		return 0
	}
	lineStart := startOfLine(data, tokenOffset(data, keyTok))
	if nl := bytes.IndexByte(data[lineStart:], '\n'); nl >= 0 {
		return lineStart + nl + 1
	}
	return len(data)
}

// seqEntryLeadingEdge returns the start-of-line offset of block-sequence entry k's
// leading head-comment block, or of entry k's own dash line when no head comment
// is attached. It is the sequence-entry analogue of leadingEdge: bounding a
// removal at these edges makes a deleted entry take its own comment with it while
// every sibling entry's comment survives. The dash token (SequenceEntry.Start) is
// preferred over the value's first token so a dash on its own line is not orphaned.
func seqEntryLeadingEdge(data []byte, seq *ast.SequenceNode, k int) int {
	if k < len(seq.ValueHeadComments) {
		if cg := seq.ValueHeadComments[k]; cg != nil && len(cg.Comments) > 0 {
			if first := cg.Comments[0].GetToken(); first != nil && first.Position != nil {
				return startOfLine(data, tokenOffset(data, first))
			}
		}
	}
	if k < len(seq.Entries) && seq.Entries[k] != nil {
		if dash := seq.Entries[k].Start; dash != nil && dash.Position != nil {
			return startOfLine(data, tokenOffset(data, dash))
		}
	}
	if tok := seq.Values[k].GetToken(); tok != nil && tok.Position != nil {
		return startOfLine(data, tokenOffset(data, tok))
	}
	return 0
}

// removeFlowSequenceEntry returns data with flow-sequence entry j removed along
// with one adjacent comma separator, preserving every other entry's bytes and the
// surrounding bracket spacing. Entry 0 takes the trailing separator (up to the
// next entry's '{'); any later entry takes the leading separator (from the
// previous entry's '}'). Caller guarantees len(seq.Values) > 1 and
// 0 <= j < len(seq.Values).
func removeFlowSequenceEntry(data []byte, seq *ast.SequenceNode, j int) ([]byte, error) {
	start, _, err := flowEntryBraces(data, seq, j)
	if err != nil {
		return nil, err
	}
	if j == 0 {
		nextStart, _, nErr := flowEntryBraces(data, seq, 1)
		if nErr != nil {
			return nil, nErr
		}
		return spliceBytes(data, start, nextStart, ""), nil
	}
	_, prevEnd, pErr := flowEntryBraces(data, seq, j-1)
	if pErr != nil {
		return nil, pErr
	}
	_, end, eErr := flowEntryBraces(data, seq, j)
	if eErr != nil {
		return nil, eErr
	}
	return spliceBytes(data, prevEnd, end, ""), nil
}

// flowEntryBraces returns [start, end) byte offsets of flow-sequence entry k:
// start at its '{' and end just past its '}'.
func flowEntryBraces(data []byte, seq *ast.SequenceNode, k int) (start, end int, err error) {
	mn, ok := seq.Values[k].(*ast.MappingNode)
	if !ok {
		return 0, 0, fmt.Errorf("config.RewriteKey: flow permission entry %d is not a mapping (got %T)", k, seq.Values[k])
	}
	if mn.Start == nil || mn.Start.Position == nil || mn.End == nil || mn.End.Position == nil {
		return 0, 0, fmt.Errorf("config.RewriteKey: flow permission entry %d missing '{'/'}' tokens", k)
	}
	return tokenOffset(data, mn.Start), tokenOffset(data, mn.End) + 1, nil
}

// buildMinimalPermissionsFile returns the bytes of a minimal settings document
// containing only permissions: <one entry>.
func buildMinimalPermissionsFile(entryLines []string) []byte {
	var b strings.Builder
	b.WriteString("permissions:\n")
	writeSequenceEntry(&b, entryLines, 2)
	return []byte(b.String())
}

// buildPermissionsBlock returns "permissions:\n" followed by one block sequence
// entry at the given key column (0 for top-level).
func buildPermissionsBlock(entryLines []string, keyCol int) string {
	var b strings.Builder
	b.WriteString(strings.Repeat(" ", keyCol))
	b.WriteString("permissions:\n")
	writeSequenceEntry(&b, entryLines, keyCol+2)
	return b.String()
}

// writeSequenceEntry writes one block-sequence entry: "<dashIndent>- <line0>"
// then "<dashIndent>  <lineN>" for each subsequent line. dashIndent is the
// column the "-" sits at.
func writeSequenceEntry(b *strings.Builder, entryLines []string, dashIndent int) {
	dash := strings.Repeat(" ", dashIndent)
	cont := strings.Repeat(" ", dashIndent+2)
	for i, line := range entryLines {
		if i == 0 {
			b.WriteString(dash)
			b.WriteString("- ")
			b.WriteString(line)
			b.WriteString("\n")
		} else {
			b.WriteString(cont)
			b.WriteString(line)
			b.WriteString("\n")
		}
	}
}

// appendBlockAtEnd appends block at the end of data, inserting a separating
// newline when data does not already end with one.
func appendBlockAtEnd(data []byte, block string) []byte {
	var b bytes.Buffer
	b.Write(data)
	if len(data) > 0 && data[len(data)-1] != '\n' {
		b.WriteByte('\n')
	}
	b.WriteString(block)
	return b.Bytes()
}

// readExistingPermissions re-decodes the on-disk permissions: list into
// validated entries in source order; returns nil for an absent or null key.
func readExistingPermissions(data []byte, path string) ([]permissions.PermissionEntry, error) {
	var raw map[string]any
	if err := yaml.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("config.RewriteKey: re-decode for permissions: %w", err)
	}
	listRaw, ok := raw["permissions"]
	if !ok || listRaw == nil {
		return nil, nil
	}
	list, ok := listRaw.([]any)
	if !ok {
		return nil, fmt.Errorf("config.RewriteKey: permissions is not a list (got %T)", listRaw)
	}
	out := make([]permissions.PermissionEntry, 0, len(list))
	for i, item := range list {
		m, ok := toStringMap(item)
		if !ok {
			return nil, fmt.Errorf("config.RewriteKey: permissions[%d] is not a mapping (got %T)", i, item)
		}
		e, perr := permissions.ParseEntry(m, path, i)
		if perr != nil {
			return nil, fmt.Errorf("config.RewriteKey: parse existing permissions[%d]: %w", i, perr)
		}
		out = append(out, e)
	}
	return out, nil
}

// toStringMap normalizes goccy's interface-keyed maps into string-keyed form
// so permissions.ParseEntry can validate them.
func toStringMap(v any) (map[string]any, bool) {
	switch m := v.(type) {
	case map[string]any:
		return m, true
	case map[any]any:
		out := make(map[string]any, len(m))
		for k, vv := range m {
			ks, ok := k.(string)
			if !ok {
				return nil, false
			}
			out[ks] = vv
		}
		return out, true
	default:
		return nil, false
	}
}

// splicePermissionAppend produces new bytes with entryLines appended to
// permissions:. permsMV must be the existing permissions: MappingValueNode.
// For a non-empty flow sequence the new entry is spliced before the closing
// ']' as a flow-form mapping so existing entry bytes — including inter-entry
// whitespace, quoting, and ordering the user authored — survive untouched.
func splicePermissionAppend(data []byte, permsMV *ast.MappingValueNode, siblings []*ast.MappingValueNode, idx int, entryLines []string) ([]byte, error) {
	keyTok := permsMV.Key.GetToken()
	if keyTok == nil || keyTok.Position == nil {
		return nil, errors.New("config.RewriteKey: permissions key has no position")
	}
	keyCol := keyTok.Position.Column - 1 // 0-based column for the key

	if seq, ok := permsMV.Value.(*ast.SequenceNode); ok && len(seq.Values) > 0 {
		if !seq.IsFlowStyle {
			// Block sequence: append at tail, preserving every existing entry's
			// bytes. Locate the dash column from source since goccy AST tokens
			// skip the dash character itself.
			dashCol := dashColumnFromSource(data, seq)
			if dashCol < 0 {
				dashCol = keyCol + 2
			}
			end := blockEnd(data, siblings, idx)
			insertAt, needNL := appendInsertionPoint(data, end)
			var rep strings.Builder
			if needNL {
				rep.WriteString("\n")
			}
			writeSequenceEntry(&rep, entryLines, dashCol)
			return spliceBytes(data, insertAt, insertAt, rep.String()), nil
		}
		// Non-empty flow sequence: insert the new entry as a flow mapping just
		// before the closing ']'. Every byte before the splice point survives,
		// so existing entry formatting, quoting, ordering, and inter-entry
		// whitespace are preserved.
		if seq.End == nil || seq.End.Position == nil {
			return nil, errors.New("config.RewriteKey: flow permissions has no closing ']' token")
		}
		endPos := tokenOffset(data, seq.End)
		ins := ", " + entryLinesToFlow(entryLines)
		return spliceBytes(data, endPos, endPos, ins), nil
	}

	// Empty flow sequence (`permissions: []`), null, or otherwise empty: replace
	// the entire value with a block-sequence containing the new entry.
	valStart, valEnd := valueRangeAfterColon(data, permsMV, siblings, idx)
	dashCol := keyCol + 2
	var rep strings.Builder
	rep.WriteString("\n")
	writeSequenceEntry(&rep, entryLines, dashCol)
	return spliceBytes(data, valStart, valEnd, strings.TrimRight(rep.String(), "\n")), nil
}

// entryLinesToFlow joins block-form "key: value" entry lines into a single
// flow mapping like "{kind: direct, subject: ls, path_scope: \"*\", grant_kind: global}".
// Caller must guarantee each line is a self-contained "key: value" pair, which
// permissions.MarshalEntry produces by construction.
func entryLinesToFlow(entryLines []string) string {
	var b strings.Builder
	b.WriteByte('{')
	for i, line := range entryLines {
		if i > 0 {
			b.WriteString(", ")
		}
		b.WriteString(line)
	}
	b.WriteByte('}')
	return b.String()
}

// valueRangeAfterColon returns [start, end) covering everything after the
// MappingValueNode's ':' delimiter through the end of its value block. Used
// when we are replacing the entire value (flow {} or empty/null). Offsets
// returned are 0-based byte indices into data.
func valueRangeAfterColon(data []byte, mv *ast.MappingValueNode, siblings []*ast.MappingValueNode, idx int) (int, int) {
	start := 0
	if mv.Start != nil && mv.Start.Position != nil {
		// mv.Start is the ':' delimiter; advance one byte past it.
		start = tokenOffset(data, mv.Start) + 1
	} else if mv.Key.GetToken() != nil && mv.Key.GetToken().Position != nil {
		keyTok := mv.Key.GetToken()
		start = tokenOffset(data, keyTok) + len(keyTok.Origin)
		if start < len(data) && data[start] == ':' {
			start++
		}
	}
	end := blockEnd(data, siblings, idx)
	end = trimBackToContent(data, end)
	return start, end
}

// trimBackToContent moves end backward over any trailing '\n' bytes so the
// returned offset sits immediately after the last non-newline byte. It never
// crosses below start-of-data.
func trimBackToContent(data []byte, end int) int {
	for end > 0 && data[end-1] == '\n' {
		end--
	}
	return end
}

// appendInsertionPoint returns the byte offset where appended content for a
// block ending at end (exclusive) should be inserted: just past the newline
// that terminates the last non-blank line in data[:end]. needLeadingNewline
// is true when data[:end]'s last content byte is not followed by a newline,
// signalling the caller must prefix its inserted bytes with '\n' to start a
// new line.
func appendInsertionPoint(data []byte, end int) (offset int, needLeadingNewline bool) {
	if end > len(data) {
		end = len(data)
	}
	i := end
	for i > 0 {
		c := data[i-1]
		if c == '\n' || c == ' ' || c == '\t' || c == '\r' {
			i--
			continue
		}
		break
	}
	nl := bytes.IndexByte(data[i:end], '\n')
	if nl < 0 {
		return i, true
	}
	return i + nl + 1, false
}

// spliceBytes returns data[:start] + repl + data[end:].
func spliceBytes(data []byte, start, end int, repl string) []byte {
	out := make([]byte, 0, len(data)-end+start+len(repl))
	out = append(out, data[:start]...)
	out = append(out, repl...)
	out = append(out, data[end:]...)
	return out
}

// rewriteModelSubkey handles model.active and model.last_used writes, which
// share the same value shape (map of provider/id/effort) and on-disk layout.
func rewriteModelSubkey(r *settingsRewrite, sub string, newValue any) (fsutil.AtomicWriteStep, fserrors.Category, error) {
	valueYAML, mErr := yaml.Marshal(newValue)
	if mErr != nil {
		return fsutil.LoadStep, "", fmt.Errorf("config.RewriteKey: marshal model.%s value: %w", sub, mErr)
	}
	valueLines := strings.Split(strings.TrimRight(string(valueYAML), "\n"), "\n")

	data, exists, step, cat, rerr := r.read()
	if rerr != nil {
		return step, cat, rerr
	}

	if !exists || len(bytes.TrimSpace(data)) == 0 {
		body := buildMinimalModelFile(sub, valueLines)
		return r.publish(body)
	}

	doc, perr := parser.ParseBytes(data, parser.ParseComments)
	if perr != nil {
		return fsutil.LoadStep, fserrors.IOError, perr
	}
	vals, verr := rootValues(doc)
	if verr != nil {
		return fsutil.LoadStep, "", verr
	}
	modelMV := findMV(vals, "model")
	if modelMV == nil {
		body := appendBlockAtEnd(data, buildModelBlock(sub, valueLines, 0))
		return r.publish(body)
	}

	body, sErr := insertOrReplaceUnderModel(data, modelMV, vals, sub, valueLines)
	if sErr != nil {
		return fsutil.LoadStep, "", sErr
	}
	return r.publish(body)
}

// buildMinimalModelFile builds a minimal settings document for an
// absent-or-empty file containing only the requested model subkey.
// For model.last_used it includes the comment block above model:
// for model.active it includes the comment block above active:.
func buildMinimalModelFile(sub string, valueLines []string) []byte {
	var b strings.Builder
	if sub == "last_used" {
		b.WriteString(modelMapCommentBlock)
	}
	b.WriteString(buildModelBlock(sub, valueLines, 0))
	return []byte(b.String())
}

// buildModelBlock returns the textual form of a model: block at the given
// column with one subkey populated. For sub == "active" it interleaves the
// comment block above the active: key.
func buildModelBlock(sub string, valueLines []string, keyCol int) string {
	indent := strings.Repeat(" ", keyCol)
	subIndent := strings.Repeat(" ", keyCol+2)
	var b strings.Builder
	b.WriteString(indent)
	b.WriteString("model:\n")
	if sub == "active" {
		for _, ln := range strings.Split(strings.TrimRight(modelActiveCommentBlock, "\n"), "\n") {
			b.WriteString(subIndent)
			b.WriteString(ln)
			b.WriteString("\n")
		}
	}
	b.WriteString(subIndent)
	b.WriteString(sub)
	b.WriteString(":\n")
	valIndent := strings.Repeat(" ", keyCol+4)
	for _, ln := range valueLines {
		b.WriteString(valIndent)
		b.WriteString(ln)
		b.WriteString("\n")
	}
	return b.String()
}

// insertOrReplaceUnderModel handles the three subcases when model: already
// exists in the file: replace an existing subkey's value, insert a new subkey
// into a block model: mapping, or convert an empty/flow model: into a block
// mapping containing the new subkey.
func insertOrReplaceUnderModel(data []byte, modelMV *ast.MappingValueNode, rootSiblings []*ast.MappingValueNode, sub string, valueLines []string) ([]byte, error) {
	modelIdx := indexInValues(rootSiblings, modelMV)
	keyTok := modelMV.Key.GetToken()
	if keyTok == nil || keyTok.Position == nil {
		return nil, errors.New("config.RewriteKey: model key has no position")
	}
	modelKeyCol := keyTok.Position.Column - 1
	subCol := modelKeyCol + 2
	valCol := modelKeyCol + 4

	// Examine model:'s value type.
	switch v := modelMV.Value.(type) {
	case *ast.MappingNode:
		if v.IsFlowStyle {
			// `model: {}` or `model: {active: ..., ...}`.
			if len(v.Values) == 0 {
				// Empty flow: replace value bytes with a block mapping.
				start, end := valueRangeAfterColon(data, modelMV, rootSiblings, modelIdx)
				rep := buildModelValueBody(sub, valueLines, subCol, valCol, true)
				return spliceBytes(data, start, end, rep), nil
			}
			// Non-empty flow.
			subMV, _ := findSubMV(v.Values, sub)
			if subMV != nil {
				// Replace the target subkey's value bytes in place; every
				// other byte (including non-target subkey bytes) survives.
				return replaceFlowSubkeyValue(data, subMV, v, valueLines)
			}
			// Target subkey absent.
			if sub == "active" {
				// requires the comment block above active when
				// inserted into a file that did not previously contain the
				// key. Comments can not sit inside a flow mapping, so
				// convert the flow value to block form while preserving each
				// non-target subkey's source value bytes (formatting,
				// quoting, and any inner flow style intact).
				return convertFlowModelForActiveInsert(data, modelMV, rootSiblings, modelIdx, v, valueLines, subCol, valCol)
			}
			// last_used: insert as a flow entry before the closing '}'; the
			// preceding bytes (including every existing subkey) survive.
			return insertFlowSubkey(data, v, sub, valueLines)
		}
		// Block model: mapping. Walk its values.
		subMV, _ := findSubMV(v.Values, sub)
		if subMV != nil {
			return replaceBlockSubkeyValue(data, subMV, v.Values, rootSiblings, modelIdx, valueLines, valCol), nil
		}
		// Insert new subkey after the last existing one.
		return insertBlockSubkey(data, modelMV, rootSiblings, modelIdx, v, sub, valueLines, subCol, valCol), nil
	case *ast.NullNode, nil:
		// `model:` with null/implicit value. Replace value bytes with block.
		start, end := valueRangeAfterColon(data, modelMV, rootSiblings, modelIdx)
		rep := buildModelValueBody(sub, valueLines, subCol, valCol, true)
		return spliceBytes(data, start, end, rep), nil
	default:
		return nil, fmt.Errorf("config.RewriteKey: model: value has unsupported shape %T", v)
	}
}

// replaceFlowSubkeyValue replaces the bytes of subMV's value inside a flow
// `model: {...}` mapping with the new value rendered as a flow mapping. Every
// other byte — the surrounding `{...}` brackets, other subkeys, separators,
// and any user-authored inter-token whitespace — survives untouched per
func replaceFlowSubkeyValue(data []byte, subMV *ast.MappingValueNode, modelMap *ast.MappingNode, valueLines []string) ([]byte, error) {
	start, end, err := flowSubkeyValueRange(data, subMV, modelMap)
	if err != nil {
		return nil, err
	}
	return spliceBytes(data, start, end, flowValueReplacement(data, start, entryLinesToFlow(valueLines))), nil
}

// insertFlowSubkey inserts ", <sub>: <flow-value>" just before the flow
// mapping's closing '}'. Every preceding byte — including every existing
// subkey and its surrounding whitespace — survives.
func insertFlowSubkey(data []byte, modelMap *ast.MappingNode, sub string, valueLines []string) ([]byte, error) {
	if modelMap.End == nil || modelMap.End.Position == nil {
		return nil, errors.New("config.RewriteKey: flow model has no closing '}' token")
	}
	endPos := tokenOffset(data, modelMap.End)
	ins := ", " + sub + ": " + entryLinesToFlow(valueLines)
	return spliceBytes(data, endPos, endPos, ins), nil
}

// convertFlowModelForActiveInsert rewrites a non-empty flow `model: {...}` as
// a block mapping when inserting the active subkey, which carries the
// comment block that no flow mapping can host inline. Every non-target
// subkey's value bytes are copied verbatim from source — preserving quoting
// and any inner flow style the user authored — and emitted on its own block
// line; only key indentation changes.
func convertFlowModelForActiveInsert(data []byte, modelMV *ast.MappingValueNode, rootSiblings []*ast.MappingValueNode, modelIdx int, modelMap *ast.MappingNode, valueLines []string, subCol, valCol int) ([]byte, error) {
	var b strings.Builder
	b.WriteString("\n")

	subIndent := strings.Repeat(" ", subCol)
	for _, subMV := range modelMap.Values {
		keyStr := mappingKeyString(subMV)
		s, e, rErr := flowSubkeyValueRange(data, subMV, modelMap)
		if rErr != nil {
			return nil, rErr
		}
		valBytes := strings.TrimSpace(string(data[s:e]))
		b.WriteString(subIndent)
		b.WriteString(keyStr)
		b.WriteString(": ")
		b.WriteString(valBytes)
		b.WriteString("\n")
	}

	for _, ln := range strings.Split(strings.TrimRight(modelActiveCommentBlock, "\n"), "\n") {
		b.WriteString(subIndent)
		b.WriteString(ln)
		b.WriteString("\n")
	}
	b.WriteString(subIndent)
	b.WriteString("active:\n")
	for _, ln := range valueLines {
		b.WriteString(strings.Repeat(" ", valCol))
		b.WriteString(ln)
		b.WriteString("\n")
	}

	start, end := valueRangeAfterColon(data, modelMV, rootSiblings, modelIdx)
	return spliceBytes(data, start, end, strings.TrimRight(b.String(), "\n")), nil
}

// goccy token origins include leading scanner whitespace; derive the end from sibling positions.
func flowSubkeyValueRange(data []byte, subMV *ast.MappingValueNode, modelMap *ast.MappingNode) (int, int, error) {
	return flowSubkeyValueRangeTo(data, subMV, modelMap, tokenOffset(data, modelMap.End))
}

func flowSubkeyValueRangeTo(data []byte, subMV *ast.MappingValueNode, modelMap *ast.MappingNode, mappingEnd int) (int, int, error) {
	var start int
	if subMV.Start != nil && subMV.Start.Position != nil {
		start = tokenOffset(data, subMV.Start) + 1
	} else {
		keyTok := subMV.Key.GetToken()
		if keyTok == nil || keyTok.Position == nil {
			return 0, 0, errors.New("config.RewriteKey: flow subkey has no key position")
		}
		start = tokenOffset(data, keyTok) + len(keyTok.Origin)
		if start < len(data) && data[start] == ':' {
			start++
		}
	}

	subIdx := indexInValues(modelMap.Values, subMV)
	var bound int
	if subIdx >= 0 && subIdx+1 < len(modelMap.Values) {
		nextKeyTok := modelMap.Values[subIdx+1].Key.GetToken()
		if nextKeyTok == nil || nextKeyTok.Position == nil {
			return 0, 0, errors.New("config.RewriteKey: flow subkey sibling has no key position")
		}
		bound = tokenOffset(data, nextKeyTok)
	} else {
		if modelMap.End == nil || modelMap.End.Position == nil {
			return 0, 0, errors.New("config.RewriteKey: flow mapping has no closing '}' token")
		}
		bound = mappingEnd
	}
	start = flowValueStart(data, start, bound)
	end := flowValueEnd(data, start, bound)
	if end < start {
		end = start
	}
	return start, end, nil
}

func flowValueStart(data []byte, start, bound int) int {
	for start < bound {
		for start < bound && isFlowSpace(data[start]) {
			start++
		}
		if start >= bound || data[start] != '#' {
			return start
		}
		for start < bound && data[start] != '\n' {
			start++
		}
	}
	return start
}

func flowValueReplacement(data []byte, start int, value string) string {
	if start > 0 && data[start-1] == ':' {
		return " " + value
	}
	return value
}

func flowMappingEnd(data []byte, start int) int {
	depth := 0
	var quote byte
	for i := start; i < len(data); i++ {
		c := data[i]
		switch {
		case quote == '"' && c == '\\':
			i++
		case quote != 0:
			if c == quote {
				quote = 0
			}
		case c == '\'' || c == '"':
			quote = c
		case c == '{':
			depth++
		case c == '}':
			depth--
			if depth == 0 {
				return i
			}
		}
	}
	return len(data)
}

func flowValueEnd(data []byte, start, bound int) int {
	if bound > len(data) {
		bound = len(data)
	}
	depth := 0
	var quote byte
	for i := start; i < bound; i++ {
		c := data[i]
		switch {
		case quote == '"' && c == '\\':
			i++
		case quote != 0:
			if c == quote {
				quote = 0
			}
		case c == '\'' || c == '"':
			quote = c
		case c == '[' || c == '{':
			depth++
		case c == ']' || c == '}':
			if depth == 0 {
				return trimTrailingFlowSpace(data, start, i)
			}
			depth--
		case depth == 0 && c == ',':
			return trimTrailingFlowSpace(data, start, i)
		case c == '#' && (i == start || isFlowSpace(data[i-1])):
			if depth == 0 {
				return trimTrailingFlowSpace(data, start, i)
			}
			for i+1 < bound && data[i+1] != '\n' {
				i++
			}
		}
	}
	return trimTrailingFlowSpace(data, start, bound)
}

func trimTrailingFlowSpace(data []byte, start, end int) int {
	for end > start && isFlowSpace(data[end-1]) {
		end--
	}
	return end
}

func isFlowSpace(c byte) bool {
	return c == ' ' || c == '\t' || c == '\n' || c == '\r'
}

// findSubMV returns the MappingValueNode with key sub, or nil.
func findSubMV(values []*ast.MappingValueNode, sub string) (*ast.MappingValueNode, int) {
	for i, mv := range values {
		if mappingKeyString(mv) == sub {
			return mv, i
		}
	}
	return nil, -1
}

// buildModelValueBody returns the textual body for a model: value when we are
// replacing the whole value (empty flow {} or null). leadingNewline causes a
// leading newline before the first subkey so it formats as `model:\n  ...`.
func buildModelValueBody(sub string, valueLines []string, subCol, valCol int, leadingNewline bool) string {
	var b strings.Builder
	if leadingNewline {
		b.WriteString("\n")
	}
	if sub == "active" {
		subIndent := strings.Repeat(" ", subCol)
		for _, ln := range strings.Split(strings.TrimRight(modelActiveCommentBlock, "\n"), "\n") {
			b.WriteString(subIndent)
			b.WriteString(ln)
			b.WriteString("\n")
		}
	}
	b.WriteString(strings.Repeat(" ", subCol))
	b.WriteString(sub)
	b.WriteString(":\n")
	for i, ln := range valueLines {
		b.WriteString(strings.Repeat(" ", valCol))
		b.WriteString(ln)
		if i < len(valueLines)-1 {
			b.WriteString("\n")
		}
	}
	return b.String()
}

func blockSubkeyValueRange(data []byte, subMV *ast.MappingValueNode, siblings []*ast.MappingValueNode, rootSiblings []*ast.MappingValueNode, parentIdx int) (int, int) {
	subIdx := indexInValues(siblings, subMV)
	var end int
	if subIdx+1 < len(siblings) {
		end = leadingEdge(data, siblings[subIdx+1])
	} else {
		end = blockEnd(data, rootSiblings, parentIdx)
	}
	end = trimBackToContent(data, end)

	start := 0
	if subMV.Start != nil && subMV.Start.Position != nil {
		start = tokenOffset(data, subMV.Start) + 1
	} else {
		keyTok := subMV.Key.GetToken()
		start = tokenOffset(data, keyTok) + len(keyTok.Origin)
		if start < len(data) && data[start] == ':' {
			start++
		}
	}
	return start, end
}

func replaceBlockSubkeyValue(data []byte, subMV *ast.MappingValueNode, siblings []*ast.MappingValueNode, rootSiblings []*ast.MappingValueNode, parentIdx int, valueLines []string, valCol int) []byte {
	start, end := blockSubkeyValueRange(data, subMV, siblings, rootSiblings, parentIdx)
	// The new value will live on its own indented lines; replace from just
	// after ':' through end of subkey block.
	var rep strings.Builder
	rep.WriteString("\n")
	for i, ln := range valueLines {
		rep.WriteString(strings.Repeat(" ", valCol))
		rep.WriteString(ln)
		if i < len(valueLines)-1 {
			rep.WriteString("\n")
		}
	}
	return spliceBytes(data, start, end, rep.String())
}

// insertBlockSubkey inserts a new subkey after the last existing subkey under
// model:.
func insertBlockSubkey(data []byte, modelMV *ast.MappingValueNode, rootSiblings []*ast.MappingValueNode, modelIdx int, modelMap *ast.MappingNode, sub string, valueLines []string, subCol, valCol int) []byte {
	if len(modelMap.Values) == 0 {
		start, e := valueRangeAfterColon(data, modelMV, rootSiblings, modelIdx)
		rep := buildModelValueBody(sub, valueLines, subCol, valCol, true)
		return spliceBytes(data, start, e, rep)
	}
	end := blockEnd(data, rootSiblings, modelIdx)
	insertAt, needNL := appendInsertionPoint(data, end)
	var rep strings.Builder
	if needNL {
		rep.WriteString("\n")
	}
	if sub == "active" {
		subIndent := strings.Repeat(" ", subCol)
		for _, ln := range strings.Split(strings.TrimRight(modelActiveCommentBlock, "\n"), "\n") {
			rep.WriteString(subIndent)
			rep.WriteString(ln)
			rep.WriteString("\n")
		}
	}
	rep.WriteString(strings.Repeat(" ", subCol))
	rep.WriteString(sub)
	rep.WriteString(":\n")
	for i, ln := range valueLines {
		rep.WriteString(strings.Repeat(" ", valCol))
		rep.WriteString(ln)
		if i < len(valueLines)-1 {
			rep.WriteString("\n")
		}
	}
	// Ensure the inserted subkey ends with a newline so the next byte
	// belongs to a clean line.
	rep.WriteString("\n")
	return spliceBytes(data, insertAt, insertAt, rep.String())
}

// setAuthChatGPT sets auth.openai-chatgpt to newValue (a yaml-marshalable
// mapping of the access_token/refresh_token/expires_at/account_id fields),
// preserving every other byte, comment, and unrelated key. It
// mirrors rewriteModelSubkey's nested-subkey handling but writes no managed
// comment block (auth carries none) and treats the auth container key.
func setAuthChatGPT(r *settingsRewrite, newValue any) (fsutil.AtomicWriteStep, fserrors.Category, error) {
	valueYAML, mErr := yaml.Marshal(newValue)
	if mErr != nil {
		return fsutil.LoadStep, "", fmt.Errorf("config.RewriteKey: marshal auth.openai-chatgpt value: %w", mErr)
	}
	valueLines := strings.Split(strings.TrimRight(string(valueYAML), "\n"), "\n")

	data, exists, step, cat, rerr := r.read()
	if rerr != nil {
		return step, cat, rerr
	}

	if !exists || len(bytes.TrimSpace(data)) == 0 {
		return r.publish([]byte(buildAuthBlock(valueLines, 0)))
	}

	doc, perr := parser.ParseBytes(data, parser.ParseComments)
	if perr != nil {
		return fsutil.LoadStep, fserrors.IOError, perr
	}
	vals, verr := rootValues(doc)
	if verr != nil {
		return fsutil.LoadStep, "", verr
	}
	authMV := findMV(vals, authKey)
	if authMV == nil {
		return r.publish(appendBlockAtEnd(data, buildAuthBlock(valueLines, 0)))
	}

	body, sErr := insertOrReplaceAuthSub(data, authMV, vals, valueLines)
	if sErr != nil {
		return fsutil.LoadStep, "", sErr
	}
	return r.publish(body)
}

// buildAuthBlock returns the textual form of an auth: block at the given key
// column with the single openai-chatgpt subkey populated from valueLines.
func buildAuthBlock(valueLines []string, keyCol int) string {
	indent := strings.Repeat(" ", keyCol)
	subIndent := strings.Repeat(" ", keyCol+2)
	valIndent := strings.Repeat(" ", keyCol+4)
	var b strings.Builder
	b.WriteString(indent)
	b.WriteString(authKey)
	b.WriteString(":\n")
	b.WriteString(subIndent)
	b.WriteString(authChatGPTSub)
	b.WriteString(":\n")
	for _, ln := range valueLines {
		b.WriteString(valIndent)
		b.WriteString(ln)
		b.WriteString("\n")
	}
	return b.String()
}

// insertOrReplaceAuthSub handles the subcases when auth: already exists: replace
// the openai-chatgpt value in place, insert openai-chatgpt into a block auth:
// mapping, or convert an empty/flow/null auth: value into a block mapping
// holding openai-chatgpt. Every non-target byte survives.
func insertOrReplaceAuthSub(data []byte, authMV *ast.MappingValueNode, rootSiblings []*ast.MappingValueNode, valueLines []string) ([]byte, error) {
	authIdx := indexInValues(rootSiblings, authMV)
	keyTok := authMV.Key.GetToken()
	if keyTok == nil || keyTok.Position == nil {
		return nil, errors.New("config.RewriteKey: auth key has no position")
	}
	authKeyCol := keyTok.Position.Column - 1
	subCol := authKeyCol + 2
	valCol := authKeyCol + 4

	switch v := authMV.Value.(type) {
	case *ast.MappingNode:
		subMV, _ := findSubMV(v.Values, authChatGPTSub)
		if v.IsFlowStyle {
			if subMV != nil {
				return replaceFlowSubkeyValue(data, subMV, v, valueLines)
			}
			return insertFlowSubkey(data, v, authChatGPTSub, valueLines)
		}
		if subMV != nil {
			return replaceBlockSubkeyValue(data, subMV, v.Values, rootSiblings, authIdx, valueLines, valCol), nil
		}
		return insertAuthBlockSubkey(data, authMV, rootSiblings, authIdx, v, valueLines, subCol, valCol), nil
	case *ast.NullNode, nil:
		start, end := valueRangeAfterColon(data, authMV, rootSiblings, authIdx)
		return spliceBytes(data, start, end, buildAuthValueBody(valueLines, subCol, valCol)), nil
	default:
		return nil, fmt.Errorf("config.RewriteKey: auth: value has unsupported shape %T", v)
	}
}

// insertAuthBlockSubkey inserts the openai-chatgpt subkey after the last existing
// subkey of a block auth: mapping (or replaces an empty value with a block
// mapping). It carries no managed comment, unlike model.active's insert.
func insertAuthBlockSubkey(data []byte, authMV *ast.MappingValueNode, rootSiblings []*ast.MappingValueNode, authIdx int, authMap *ast.MappingNode, valueLines []string, subCol, valCol int) []byte {
	if len(authMap.Values) == 0 {
		start, e := valueRangeAfterColon(data, authMV, rootSiblings, authIdx)
		return spliceBytes(data, start, e, buildAuthValueBody(valueLines, subCol, valCol))
	}
	end := blockEnd(data, rootSiblings, authIdx)
	insertAt, needNL := appendInsertionPoint(data, end)
	var rep strings.Builder
	if needNL {
		rep.WriteString("\n")
	}
	writeAuthSubkey(&rep, valueLines, subCol, valCol)
	rep.WriteString("\n")
	return spliceBytes(data, insertAt, insertAt, rep.String())
}

// buildAuthValueBody returns the body for an auth: value when replacing the whole
// value (empty/flow {} or null): a leading newline then the openai-chatgpt block.
func buildAuthValueBody(valueLines []string, subCol, valCol int) string {
	var b strings.Builder
	b.WriteString("\n")
	writeAuthSubkey(&b, valueLines, subCol, valCol)
	return strings.TrimRight(b.String(), "\n")
}

// writeAuthSubkey writes "openai-chatgpt:\n" at subCol followed by each value
// line at valCol, each terminated by a newline.
func writeAuthSubkey(b *strings.Builder, valueLines []string, subCol, valCol int) {
	b.WriteString(strings.Repeat(" ", subCol))
	b.WriteString(authChatGPTSub)
	b.WriteString(":\n")
	for _, ln := range valueLines {
		b.WriteString(strings.Repeat(" ", valCol))
		b.WriteString(ln)
		b.WriteString("\n")
	}
}

// deleteAuthChatGPT removes auth.openai-chatgpt (logout). Because
// the settings schema makes openai-chatgpt the only key permitted under auth
// (additionalProperties:false) and Persist re-reads + schema-validates before
// this runs, an auth: block that contains the session contains nothing else, so
// removing the whole auth: block removes only the session and preserves every
// unrelated key, comment, and whitespace byte. Deleting an absent session (no
// file, no auth:, or no openai-chatgpt subkey) is a no-op that writes nothing.
func deleteAuthChatGPT(r *settingsRewrite) (fsutil.AtomicWriteStep, fserrors.Category, error) {
	data, exists, step, cat, rerr := r.read()
	if rerr != nil {
		return step, cat, rerr
	}
	if !exists || len(bytes.TrimSpace(data)) == 0 {
		return "", "", nil
	}

	doc, perr := parser.ParseBytes(data, parser.ParseComments)
	if perr != nil {
		return fsutil.LoadStep, fserrors.IOError, perr
	}
	vals, verr := rootValues(doc)
	if verr != nil {
		return fsutil.LoadStep, "", verr
	}
	authMV := findMV(vals, authKey)
	if authMV == nil {
		return "", "", nil
	}
	authMap, ok := authMV.Value.(*ast.MappingNode)
	if !ok {
		// auth: present but null/scalar (no session mapping): nothing to delete.
		return "", "", nil
	}
	if _, idx := findSubMV(authMap.Values, authChatGPTSub); idx < 0 {
		return "", "", nil
	}

	body := removeTopLevelBlock(data, authMV, vals)
	return r.publish(body)
}

// removeTopLevelBlock returns data with the whole top-level block at mv removed:
// from the start of mv's key line (preserving any preceding comment that belongs
// to a prior key) through the next sibling's leading edge, or end-of-file. When
// mv was the final block, the result is trimmed to end in a single trailing
// newline so no dangling blank line remains.
func removeTopLevelBlock(data []byte, mv *ast.MappingValueNode, siblings []*ast.MappingValueNode) []byte {
	idx := indexInValues(siblings, mv)
	keyTok := mv.Key.GetToken()
	start := startOfLine(data, tokenOffset(data, keyTok))
	end := blockEnd(data, siblings, idx)
	out := spliceBytes(data, start, end, "")
	if end >= len(data) {
		out = trimToSingleTrailingNewline(out)
	}
	return out
}

// trimToSingleTrailingNewline strips trailing whitespace-only bytes and, when any
// content remains, terminates the result with exactly one newline. An all-blank
// input yields empty bytes (a valid empty settings document).
func trimToSingleTrailingNewline(data []byte) []byte {
	end := len(data)
	for end > 0 {
		switch data[end-1] {
		case '\n', ' ', '\t', '\r':
			end--
			continue
		}
		break
	}
	if end == 0 {
		return []byte{}
	}
	out := make([]byte, 0, end+1)
	out = append(out, data[:end]...)
	return append(out, '\n')
}

// setAttribution creates or updates the top-level attribution boolean. An existing
// key is rewritten by replacing the scalar's own bytes rather than its whole value
// range, so an inline comment on the same line survives.
func setAttribution(r *settingsRewrite, on bool) (fsutil.AtomicWriteStep, fserrors.Category, error) {
	scalar := strconv.FormatBool(on)

	data, exists, step, cat, rerr := r.read()
	if rerr != nil {
		return step, cat, rerr
	}
	if !exists || len(bytes.TrimSpace(data)) == 0 {
		return r.publish([]byte(KeyAttribution + ": " + scalar + "\n"))
	}

	doc, perr := parser.ParseBytes(data, parser.ParseComments)
	if perr != nil {
		return fsutil.LoadStep, fserrors.IOError, perr
	}
	vals, verr := rootValues(doc)
	if verr != nil {
		return fsutil.LoadStep, "", verr
	}
	mv := findMV(vals, KeyAttribution)
	if mv == nil {
		return r.publish(appendBlockAtEnd(data, KeyAttribution+": "+scalar+"\n"))
	}

	node, ok := mv.Value.(*ast.BoolNode)
	if !ok {
		return fsutil.LoadStep, "", fmt.Errorf("config.RewriteKey: attribution is not a boolean scalar (got %T)", mv.Value)
	}
	tok := node.GetToken()
	if tok == nil || tok.Position == nil {
		return fsutil.LoadStep, "", errors.New("config.RewriteKey: attribution value has no position")
	}
	start := tokenOffset(data, tok)
	return r.publish(spliceBytes(data, start, start+len(tok.Value), scalar))
}

func setNestedScalar(r *settingsRewrite, container, field, value string) (fsutil.AtomicWriteStep, fserrors.Category, error) {
	entry := field + ": " + value
	block := container + ":\n  " + entry + "\n"

	data, exists, step, cat, rerr := r.read()
	if rerr != nil {
		return step, cat, rerr
	}
	if !exists || len(bytes.TrimSpace(data)) == 0 {
		return r.publish([]byte(block))
	}

	doc, perr := parser.ParseBytes(data, parser.ParseComments)
	if perr != nil {
		return fsutil.LoadStep, fserrors.IOError, perr
	}
	vals, verr := rootValues(doc)
	if verr != nil {
		return fsutil.LoadStep, "", verr
	}
	mv := findMV(vals, container)
	if mv == nil {
		var root yamlMapping
		if len(doc.Docs) > 0 {
			root, _ = asYAMLMapping(doc.Docs[0].Body)
		}
		if len(root.values) > 0 || root.flow != nil {
			body, err := insertMappingEntry(data, root, []string{container + ":", "  " + entry}, container+": {"+entry+"}")
			if err != nil {
				return fsutil.LoadStep, "", err
			}
			return r.publish(body)
		}
		at, off := len(data), 0
		for line := range bytes.Lines(data) {
			if rest, ok := bytes.CutPrefix(line, []byte("...")); ok && (len(rest) == 0 || strings.ContainsRune(" \t\r\n", rune(rest[0]))) {
				at = off
				break
			}
			off += len(line)
		}
		return r.publish(append(appendBlockAtEnd(data[:at:at], block), data[at:]...))
	}

	switch mv.Value.(type) {
	case *ast.NullNode, nil:
		if root, _ := asYAMLMapping(doc.Docs[0].Body); root.flow != nil {
			start, end, err := flowSubkeyValueRange(data, mv, root.flow)
			if err != nil {
				return fsutil.LoadStep, "", err
			}
			return r.publish(spliceBytes(data, start, end, flowValueReplacement(data, start, "{"+entry+"}")))
		}
		keyTok := mv.Key.GetToken()
		if keyTok == nil || keyTok.Position == nil {
			return fsutil.LoadStep, "", fmt.Errorf("config.RewriteKey: %s key has no position", container)
		}
		start, _ := valueRangeAfterColon(data, mv, vals, indexInValues(vals, mv))
		end := start
		if n, ok := mv.Value.(*ast.NullNode); ok {
			if tok := n.GetToken(); tok != nil && tok.Position != nil && tok.Value != "" {
				off := exactTokenOffset(data, tok)
				if e := off + len(tok.Value); off >= start && bytes.HasPrefix(data[off:], []byte(tok.Value)) && (e == len(data) || strings.IndexByte(" \t\r\n#", data[e]) >= 0) {
					end = e
				}
			}
		}
		at := lineEndAfter(data, end)
		if at > end && data[at-1] == '\n' {
			at--
		}
		indent := strings.Repeat(" ", keyTok.Position.Column+1)
		body := spliceBytes(data, at, at, "\n"+indent+entry)
		return r.publish(spliceBytes(body, start, end, ""))
	}
	m, ok := asYAMLMapping(mv.Value)
	if !ok {
		return fsutil.LoadStep, "", fmt.Errorf("config.RewriteKey: %s is not a mapping (got %T)", container, mv.Value)
	}
	body, err := setMappingScalar(data, m, field, value)
	if err != nil {
		return fsutil.LoadStep, "", err
	}
	return r.publish(body)
}

// setProviderEntry creates or updates the durable global provider.<name> mapping,
// preserving every other byte, comment, and unrelated key. It mirrors
// setAuthChatGPT's nested-subkey byte-splice but under the provider: container with
// a caller-supplied entry name. Writing the reserved openai-chatgpt id is refused
// before any file access (that provider's credentials live only under
// auth.openai-chatgpt). The value is marshaled to the provider.ProviderEntry shape
// and schema-validated before any write; a malformed value leaves the on-disk file
// untouched. The api key value never appears in a returned error.
func setProviderEntry(r *settingsRewrite, name string, newValue any) (fsutil.AtomicWriteStep, fserrors.Category, error) {
	if name == provider.ChatGPTProviderID {
		return fsutil.LoadStep, "", fmt.Errorf("config.RewriteKey: refusing to write provider.%s: %w", name, ErrReservedProviderID)
	}

	valueYAML, mErr := yaml.Marshal(newValue)
	if mErr != nil {
		// Wrap with a static message only: valueYAML holds the plaintext api key.
		return fsutil.LoadStep, "", errors.New("config.RewriteKey: marshal provider entry value failed")
	}
	valueLines := strings.Split(strings.TrimRight(string(valueYAML), "\n"), "\n")

	// A hand-authored settings file may store provider: as a flow mapping
	// (`provider: {name: {...}}`). Editing that shape splices a single flow-form
	// entry, so render the value in flow too. Like valueYAML this holds the
	// plaintext api key, so any marshal error is reported with a static message.
	flowYAML, fErr := yaml.MarshalWithOptions(newValue, yaml.Flow(true))
	if fErr != nil {
		return fsutil.LoadStep, "", errors.New("config.RewriteKey: marshal provider entry value failed")
	}
	flowEntry := strings.TrimSpace(string(flowYAML))

	// Validate the entry shape against the settings schema before writing so a
	// malformed value is refused with the file untouched. A minimal
	// provider.<name> document is enough — unrelated on-disk keys are already
	// valid, and the schema error names offending keys, never the api key value.
	entryDoc := buildProviderBlock(name, valueLines, 0)
	if vErr := Validate([]byte(entryDoc), "provider."+name); vErr != nil {
		return fsutil.LoadStep, "", fmt.Errorf("config.RewriteKey: provider.%s failed schema validation: %w", name, vErr)
	}

	data, exists, step, cat, rerr := r.read()
	if rerr != nil {
		return step, cat, rerr
	}
	if !exists || len(bytes.TrimSpace(data)) == 0 {
		return r.publish([]byte(entryDoc))
	}

	if name == openRouterProviderID {
		body, merged, mErr := mergeOpenRouterConnection(data, valueYAML)
		if mErr != nil {
			return fsutil.LoadStep, "", mErr
		}
		if merged {
			return validateAndPublish(r, body)
		}
	}

	doc, perr := parser.ParseBytes(data, parser.ParseComments)
	if perr != nil {
		return fsutil.LoadStep, fserrors.IOError, perr
	}
	vals, verr := rootValues(doc)
	if verr != nil {
		return fsutil.LoadStep, "", verr
	}
	provMV := findMV(vals, providerKey)
	if provMV == nil {
		return r.publish(appendBlockAtEnd(data, entryDoc))
	}

	body, sErr := insertOrReplaceProviderSub(data, provMV, vals, name, valueLines, flowEntry)
	if sErr != nil {
		return fsutil.LoadStep, "", sErr
	}
	return r.publish(body)
}

// insertOrReplaceProviderSub handles the subcases when provider: already exists:
// replace the <name> entry's value in place, insert <name> into an existing
// provider: mapping, or convert an empty/null provider: value into a block mapping
// holding <name>. Every non-target byte survives. Both block and non-empty
// flow-style (`provider: {...}`) maps are supported: a flow map is edited in flow
// form — replace the target's value range, or splice `, <name>: <flowEntry>` before
// the closing '}' — so each sibling's original flow bytes are preserved. flowEntry
// is the value rendered as a single flow mapping for that path.
func insertOrReplaceProviderSub(data []byte, provMV *ast.MappingValueNode, rootSiblings []*ast.MappingValueNode, name string, valueLines []string, flowEntry string) ([]byte, error) {
	provIdx := indexInValues(rootSiblings, provMV)
	keyTok := provMV.Key.GetToken()
	if keyTok == nil || keyTok.Position == nil {
		return nil, errors.New("config.RewriteKey: provider key has no position")
	}
	provKeyCol := keyTok.Position.Column - 1
	subCol := provKeyCol + 2
	valCol := provKeyCol + 4

	switch v := provMV.Value.(type) {
	case *ast.MappingNode:
		if v.IsFlowStyle {
			// Empty `provider: {}`: no siblings to keep, so materialize a block
			// mapping holding <name> (the form codemeld otherwise writes).
			if len(v.Values) == 0 {
				start, end := valueRangeAfterColon(data, provMV, rootSiblings, provIdx)
				return spliceBytes(data, start, end, buildProviderValueBody(name, valueLines, subCol, valCol)), nil
			}
			// Replace the target's flow value range in place.
			if subMV, _ := findSubMV(v.Values, name); subMV != nil {
				start, end, rErr := flowSubkeyValueRange(data, subMV, v)
				if rErr != nil {
					return nil, rErr
				}
				return spliceBytes(data, start, end, flowValueReplacement(data, start, flowEntry)), nil
			}
			// Absent target: splice a new flow entry before the closing '}',
			// leaving every existing sibling's bytes untouched.
			if v.End == nil || v.End.Position == nil {
				return nil, errors.New("config.RewriteKey: flow provider map has no closing '}' token")
			}
			endPos := tokenOffset(data, v.End)
			return spliceBytes(data, endPos, endPos, ", "+name+": "+flowEntry), nil
		}
		if subMV, _ := findSubMV(v.Values, name); subMV != nil {
			return replaceBlockSubkeyValue(data, subMV, v.Values, rootSiblings, provIdx, valueLines, valCol), nil
		}
		return insertProviderSubkey(data, provMV, rootSiblings, provIdx, v, name, valueLines, subCol, valCol), nil
	case *ast.NullNode, nil:
		start, end := valueRangeAfterColon(data, provMV, rootSiblings, provIdx)
		return spliceBytes(data, start, end, buildProviderValueBody(name, valueLines, subCol, valCol)), nil
	default:
		return nil, fmt.Errorf("config.RewriteKey: provider: value has unsupported shape %T", v)
	}
}

// insertProviderSubkey inserts a new <name> entry after the last existing entry of
// a block provider: mapping (or replaces an empty value with a block mapping). It
// carries no managed comment, mirroring insertBlockSubkey's newline handling so no
// trailing blank line is introduced.
func insertProviderSubkey(data []byte, provMV *ast.MappingValueNode, rootSiblings []*ast.MappingValueNode, provIdx int, provMap *ast.MappingNode, name string, valueLines []string, subCol, valCol int) []byte {
	if len(provMap.Values) == 0 {
		start, e := valueRangeAfterColon(data, provMV, rootSiblings, provIdx)
		return spliceBytes(data, start, e, buildProviderValueBody(name, valueLines, subCol, valCol))
	}
	end := blockEnd(data, rootSiblings, provIdx)
	insertAt, needNL := appendInsertionPoint(data, end)
	var rep strings.Builder
	if needNL {
		rep.WriteString("\n")
	}
	writeProviderSubkey(&rep, name, valueLines, subCol, valCol)
	rep.WriteString("\n")
	return spliceBytes(data, insertAt, insertAt, rep.String())
}

// buildProviderBlock returns a provider: block at the given key column with the
// single <name> entry populated from valueLines, each value line terminated by a
// newline (so a create-from-absence file ends with a newline).
func buildProviderBlock(name string, valueLines []string, keyCol int) string {
	indent := strings.Repeat(" ", keyCol)
	subIndent := strings.Repeat(" ", keyCol+2)
	valIndent := strings.Repeat(" ", keyCol+4)
	var b strings.Builder
	b.WriteString(indent)
	b.WriteString(providerKey)
	b.WriteString(":\n")
	b.WriteString(subIndent)
	b.WriteString(name)
	b.WriteString(":\n")
	for _, ln := range valueLines {
		b.WriteString(valIndent)
		b.WriteString(ln)
		b.WriteString("\n")
	}
	return b.String()
}

// buildProviderValueBody returns the body for a provider: value when replacing the
// whole value (empty flow {} or null): a leading newline then the <name> block,
// with no trailing newline so the original file's trailing bytes survive.
func buildProviderValueBody(name string, valueLines []string, subCol, valCol int) string {
	var b strings.Builder
	b.WriteString("\n")
	writeProviderSubkey(&b, name, valueLines, subCol, valCol)
	return b.String()
}

// writeProviderSubkey writes "<name>:\n" at subCol followed by each value line at
// valCol. Value lines are joined by newlines with no trailing newline; the caller
// adds the terminating newline (matching insertBlockSubkey).
func writeProviderSubkey(b *strings.Builder, name string, valueLines []string, subCol, valCol int) {
	b.WriteString(strings.Repeat(" ", subCol))
	b.WriteString(name)
	b.WriteString(":\n")
	for i, ln := range valueLines {
		b.WriteString(strings.Repeat(" ", valCol))
		b.WriteString(ln)
		if i < len(valueLines)-1 {
			b.WriteString("\n")
		}
	}
}

type yamlMapping struct {
	values  []*ast.MappingValueNode
	flow    *ast.MappingNode
	wrapped bool
}

func yamlNodeValue(n ast.Node) ast.Node {
	for {
		switch v := n.(type) {
		case *ast.AnchorNode:
			n = v.Value
		case *ast.TagNode:
			n = v.Value
		default:
			return n
		}
	}
}

func asYAMLMapping(n ast.Node) (yamlMapping, bool) {
	inner := yamlNodeValue(n)
	switch v := inner.(type) {
	case *ast.MappingNode:
		m := yamlMapping{values: v.Values, wrapped: inner != n}
		if v.IsFlowStyle {
			m.flow = v
		}
		return m, true
	case *ast.MappingValueNode:
		return yamlMapping{values: []*ast.MappingValueNode{v}, wrapped: inner != n}, true
	default:
		return yamlMapping{}, false
	}
}

func findOpenRouterEntry(data []byte) (yamlMapping, bool, error) {
	doc, err := parser.ParseBytes(data, parser.ParseComments)
	if err != nil {
		return yamlMapping{}, false, err
	}
	vals, err := rootValues(doc)
	if err != nil {
		return yamlMapping{}, false, err
	}
	provMV := findMV(vals, providerKey)
	if provMV == nil {
		return yamlMapping{}, false, nil
	}
	prov, ok := asYAMLMapping(provMV.Value)
	if !ok {
		return yamlMapping{}, false, nil
	}
	entryMV := findMV(prov.values, openRouterProviderID)
	if entryMV == nil {
		return yamlMapping{}, false, nil
	}
	entry, ok := asYAMLMapping(entryMV.Value)
	if !ok {
		return yamlMapping{}, false, fmt.Errorf("config.RewriteKey: provider.openrouter is not a mapping (got %T)", entryMV.Value)
	}
	entry.wrapped = entry.wrapped || prov.wrapped
	return entry, true, nil
}

func readOpenRouterEntry(r *settingsRewrite) ([]byte, yamlMapping, fsutil.AtomicWriteStep, fserrors.Category, error) {
	data, exists, step, cat, err := r.read()
	if err != nil {
		return nil, yamlMapping{}, step, cat, err
	}
	if !exists {
		return nil, yamlMapping{}, fsutil.LoadStep, "", errNoOpenRouterEntry
	}
	entry, found, err := findOpenRouterEntry(data)
	if err != nil {
		return nil, yamlMapping{}, fsutil.LoadStep, "", err
	}
	if !found {
		return nil, yamlMapping{}, fsutil.LoadStep, "", errNoOpenRouterEntry
	}
	return data, entry, "", "", nil
}

func childMapping(parent yamlMapping, mv *ast.MappingValueNode) (yamlMapping, bool) {
	m, ok := asYAMLMapping(mv.Value)
	m.wrapped = m.wrapped || parent.wrapped
	return m, ok
}

func findOpenRouterMapping(data []byte, path ...string) (yamlMapping, error) {
	m, found, err := findOpenRouterEntry(data)
	if err != nil {
		return yamlMapping{}, err
	}
	if !found {
		return yamlMapping{}, errNoOpenRouterEntry
	}
	for _, key := range path {
		mv := findMV(m.values, key)
		if mv == nil {
			return yamlMapping{}, fmt.Errorf("config.RewriteKey: provider.openrouter has no %s mapping", key)
		}
		var ok bool
		if m, ok = childMapping(m, mv); !ok {
			return yamlMapping{}, fmt.Errorf("config.RewriteKey: provider.openrouter %s is not a mapping (got %T)", key, mv.Value)
		}
	}
	return m, nil
}

func setOpenRouterRouting(r *settingsRewrite, field, value string) (fsutil.AtomicWriteStep, fserrors.Category, error) {
	data, entry, step, cat, err := readOpenRouterEntry(r)
	if err != nil {
		return step, cat, err
	}
	remove := field == "sort" && value == routingSortDefault
	rendered, err := renderFlowValue(value)
	if err != nil {
		return fsutil.LoadStep, "", err
	}

	routingMV := findMV(entry.values, routingKey)
	var body []byte
	switch {
	case routingMV == nil && remove:
		return "", "", nil
	case routingMV == nil:
		body, err = insertMappingEntry(data, entry, []string{routingKey + ":", "  " + field + ": " + rendered}, routingKey+": {"+field+": "+rendered+"}")
	default:
		routing, ok := asYAMLMapping(routingMV.Value)
		if !ok {
			return fsutil.LoadStep, "", fmt.Errorf("config.RewriteKey: provider.openrouter.routing is not a mapping (got %T)", routingMV.Value)
		}
		target := findMV(routing.values, field)
		switch {
		case remove && target == nil:
			return "", "", nil
		case remove && len(routing.values) == 1:
			body, err = removeEmptyMappingEntry(data, entry, routingMV)
		case remove:
			body, err = removeMappingEntry(data, routing, target)
		case target != nil && target.Value.Type() == ast.LiteralType:
			body = replaceBlockScalar(data, target, rendered)
		default:
			body, err = setMappingScalar(data, routing, field, rendered)
		}
	}
	if err != nil {
		return fsutil.LoadStep, "", err
	}
	return validateAndPublish(r, body)
}

func setOpenRouterMaxPrice(r *settingsRewrite, model string, p provider.MaxPrice) (fsutil.AtomicWriteStep, fserrors.Category, error) {
	data, entry, step, cat, err := readOpenRouterEntry(r)
	if err != nil {
		return step, cat, err
	}
	var routing, prices yamlMapping
	var pricesMV, modelMV *ast.MappingValueNode
	routingMV := findMV(entry.values, routingKey)
	if routingMV != nil {
		var ok bool
		if routing, ok = childMapping(entry, routingMV); !ok {
			return fsutil.LoadStep, "", fmt.Errorf("config.RewriteKey: provider.openrouter.routing is not a mapping (got %T)", routingMV.Value)
		}
		pricesMV = findMV(routing.values, maxPriceKey)
	}
	if pricesMV != nil {
		var ok bool
		if prices, ok = childMapping(routing, pricesMV); !ok {
			return fsutil.LoadStep, "", fmt.Errorf("config.RewriteKey: provider.openrouter.routing.max_price is not a mapping (got %T)", pricesMV.Value)
		}
		modelMV = findMV(prices.values, model)
	}

	remove := !p.HasPrompt && !p.HasCompletion
	line := strconv.Quote(model) + ": {" + strings.Join(maxPriceFields(p), ", ") + "}"
	var body []byte
	switch {
	case modelMV == nil && remove:
		return "", "", nil
	case routingMV == nil:
		body, err = insertMappingEntry(data, entry, []string{routingKey + ":", "  " + maxPriceKey + ":", "    " + line}, routingKey+": {"+maxPriceKey+": {"+line+"}}")
	case pricesMV == nil:
		body, err = insertMappingEntry(data, routing, []string{maxPriceKey + ":", "  " + line}, maxPriceKey+": {"+line+"}")
	case modelMV == nil:
		body, err = insertMappingEntry(data, prices, []string{line}, line)
	case !remove:
		body, err = setMaxPriceFields(data, model, p)
	case len(prices.values) > 1:
		body, err = removeMappingEntry(data, prices, modelMV)
	case len(routing.values) > 1:
		body, err = removeEmptyMappingEntry(data, routing, pricesMV, routingKey)
	default:
		body, err = removeEmptyMappingEntry(data, entry, routingMV)
	}
	if err != nil {
		return fsutil.LoadStep, "", err
	}
	return validateAndPublish(r, body)
}

func maxPriceFields(p provider.MaxPrice) []string {
	var fields []string
	if p.HasPrompt {
		fields = append(fields, "prompt: "+strconv.FormatFloat(p.Prompt, 'f', -1, 64))
	}
	if p.HasCompletion {
		fields = append(fields, "completion: "+strconv.FormatFloat(p.Completion, 'f', -1, 64))
	}
	return fields
}

// Fields are set before any is removed so the model's mapping never becomes empty mid-edit.
func setMaxPriceFields(data []byte, model string, p provider.MaxPrice) ([]byte, error) {
	type field struct {
		name  string
		set   bool
		value float64
	}
	fields := []field{{"prompt", p.HasPrompt, p.Prompt}, {"completion", p.HasCompletion, p.Completion}}
	if !p.HasPrompt {
		fields[0], fields[1] = fields[1], fields[0]
	}
	for _, f := range fields {
		m, err := findOpenRouterMapping(data, routingKey, maxPriceKey, model)
		if err != nil {
			return nil, err
		}
		mv := findMV(m.values, f.name)
		switch {
		case f.set:
			data, err = setMappingScalar(data, m, f.name, strconv.FormatFloat(f.value, 'f', -1, 64))
		case mv != nil:
			data, err = removeMappingEntry(data, m, mv)
		}
		if err != nil {
			return nil, err
		}
	}
	return data, nil
}

func mergeOpenRouterConnection(data, valueYAML []byte) ([]byte, bool, error) {
	var fields yaml.MapSlice
	if err := yaml.Unmarshal(valueYAML, &fields); err != nil {
		return nil, false, errors.New("config.RewriteKey: decode provider entry value failed")
	}
	for _, f := range fields {
		key, ok := f.Key.(string)
		if !ok {
			return nil, false, fmt.Errorf("config.RewriteKey: provider entry key %v is not a string", f.Key)
		}
		entry, found, err := findOpenRouterEntry(data)
		if err != nil {
			return nil, false, err
		}
		if !found {
			return nil, false, nil
		}
		rendered, err := renderFlowValue(f.Value)
		if err != nil {
			return nil, false, err
		}
		if data, err = setMappingScalar(data, entry, key, rendered); err != nil {
			return nil, false, err
		}
	}
	return data, true, nil
}

func validateAndPublish(r *settingsRewrite, body []byte) (fsutil.AtomicWriteStep, fserrors.Category, error) {
	if err := Validate(body, r.path); err != nil {
		return fsutil.LoadStep, "", fmt.Errorf("config.RewriteKey: provider.openrouter failed schema validation: %w", err)
	}
	return r.publish(body)
}

// The rendered value can hold the plaintext api key, so a marshal failure is reported statically.
func renderFlowValue(v any) (string, error) {
	b, err := yaml.MarshalWithOptions(v, yaml.Flow(true))
	if err != nil {
		return "", errors.New("config.RewriteKey: marshal provider entry value failed")
	}
	return strings.TrimSpace(string(b)), nil
}

func setMappingScalar(data []byte, m yamlMapping, key, rendered string) ([]byte, error) {
	mv := findMV(m.values, key)
	if mv == nil {
		return insertMappingEntry(data, m, []string{key + ": " + rendered}, key+": "+rendered)
	}
	if m.flow != nil {
		start, end, err := flowSubkeyValueRange(data, mv, m.flow)
		if err != nil {
			return nil, err
		}
		value := yamlNodeValue(mv.Value)
		if value != mv.Value {
			tok := value.GetToken()
			if tok == nil || tok.Position == nil {
				return nil, fmt.Errorf("config.RewriteKey: %s value has no position", key)
			}
			start = exactTokenOffset(data, tok)
		}
		return spliceBytes(data, start, end, flowValueReplacement(data, start, rendered)), nil
	}
	value := yamlNodeValue(mv.Value)
	switch value.(type) {
	case *ast.MappingNode, *ast.MappingValueNode, *ast.SequenceNode, *ast.NullNode, *ast.LiteralNode:
		return nil, fmt.Errorf("config.RewriteKey: %s is not a single-line scalar (got %T)", key, value)
	}
	_, properties, _ := nodeProperties(data, mv.Value)
	tok := value.GetToken()
	if tok == nil || tok.Position == nil {
		return nil, fmt.Errorf("config.RewriteKey: %s value has no position", key)
	}
	start := tokenOffset(data, tok)
	if properties != "" {
		start = exactTokenOffset(data, tok)
	}
	end := len(data)
	if i := bytes.IndexByte(data[start:], '\n'); i >= 0 {
		end = start + i
	}
	if c, _, ok := inlineKeyComment(data, start, end); ok {
		end = c
	}
	return spliceBytes(data, start, trimTrailingFlowSpace(data, start, end), rendered), nil
}

func insertMappingEntry(data []byte, m yamlMapping, blockLines []string, flowText string) ([]byte, error) {
	if m.flow != nil {
		if m.flow.End == nil || m.flow.End.Position == nil {
			return nil, errors.New("config.RewriteKey: flow mapping has no closing '}' token")
		}
		at := tokenOffset(data, m.flow.End)
		if m.wrapped {
			at = flowMappingEnd(data, tokenOffset(data, m.flow.Start))
		}
		sep := ""
		if len(m.values) > 0 {
			_, lastEnd, err := flowSubkeyValueRangeTo(data, m.values[len(m.values)-1], m.flow, at)
			if err != nil {
				return nil, err
			}
			sep = ", "
			if p := flowValueStart(data, lastEnd, at); p < at && data[p] == ',' {
				sep = ""
				if !isFlowSpace(data[at-1]) {
					sep = " "
				}
			}
		}
		return spliceBytes(data, at, at, sep+flowText), nil
	}
	keyTok := m.values[0].Key.GetToken()
	if keyTok == nil || keyTok.Position == nil {
		return nil, errors.New("config.RewriteKey: mapping key has no position")
	}
	indent := strings.Repeat(" ", keyTok.Position.Column-1)
	at := lineEndAfter(data, subtreeEnd(data, m.values[len(m.values)-1]))
	var b strings.Builder
	if at > 0 && data[at-1] != '\n' {
		b.WriteByte('\n')
	}
	for _, ln := range blockLines {
		b.WriteString(indent)
		b.WriteString(ln)
		b.WriteByte('\n')
	}
	return spliceBytes(data, at, at, b.String()), nil
}

func removeEmptyMappingEntry(data []byte, parent yamlMapping, mv *ast.MappingValueNode, parentPath ...string) ([]byte, error) {
	value, ok := mv.Value.(*ast.MappingNode)
	if !ok {
		return removeMappingEntry(data, parent, mv)
	}
	var valueStart, valueEnd int
	if value.IsFlowStyle {
		if value.Start == nil || value.End == nil {
			return nil, errors.New("config.RewriteKey: flow mapping has no braces")
		}
		valueStart = tokenOffset(data, value.Start)
		valueEnd = tokenOffset(data, value.End) + len("}")
	} else {
		valueStart = lineEndAfter(data, tokenOffset(data, mv.Key.GetToken()))
		valueEnd = lineEndAfter(data, subtreeEnd(data, mv))
	}
	comments := mappingComments(data[valueStart:valueEnd])
	if parent.flow == nil {
		keyStart := tokenOffset(data, mv.Key.GetToken())
		if value.IsFlowStyle {
			comments = append(comments, mappingComments(data[valueEnd:lineEndAfter(data, valueEnd)])...)
		} else {
			comments = append(mappingComments(data[keyStart:valueStart]), comments...)
		}
	}
	if len(comments) == 0 {
		return removeMappingEntry(data, parent, mv)
	}
	if parent.flow == nil {
		start := startOfLine(data, tokenOffset(data, mv.Key.GetToken()))
		end := lineEndAfter(data, subtreeEnd(data, mv))
		indent := value.Values[0].Key.GetToken().Position.Column - 1
		if value.IsFlowStyle {
			indent = mv.Key.GetToken().Position.Column + 1
		}
		var kept strings.Builder
		for _, comment := range comments {
			kept.WriteString(strings.Repeat(" ", indent))
			kept.WriteString(strings.TrimSpace(comment.text))
			kept.WriteByte('\n')
		}
		return spliceBytes(data, start, end, kept.String()), nil
	}

	key := mappingKeyString(mv)
	body := spliceBytes(data, valueStart, valueEnd, "{}")
	parent, err := findOpenRouterMapping(body, parentPath...)
	if err != nil {
		return nil, err
	}
	target := findMV(parent.values, key)
	if target == nil {
		return nil, fmt.Errorf("config.RewriteKey: %s disappeared during comment preservation", key)
	}
	body, err = removeMappingEntry(body, parent, target)
	if err != nil {
		return nil, err
	}
	if parent, err = findOpenRouterMapping(body, parentPath...); err != nil {
		return nil, err
	}
	if parent.flow == nil || parent.flow.End == nil {
		return nil, fmt.Errorf("config.RewriteKey: the mapping holding %s changed style during comment preservation", key)
	}
	var moved strings.Builder
	for i, comment := range comments {
		if i == 0 {
			moved.WriteByte(' ')
		}
		moved.WriteString(strings.TrimRight(comment.text, "\r\n"))
		moved.WriteByte('\n')
	}
	at := tokenOffset(body, parent.flow.End)
	return spliceBytes(body, at, at, moved.String()), nil
}

type mappingComment struct {
	text string
}

func mappingComments(data []byte) []mappingComment {
	var comments []mappingComment
	for _, tok := range lexer.Tokenize(string(data)) {
		if tok.Type == token.CommentType {
			comments = append(comments, mappingComment{text: tok.Origin})
		}
	}
	return comments
}

func removeMappingEntry(data []byte, m yamlMapping, mv *ast.MappingValueNode) ([]byte, error) {
	if m.flow == nil {
		start := startOfLine(data, tokenOffset(data, mv.Key.GetToken()))
		end := lineEndAfter(data, subtreeEnd(data, mv))
		comments := mappingComments(data[start:end])
		if len(comments) == 0 {
			return spliceBytes(data, start, end, ""), nil
		}
		indent := mv.Key.GetToken().Position.Column - 1
		var kept strings.Builder
		for _, comment := range comments {
			kept.WriteString(strings.Repeat(" ", indent))
			kept.WriteString(strings.TrimRight(comment.text, "\r\n"))
			kept.WriteByte('\n')
		}
		return spliceBytes(data, start, end, kept.String()), nil
	}
	if len(m.values) == 1 {
		if m.flow.Start == nil || m.flow.End == nil {
			return nil, errors.New("config.RewriteKey: flow mapping has no braces")
		}
		start, end := tokenOffset(data, m.flow.Start)+1, tokenOffset(data, m.flow.End)
		return spliceBytes(data, start, end, flowKeptComments(data, start, end)), nil
	}
	idx := indexInValues(m.values, mv)
	keyStart := tokenOffset(data, mv.Key.GetToken())
	_, end, err := flowSubkeyValueRange(data, mv, m.flow)
	if err != nil {
		return nil, err
	}
	kept := flowKeptComments(data, keyStart, end)
	if idx == 0 {
		next := tokenOffset(data, m.values[1].Key.GetToken())
		comma := flowValueStart(data, end, next)
		if comma >= next || data[comma] != ',' {
			return nil, errors.New("config.RewriteKey: flow mapping entry has no ',' separator")
		}
		if bytes.IndexByte(data[end:next], '#') < 0 {
			return spliceBytes(data, keyStart, next, kept), nil
		}
		return spliceBytes(spliceBytes(data, comma, comma+1, ""), keyStart, end, kept), nil
	}
	_, prevEnd, err := flowSubkeyValueRange(data, m.values[idx-1], m.flow)
	if err != nil {
		return nil, err
	}
	comma := flowValueStart(data, prevEnd, keyStart)
	if comma >= keyStart || data[comma] != ',' {
		return nil, errors.New("config.RewriteKey: flow mapping entry has no ',' separator")
	}
	if bytes.IndexByte(data[comma:keyStart], '#') < 0 {
		return spliceBytes(data, comma, end, kept), nil
	}
	return spliceBytes(spliceBytes(data, keyStart, end, kept), comma, comma+1, ""), nil
}

// A comment runs to the end of its line, so the text after each kept comment resumes on a new line
// at the indentation the removed range ended on.
func flowKeptComments(data []byte, start, end int) string {
	comments := mappingComments(data[start:end])
	if len(comments) == 0 {
		return ""
	}
	line := data[startOfLine(data, end):end]
	indent := string(line[:len(line)-len(bytes.TrimLeft(line, " "))])
	var b strings.Builder
	b.WriteByte(' ')
	for _, comment := range comments {
		b.WriteString(strings.TrimSpace(comment.text))
		b.WriteByte('\n')
		b.WriteString(indent)
	}
	return b.String()
}

func subtreeEnd(data []byte, n ast.Node) int {
	if inner := yamlNodeValue(n); inner != n {
		return subtreeEnd(data, inner)
	}
	switch v := n.(type) {
	case *ast.MappingNode:
		if v.IsFlowStyle || len(v.Values) == 0 {
			return tokenOffset(data, v.End)
		}
		return subtreeEnd(data, v.Values[len(v.Values)-1])
	case *ast.MappingValueNode:
		if v.Value.Type() == ast.LiteralType {
			return blockScalarLastLine(data, v)
		}
		return subtreeEnd(data, v.Value)
	case *ast.SequenceNode:
		if v.IsFlowStyle || len(v.Values) == 0 {
			return tokenOffset(data, v.End)
		}
		return subtreeEnd(data, v.Values[len(v.Values)-1])
	default:
		return tokenOffset(data, n.GetToken())
	}
}

func blockScalarLastLine(data []byte, mv *ast.MappingValueNode) int {
	header := tokenOffset(data, mv.Value.GetToken())
	parent := tokenOffset(data, mv.Key.GetToken()) - startOfLine(data, tokenOffset(data, mv.Key.GetToken()))
	content := -1
	for i := header + 1; i < len(data) && i <= header+2; i++ {
		if c := data[i]; c >= '1' && c <= '9' {
			content = parent + int(c-'0')
		}
	}
	last := header
	for pos := lineEndAfter(data, header); pos < len(data); pos = lineEndAfter(data, pos) {
		line := data[pos:lineEndAfter(data, pos)]
		text := bytes.TrimLeft(line, " ")
		if len(bytes.TrimSpace(text)) == 0 {
			continue
		}
		indent := len(line) - len(text)
		if content < 0 {
			if indent <= parent {
				break
			}
			content = indent
		}
		if indent < content {
			break
		}
		last = pos
	}
	return last
}

func replaceBlockScalar(data []byte, mv *ast.MappingValueNode, rendered string) []byte {
	header := tokenOffset(data, mv.Value.GetToken())
	headerEnd := lineEndAfter(data, header)
	if headerEnd > header && data[headerEnd-1] == '\n' {
		headerEnd--
	}
	contentEnd := headerEnd
	if last := blockScalarLastLine(data, mv); last != header {
		contentEnd = lineEndAfter(data, last)
		if data[contentEnd-1] == '\n' {
			contentEnd--
		}
	}
	valueEnd := headerEnd
	if c, _, ok := inlineKeyComment(data, header, headerEnd); ok {
		valueEnd = c
	}
	out := spliceBytes(data, headerEnd, contentEnd, "")
	return spliceBytes(out, header, trimTrailingFlowSpace(out, header, valueEnd), rendered)
}

func lineEndAfter(data []byte, offset int) int {
	if i := bytes.IndexByte(data[offset:], '\n'); i >= 0 {
		return offset + i + 1
	}
	return len(data)
}

func rewriteModelFavorites(r *settingsRewrite, op *favoriteToggleValue) (fsutil.AtomicWriteStep, fserrors.Category, error) {
	if op == nil || !op.prepared {
		return fsutil.LoadStep, "", errors.New("config.RewriteKey: model.favorites payload was not prepared under the settings lock")
	}
	if op.target.Provider == "" || op.target.ID == "" {
		return fsutil.LoadStep, "", fmt.Errorf("config.RewriteKey: model.favorites target needs a non-empty provider and id, got %+v", op.target)
	}
	if slices.Equal(op.source, op.next) {
		return "", "", nil
	}

	data, exists, step, cat, rerr := r.read()
	if rerr != nil {
		return step, cat, rerr
	}
	if !exists || len(bytes.TrimSpace(data)) == 0 {
		valueLines, mErr := favoritesValueLines(op.next, nil)
		if mErr != nil {
			return fsutil.LoadStep, "", mErr
		}
		return r.publish([]byte(buildFavoritesBlock(valueLines, 0)))
	}

	doc, perr := parser.ParseBytes(data, parser.ParseComments)
	if perr != nil {
		return fsutil.LoadStep, fserrors.IOError, perr
	}
	vals, verr := rootValues(doc)
	if verr != nil {
		return fsutil.LoadStep, "", verr
	}
	modelMV := findMV(vals, "model")
	if modelMV == nil {
		valueLines, mErr := favoritesValueLines(op.next, nil)
		if mErr != nil {
			return fsutil.LoadStep, "", mErr
		}
		return r.publish(appendBlockAtEnd(data, buildFavoritesBlock(valueLines, 0)))
	}

	body, sErr := insertOrReplaceFavoritesUnderModel(data, modelMV, vals, op.source, op.next)
	if sErr != nil {
		return fsutil.LoadStep, "", sErr
	}
	return r.publish(body)
}

func insertOrReplaceFavoritesUnderModel(data []byte, modelMV *ast.MappingValueNode, rootSiblings []*ast.MappingValueNode, source, next []Favorite) ([]byte, error) {
	modelIdx := indexInValues(rootSiblings, modelMV)
	keyTok := modelMV.Key.GetToken()
	if keyTok == nil || keyTok.Position == nil {
		return nil, errors.New("config.RewriteKey: model key has no position")
	}
	modelKeyCol := keyTok.Position.Column - 1
	subCol := modelKeyCol + 2
	valCol := modelKeyCol + 4

	modelValue, _, modelPropsEnd := nodeProperties(data, modelMV.Value)

	switch v := modelValue.(type) {
	case *ast.MappingNode:
		if v.IsFlowStyle {
			if subMV, _ := findSubMV(v.Values, favoritesSub); subMV != nil {
				if name, orphaned := removalOrphansAlias(data, subMV.Value, rootSiblings, source, next); orphaned {
					return nil, fmt.Errorf("config.RewriteKey: removing a model.favorites entry drops anchor &%s referenced by an unchanged alias; refusing to publish an undefined YAML alias", name)
				}
				_, flowEntries := favoriteEntryRepresentations(data, subMV.Value, source, next, 0, 0)
				flowValue, fErr := favoritesFlowValue(next, flowEntries)
				if fErr != nil {
					return nil, fErr
				}
				start, end, rErr := flowSubkeyValueRange(data, subMV, v)
				if rErr != nil {
					return nil, rErr
				}
				value := flowValue
				if _, props, _ := nodeProperties(data, subMV.Value); props != "" {
					value = props + " " + value
				}
				return spliceBytes(data, start, end, flowValueReplacement(data, start, value)), nil
			}
			if v.End == nil || v.End.Position == nil {
				return nil, errors.New("config.RewriteKey: flow model has no closing '}' token")
			}
			flowValue, fErr := favoritesFlowValue(next, nil)
			if fErr != nil {
				return nil, fErr
			}
			sep := ", "
			if len(v.Values) == 0 {
				sep = ""
			}
			endPos := tokenOffset(data, v.End)
			return spliceBytes(data, endPos, endPos, sep+favoritesSub+": "+flowValue), nil
		}
		if subMV, _ := findSubMV(v.Values, favoritesSub); subMV != nil {
			if name, orphaned := removalOrphansAlias(data, subMV.Value, rootSiblings, source, next); orphaned {
				return nil, fmt.Errorf("config.RewriteKey: removing a model.favorites entry drops anchor &%s referenced by an unchanged alias; refusing to publish an undefined YAML alias", name)
			}
			start, end := blockSubkeyValueRange(data, subMV, v.Values, rootSiblings, modelIdx)
			blockEntries, _ := favoriteEntryRepresentations(data, subMV.Value, source, next, valCol, end)
			valueLines, mErr := favoritesValueLines(next, blockEntries)
			if mErr != nil {
				return nil, mErr
			}
			var anchor string
			if _, props, _ := nodeProperties(data, subMV.Value); props != "" {
				anchor = " " + props
			}
			if cStart, cEnd, ok := inlineKeyComment(data, start, end); ok {
				kept := anchor + " " + string(data[cStart:cEnd])
				return spliceBytes(data, start, end, kept+favoritesIndentedValue(valueLines, valCol)), nil
			}
			return spliceBytes(data, start, end, anchor+favoritesBlockValue(valueLines, valCol)), nil
		}
		valueLines, mErr := favoritesValueLines(next, nil)
		if mErr != nil {
			return nil, mErr
		}
		return insertFavoritesBlockSubkey(data, modelMV, rootSiblings, modelIdx, v, valueLines, subCol, valCol), nil
	case *ast.NullNode, nil:
		valueLines, mErr := favoritesValueLines(next, nil)
		if mErr != nil {
			return nil, mErr
		}
		start, end := valueRangeAfterColon(data, modelMV, rootSiblings, modelIdx)
		if modelPropsEnd > start {
			start = modelPropsEnd
		}
		if end < start {
			end = start
		}
		return spliceBytes(data, start, end, buildFavoritesValueBody(valueLines, subCol, valCol)), nil
	default:
		return nil, fmt.Errorf("config.RewriteKey: model: value has unsupported shape %T", v)
	}
}

func insertFavoritesBlockSubkey(data []byte, modelMV *ast.MappingValueNode, rootSiblings []*ast.MappingValueNode, modelIdx int, modelMap *ast.MappingNode, valueLines []string, subCol, valCol int) []byte {
	if len(modelMap.Values) == 0 {
		start, e := valueRangeAfterColon(data, modelMV, rootSiblings, modelIdx)
		return spliceBytes(data, start, e, buildFavoritesValueBody(valueLines, subCol, valCol))
	}
	end := blockEnd(data, rootSiblings, modelIdx)
	insertAt, needNL := appendInsertionPoint(data, end)
	var rep strings.Builder
	if needNL {
		rep.WriteString("\n")
	}
	writeFavoritesSubkey(&rep, valueLines, subCol, valCol)
	return spliceBytes(data, insertAt, insertAt, rep.String())
}

func buildFavoritesBlock(valueLines []string, keyCol int) string {
	var b strings.Builder
	b.WriteString(strings.Repeat(" ", keyCol))
	b.WriteString("model:\n")
	writeFavoritesSubkey(&b, valueLines, keyCol+2, keyCol+4)
	return b.String()
}

func buildFavoritesValueBody(valueLines []string, subCol, valCol int) string {
	var b strings.Builder
	b.WriteString("\n")
	writeFavoritesSubkey(&b, valueLines, subCol, valCol)
	return strings.TrimRight(b.String(), "\n")
}

func writeFavoritesSubkey(b *strings.Builder, valueLines []string, subCol, valCol int) {
	b.WriteString(strings.Repeat(" ", subCol))
	b.WriteString(favoritesSub)
	b.WriteString(":")
	b.WriteString(favoritesBlockValue(valueLines, valCol))
	b.WriteString("\n")
}

func favoritesBlockValue(valueLines []string, valCol int) string {
	if len(valueLines) == 0 {
		return " []"
	}
	var b strings.Builder
	for _, ln := range valueLines {
		b.WriteString("\n")
		b.WriteString(strings.Repeat(" ", valCol))
		b.WriteString(ln)
	}
	return b.String()
}

func inlineKeyComment(data []byte, start, end int) (int, int, bool) {
	if start < 0 || end > len(data) || start >= end {
		return 0, 0, false
	}
	lineEnd := end
	if i := bytes.IndexByte(data[start:end], '\n'); i >= 0 {
		lineEnd = start + i
	}
	var quote byte
	for i := start; i < lineEnd; i++ {
		c := data[i]
		switch {
		case quote == '"' && c == '\\':
			i++
		case quote != 0:
			if c == quote {
				quote = 0
			}
		case c == '\'' || c == '"':
			quote = c
		case c == '#' && (i == start || data[i-1] == ' ' || data[i-1] == '\t'):
			return i, lineEnd, true
		}
	}
	return 0, 0, false
}

func nodeProperties(data []byte, v ast.Node) (ast.Node, string, int) {
	var parts []string
	end := -1
	for {
		switch n := v.(type) {
		case *ast.TagNode:
			if n == nil || n.Start == nil || n.Start.Position == nil {
				return v, strings.Join(parts, " "), end
			}
			parts = append(parts, n.Start.Value)
			end = tokenOffset(data, n.Start) + len(n.Start.Value)
			v = n.Value
		case *ast.AnchorNode:
			if n == nil || n.Name == nil {
				return v, strings.Join(parts, " "), end
			}
			tok := n.Name.GetToken()
			if tok == nil || tok.Position == nil {
				return v, strings.Join(parts, " "), end
			}
			parts = append(parts, "&"+tok.Value)
			end = tokenOffset(data, tok) + len(tok.Value)
			v = n.Value
		default:
			return v, strings.Join(parts, " "), end
		}
	}
}

func favoritesIndentedValue(valueLines []string, valCol int) string {
	if len(valueLines) == 0 {
		return "\n" + strings.Repeat(" ", valCol) + "[]"
	}
	return favoritesBlockValue(valueLines, valCol)
}

func favoriteEntryRepresentations(data []byte, value ast.Node, source, next []Favorite, valCol, blockEnd int) ([][]string, []string) {
	inner, _, _ := nodeProperties(data, value)
	sequence, ok := inner.(*ast.SequenceNode)
	if !ok || len(sequence.Values) != len(source) {
		return nil, nil
	}
	blockEntries := make([][]string, len(next))
	flowEntries := make([]string, len(next))
	matched := make([]bool, len(next))
	for i, favorite := range source {
		for j, replacement := range next {
			if matched[j] || favorite != replacement {
				continue
			}
			isFlow := sequence.IsFlowStyle || (sequence.Start != nil && (sequence.Start.Value == "[" || sequence.Start.Origin == "["))
			if isFlow {
				_, properties, _ := nodeProperties(data, sequence.Values[i])
				start, end, ok := flowFavoriteEntryRange(data, sequence, i)
				if !ok {
					break
				}
				entry := string(data[start:end])
				if properties != "" {
					entry = properties + " " + entry
				}
				flowEntries[j] = entry
			} else {
				start := seqEntryLeadingEdge(data, sequence, i)
				end := blockEnd
				if i+1 < len(sequence.Values) {
					end = seqEntryLeadingEdge(data, sequence, i+1)
				}
				if end <= start {
					break
				}
				entry := strings.TrimRight(string(data[start:end]), " \t\r\n")
				lines := strings.Split(entry, "\n")
				indent := strings.Repeat(" ", valCol)
				for k, line := range lines {
					lines[k] = strings.TrimPrefix(line, indent)
				}
				blockEntries[j] = lines
			}
			matched[j] = true
			break
		}
	}
	return blockEntries, flowEntries
}

func flowFavoriteEntryRange(data []byte, sequence *ast.SequenceNode, index int) (int, int, bool) {
	if sequence.Start == nil || sequence.Start.Position == nil {
		return 0, 0, false
	}
	start := tokenOffset(data, sequence.Start) + 1
	end := len(data)
	entry := 0
	depth := 0
	var quote byte
	for i := start; i < end; i++ {
		c := data[i]
		switch {
		case quote == '"' && c == '\\':
			i++
		case quote != 0:
			if c == quote {
				quote = 0
			}
		case c == '\'' || c == '"':
			quote = c
		case c == '{':
			if depth == 0 && entry == index {
				return i, flowValueEnd(data, i, end), true
			}
			depth++
		case c == '}' && depth > 0:
			depth--
		case c == ',' && depth == 0:
			entry++
		}
	}
	return 0, 0, false
}

func removalOrphansAlias(data []byte, favoritesValue ast.Node, rootSiblings []*ast.MappingValueNode, source, next []Favorite) (string, bool) {
	removed := removedFavoriteAnchorNames(data, favoritesValue, source, next)
	if len(removed) == 0 {
		return "", false
	}
	referenced := aliasNamesOutside(rootSiblings, favoritesValue)
	for _, name := range removed {
		if referenced[name] {
			return name, true
		}
	}
	return "", false
}

func removedFavoriteAnchorNames(data []byte, favoritesValue ast.Node, source, next []Favorite) []string {
	inner, _, _ := nodeProperties(data, favoritesValue)
	sequence, ok := inner.(*ast.SequenceNode)
	if !ok || len(sequence.Values) != len(source) {
		return nil
	}
	matched := make([]bool, len(next))
	var names []string
	for i, favorite := range source {
		found := false
		for j, replacement := range next {
			if matched[j] || favorite != replacement {
				continue
			}
			matched[j] = true
			found = true
			break
		}
		if !found {
			names = append(names, anchorNamesInSubtree(sequence.Values[i])...)
		}
	}
	return names
}

func anchorNamesInSubtree(node ast.Node) []string {
	if node == nil {
		return nil
	}
	c := &anchorNameCollector{}
	ast.Walk(c, node)
	return c.names
}

func aliasNamesOutside(rootSiblings []*ast.MappingValueNode, skip ast.Node) map[string]bool {
	c := &aliasNameCollector{names: map[string]bool{}, skip: skip}
	for _, mv := range rootSiblings {
		if mv == nil {
			continue
		}
		ast.Walk(c, mv)
	}
	return c.names
}

type anchorNameCollector struct{ names []string }

func (c *anchorNameCollector) Visit(n ast.Node) ast.Visitor {
	if a, ok := n.(*ast.AnchorNode); ok && a.Name != nil {
		if tok := a.Name.GetToken(); tok != nil {
			c.names = append(c.names, tok.Value)
		}
	}
	return c
}

type aliasNameCollector struct {
	names map[string]bool
	skip  ast.Node
}

func (c *aliasNameCollector) Visit(n ast.Node) ast.Visitor {
	if n == nil {
		return c
	}
	if c.skip != nil && n == c.skip {
		return nil
	}
	if a, ok := n.(*ast.AliasNode); ok && a.Value != nil {
		if tok := a.Value.GetToken(); tok != nil {
			c.names[tok.Value] = true
		}
	}
	return c
}

func favoriteItems(favs []Favorite) []yaml.MapSlice {
	items := make([]yaml.MapSlice, 0, len(favs))
	for _, f := range favs {
		items = append(items, yaml.MapSlice{
			{Key: "provider", Value: f.Provider},
			{Key: "id", Value: f.ID},
		})
	}
	return items
}

func favoritesValueLines(favs []Favorite, entries [][]string) ([]string, error) {
	if len(favs) == 0 {
		return nil, nil
	}
	b, err := yaml.Marshal(favoriteItems(favs))
	if err != nil {
		return nil, fmt.Errorf("config.RewriteKey: marshal model.favorites value: %w", err)
	}
	lines := strings.Split(strings.TrimRight(string(b), "\n"), "\n")
	withEntries := make([]string, 0, len(lines)+len(entries))
	entry := 0
	for i := 0; i < len(lines); {
		if !strings.HasPrefix(lines[i], "- ") {
			withEntries = append(withEntries, lines[i])
			i++
			continue
		}
		end := i + 1
		for end < len(lines) && !strings.HasPrefix(lines[end], "- ") {
			end++
		}
		if entry < len(entries) && len(entries[entry]) > 0 {
			withEntries = append(withEntries, entries[entry]...)
		} else {
			withEntries = append(withEntries, lines[i:end]...)
		}
		entry++
		i = end
	}
	return withEntries, nil
}

func favoritesFlowValue(favs []Favorite, entries []string) (string, error) {
	if len(favs) == 0 {
		return "[]", nil
	}
	b, err := yaml.MarshalWithOptions(favoriteItems(favs), yaml.Flow(true))
	if err != nil {
		return "", fmt.Errorf("config.RewriteKey: marshal model.favorites flow value: %w", err)
	}
	value := strings.TrimSpace(string(b))
	start := 0
	for i := range favs {
		entry := strings.Index(value[start:], "{")
		if entry < 0 {
			break
		}
		entry += start
		if i < len(entries) && entries[i] != "" {
			end := flowValueEnd([]byte(value), entry, len(value))
			value = value[:entry] + entries[i] + value[end:]
			entry += len(entries[i])
		}
		start = entry + 1
	}
	return value, nil
}
