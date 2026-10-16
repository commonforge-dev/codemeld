package config

import (
	"bytes"
	"errors"
	"fmt"
	"reflect"
	"slices"
	"strconv"
	"strings"

	"github.com/goccy/go-yaml"
	"github.com/goccy/go-yaml/ast"
	"github.com/goccy/go-yaml/lexer"
	"github.com/goccy/go-yaml/parser"
	"github.com/goccy/go-yaml/token"

	"codemeld.dev/codemeld/internal/fserrors"
	"codemeld.dev/codemeld/internal/fsutil"
	"codemeld.dev/codemeld/internal/permissions"
)

type blockedPathRemoveValue struct {
	home       string
	path       string
	occurrence int
}

type blockedPathAddValue struct {
	home    string
	item    string
	heading string
}

func BlockedPathRemove(home, path string, occurrence int) any {
	return blockedPathRemoveValue{home: home, path: path, occurrence: occurrence}
}

func BlockedPathAdd(home, item, heading string) any {
	return blockedPathAddValue{home: home, item: item, heading: heading}
}

type blockedList struct {
	data     []byte
	mv       *ast.MappingValueNode
	seq      *ast.SequenceNode
	flowRoot *ast.MappingNode
	items    []any
	colon    int
	comments map[int]bool
	nl       string
	docEnd   int
}

func rewriteBlockedPaths(r *settingsRewrite, newValue any) (fsutil.AtomicWriteStep, fserrors.Category, error) {
	switch v := newValue.(type) {
	case blockedPathRemoveValue:
		return removeBlockedPath(r, v)
	case blockedPathAddValue:
		return addBlockedPath(r, v)
	default:
		return fsutil.LoadStep, "", fmt.Errorf("config.RewriteKey: %q requires a BlockedPathRemove or BlockedPathAdd payload, got %T", blockedPathsKey, newValue)
	}
}

func removeBlockedPath(r *settingsRewrite, v blockedPathRemoveValue) (fsutil.AtomicWriteStep, fserrors.Category, error) {
	data, exists, step, cat, err := r.read()
	if err != nil {
		return step, cat, err
	}
	if !exists {
		return "", "", nil
	}
	l, err := loadBlockedList(data)
	if err != nil {
		return fsutil.LoadStep, "", err
	}
	j, seen := -1, 0
	for i, item := range l.items {
		if blockedItemMatches(v.home, item, v.path) {
			if seen == v.occurrence {
				j = i
				break
			}
			seen++
		}
	}
	if j < 0 {
		return "", "", nil
	}
	body, err := l.remove(j)
	if err != nil {
		return fsutil.LoadStep, "", err
	}
	return publishBlockedList(r, body, slices.Delete(slices.Clone(l.items), j, j+1))
}

func addBlockedPath(r *settingsRewrite, v blockedPathAddValue) (fsutil.AtomicWriteStep, fserrors.Category, error) {
	expanded, err := permissions.ExpandBlockedEntry(v.home, v.item)
	if err != nil {
		return fsutil.LoadStep, "", fmt.Errorf("config.RewriteKey: %w", err)
	}
	quoted := strconv.Quote(v.item)
	data, exists, step, cat, err := r.read()
	if err != nil {
		return step, cat, err
	}
	if !exists {
		return publishBlockedList(r, []byte(blockedPathsKey+":\n  - "+quoted+"\n"), []any{v.item})
	}
	l, err := loadBlockedList(data)
	if err != nil {
		return fsutil.LoadStep, "", err
	}
	for _, item := range l.items {
		if blockedItemMatches(v.home, item, expanded) {
			return "", "", nil
		}
	}
	if l.mv == nil {
		if l.flowRoot != nil {
			pos := l.flowTailEnd(tokenOffset(data, l.flowRoot.End))
			sep := ""
			if data[pos-1] == ',' {
				sep = " "
			} else if len(l.flowRoot.Values) > 0 {
				sep = ", "
			}
			return publishBlockedList(r, spliceBytes(data, pos, pos, sep+blockedPathsKey+": ["+quoted+"]"), append(l.items, v.item))
		}
		block := lineBreakBefore(data, l.docEnd, l.nl) + blockedPathsKey + ":" + l.nl + "  - " + quoted + l.nl
		return publishBlockedList(r, spliceBytes(data, l.docEnd, l.docEnd, block), append(l.items, v.item))
	}
	body, at, err := l.add(quoted, v.heading)
	if err != nil {
		return fsutil.LoadStep, "", err
	}
	return publishBlockedList(r, body, slices.Insert(slices.Clone(l.items), at, any(v.item)))
}

func loadBlockedList(data []byte) (*blockedList, error) {
	items, err := decodeBlockedItems(data)
	if err != nil {
		return nil, err
	}
	doc, err := parser.ParseBytes(data, parser.ParseComments)
	if err != nil {
		return nil, err
	}
	if len(doc.Docs) > 0 {
		if _, ok := doc.Docs[0].Body.(*ast.CommentGroupNode); ok {
			doc.Docs = nil
		}
	}
	vals, err := rootValues(doc)
	if err != nil {
		return nil, err
	}
	l := &blockedList{data: data, items: items, mv: findMV(vals, blockedPathsKey), comments: map[int]bool{}, nl: lineBreak(data), docEnd: len(data)}
	if len(doc.Docs) > 0 {
		if root, ok := doc.Docs[0].Body.(*ast.MappingNode); ok && root.IsFlowStyle {
			l.flowRoot = root
		}
		if end := doc.Docs[0].End; end != nil && end.Position != nil {
			l.docEnd = tokenOffset(data, end)
		}
	}
	for _, tk := range lexer.Tokenize(string(data)) {
		if tk.Type == token.CommentType {
			l.comments[tokenOffset(data, tk)] = true
		}
	}
	if l.mv == nil {
		return l, nil
	}
	if l.mv.Start == nil || l.mv.Start.Position == nil {
		return nil, errors.New("config.RewriteKey: blocked_paths key has no ':' position")
	}
	l.colon = tokenOffset(data, l.mv.Start)
	switch value := l.mv.Value.(type) {
	case *ast.SequenceNode:
		if len(value.Values) != len(items) {
			return nil, fmt.Errorf("config.RewriteKey: blocked_paths has %d nodes for %d items", len(value.Values), len(items))
		}
		for _, v := range value.Values {
			s, ok := v.(*ast.StringNode)
			if !ok || s.Token == nil || strings.ContainsAny(strings.TrimSpace(s.Token.Origin), "\r\n") {
				return nil, fmt.Errorf("config.RewriteKey: blocked_paths item is not a one-line scalar (got %T)", v)
			}
		}
		if value.IsFlowStyle && len(items) == 0 && l.hasComment(l.colon, lineEnd(data, tokenOffset(data, value.End))) {
			return nil, errors.New("config.RewriteKey: blocked_paths is an empty flow list with an inline comment")
		}
		l.seq = value
	default:
		return nil, fmt.Errorf("config.RewriteKey: blocked_paths is not a list (got %T)", value)
	}
	return l, nil
}

func decodeBlockedItems(data []byte) ([]any, error) {
	var raw map[string]any
	if err := yaml.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("config.RewriteKey: re-decode for blocked_paths: %w", err)
	}
	switch list := raw[blockedPathsKey].(type) {
	case nil:
		return nil, nil
	case []any:
		return list, nil
	default:
		return nil, fmt.Errorf("config.RewriteKey: blocked_paths is not a list (got %T)", list)
	}
}

func blockedItemMatches(home string, item any, path string) bool {
	s, ok := item.(string)
	if !ok {
		return false
	}
	expanded, err := permissions.ExpandBlockedEntry(home, s)
	return err == nil && expanded == path
}

func publishBlockedList(r *settingsRewrite, body []byte, want []any) (fsutil.AtomicWriteStep, fserrors.Category, error) {
	got, err := decodeBlockedItems(body)
	if err != nil {
		return fsutil.LoadStep, "", err
	}
	if len(got) != len(want) || (len(want) > 0 && !reflect.DeepEqual(got, want)) {
		return fsutil.LoadStep, "", errors.New("config.RewriteKey: blocked_paths edit did not produce the expected list")
	}
	return r.publish(body)
}

func (l *blockedList) remove(j int) ([]byte, error) {
	data := l.data
	if l.seq.IsFlowStyle {
		start, end, err := l.flowItem(j)
		if err != nil {
			return nil, err
		}
		open, closing := tokenOffset(data, l.seq.Start), tokenOffset(data, l.seq.End)
		if len(l.items) == 1 {
			if !bytes.ContainsAny(data[open:closing], "\r\n") {
				return spliceBytes(data, open, closing+1, "[]"), nil
			}
			cs, ce := flowRemovalRange(data, closing, closing+1)
			s, e := flowRemovalRange(data, start, withTrailingComma(data, end, closing))
			return spliceBytes(spliceBytes(spliceBytes(data, cs, ce, ""), s, e, ""), open+1, open+1, "]"), nil
		}
		if j < len(l.items)-1 {
			comma := l.skipFlowGap(end, closing)
			if comma >= closing || data[comma] != ',' {
				return nil, fmt.Errorf("config.RewriteKey: blocked_paths flow item %d has no ',' after it", j)
			}
			if skipFlowBlanks(data, end, closing) != comma {
				cs, ce := flowRemovalRange(data, comma, comma+1)
				s, e := flowRemovalRange(data, start, end)
				return spliceBytes(spliceBytes(data, cs, ce, ""), s, e, ""), nil
			}
			s, e := flowRemovalRange(data, start, comma+1)
			return spliceBytes(data, s, e, ""), nil
		}
		_, prevEnd, err := l.flowItem(j - 1)
		if err != nil {
			return nil, err
		}
		if !bytes.ContainsAny(data[prevEnd:start], "\r\n") {
			return spliceBytes(data, prevEnd, end, ""), nil
		}
		comma := l.skipFlowGap(prevEnd, start)
		if data[comma] != ',' {
			return nil, fmt.Errorf("config.RewriteKey: blocked_paths flow item %d has no ',' before it", j)
		}
		tail := withTrailingComma(data, end, closing)
		crossed := skipFlowBlanks(data, prevEnd, start) != comma
		if crossed && !l.hasComment(comma, closing) {
			s, e := flowRemovalRange(data, comma, tail)
			return spliceBytes(data, s, e, ""), nil
		}
		cs, ce := flowRemovalRange(data, closing, closing+1)
		s, e := flowRemovalRange(data, start, tail)
		body := spliceBytes(spliceBytes(data, cs, ce, ""), s, e, "")
		if !crossed {
			return spliceBytes(body, prevEnd, comma+1, "]"), nil
		}
		ks, ke := flowRemovalRange(data, comma, comma+1)
		return spliceBytes(spliceBytes(body, ks, ke, ""), prevEnd, prevEnd, "]"), nil
	}
	start, end, _, err := l.blockItem(j)
	if err != nil {
		return nil, err
	}
	body := spliceBytes(data, start, end, "")
	if len(l.items) == 1 {
		body = spliceBytes(body, l.colon+1, l.colon+1, " []")
	}
	return body, nil
}

func (l *blockedList) add(quoted, heading string) ([]byte, int, error) {
	data := l.data
	entry := "- " + quoted + l.nl
	keyTok := l.mv.Key.GetToken()
	if keyTok == nil || keyTok.Position == nil {
		return nil, 0, errors.New("config.RewriteKey: blocked_paths key has no position")
	}
	if len(l.items) == 0 {
		insertAt := lineEnd(data, l.colon)
		for p := insertAt; p < len(data); {
			next, _, content := lineAt(data, p)
			if !bytes.HasPrefix(content, []byte("#")) {
				break
			}
			if isHeadingLine(content, heading) {
				insertAt = next
				break
			}
			p = next
		}
		line := lineBreakBefore(data, insertAt, l.nl) + strings.Repeat(" ", keyTok.Position.Column+1) + entry
		if l.seq == nil {
			return spliceBytes(data, insertAt, insertAt, line), 0, nil
		}
		if l.flowRoot != nil {
			open := tokenOffset(data, l.seq.Start) + 1
			return spliceBytes(data, open, open, quoted), 0, nil
		}
		cs, ce := flowRemovalRange(data, tokenOffset(data, l.seq.End), tokenOffset(data, l.seq.End)+1)
		var body []byte
		if insertAt > cs {
			body = spliceBytes(spliceBytes(data, insertAt, insertAt, line), cs, ce, "")
		} else {
			body = spliceBytes(spliceBytes(data, cs, ce, ""), insertAt, insertAt, line)
		}
		return spliceBytes(body, l.colon+1, tokenOffset(data, l.seq.Start)+1, ""), 0, nil
	}
	if l.seq.IsFlowStyle {
		_, end, err := l.flowItem(len(l.items) - 1)
		if err != nil {
			return nil, 0, err
		}
		return spliceBytes(data, end, end, ", "+quoted), len(l.items), nil
	}
	starts := make([]int, len(l.items))
	ends := make([]int, len(l.items))
	dashCol := 0
	for i := range l.items {
		start, end, col, err := l.blockItem(i)
		if err != nil {
			return nil, 0, err
		}
		starts[i], ends[i] = start, end
		if i == 0 {
			dashCol = col
		}
	}
	regionEnd := ends[len(ends)-1]
	for regionEnd < len(data) {
		next, indent, content := lineAt(data, regionEnd)
		if !bytes.HasPrefix(content, []byte("#")) || indent < dashCol {
			break
		}
		regionEnd = next
	}
	pos, at := ends[len(ends)-1], len(l.items)
	k := 0
	for p := lineEnd(data, l.colon); p < regionEnd; {
		if k < len(starts) && p >= starts[k] {
			p = max(p, ends[k])
			k++
			continue
		}
		next, _, content := lineAt(data, p)
		if isHeadingLine(content, heading) {
			pos, at = next, k
			for at < len(starts) && !hasCommentLine(data[pos:starts[at]]) {
				pos = ends[at]
				at++
			}
			break
		}
		p = next
	}
	return spliceBytes(data, pos, pos, lineBreakBefore(data, pos, l.nl)+strings.Repeat(" ", dashCol)+entry), at, nil
}

func (l *blockedList) blockItem(j int) (start, end, dashCol int, err error) {
	if j >= len(l.seq.Entries) || l.seq.Entries[j] == nil || l.seq.Entries[j].Start == nil || l.seq.Entries[j].Start.Position == nil {
		return 0, 0, 0, fmt.Errorf("config.RewriteKey: blocked_paths item %d has no '-' position", j)
	}
	dash := tokenOffset(l.data, l.seq.Entries[j].Start)
	start = startOfLine(l.data, dash)
	dashCol = dash - start
	end = lineEnd(l.data, dash)
	for p := end; p < len(l.data); {
		next, indent, content := lineAt(l.data, p)
		if len(content) != 0 && !l.comments[p+indent] {
			if indent <= dashCol {
				break
			}
			end = next
		}
		p = next
	}
	return start, end, dashCol, nil
}

func (l *blockedList) flowItem(k int) (start, end int, err error) {
	tok := l.seq.Values[k].GetToken()
	if tok == nil || tok.Position == nil || l.seq.End == nil || l.seq.End.Position == nil {
		return 0, 0, fmt.Errorf("config.RewriteKey: blocked_paths flow item %d has no position", k)
	}
	start = tokenOffset(l.data, tok)
	return start, flowValueEnd(l.data, start, tokenOffset(l.data, l.seq.End)), nil
}

func (l *blockedList) flowTailEnd(pos int) int {
	for {
		pos = trimTrailingFlowSpace(l.data, 0, pos)
		lineStart, comment := startOfLine(l.data, pos), -1
		for p := lineStart; p < pos; p++ {
			if l.comments[p] {
				comment = p
				break
			}
		}
		if comment < 0 {
			return pos
		}
		pos = comment
	}
}

func (l *blockedList) skipFlowGap(p, bound int) int {
	for p < bound {
		switch {
		case l.comments[p]:
			p = min(lineEnd(l.data, p), bound)
		case isFlowSpace(l.data[p]):
			p++
		default:
			return p
		}
	}
	return p
}

func (l *blockedList) hasComment(from, to int) bool {
	for p := from; p < to; p++ {
		if l.comments[p] {
			return true
		}
	}
	return false
}

func withTrailingComma(data []byte, end, closing int) int {
	if comma := skipFlowBlanks(data, end, closing); comma < closing && data[comma] == ',' {
		return comma + 1
	}
	return end
}

func flowRemovalRange(data []byte, start, end int) (int, int) {
	for end < len(data) && (data[end] == ' ' || data[end] == '\t') {
		end++
	}
	lineStart := startOfLine(data, start)
	if len(bytes.TrimLeft(data[lineStart:start], " \t")) == 0 && (end == len(data) || data[end] == '\n' || data[end] == '\r') {
		return lineStart, lineEnd(data, end)
	}
	return start, end
}

func skipFlowBlanks(data []byte, p, bound int) int {
	for p < bound && isFlowSpace(data[p]) {
		p++
	}
	return p
}

func lineEnd(data []byte, offset int) int {
	i := bytes.IndexAny(data[offset:], "\r\n")
	if i < 0 {
		return len(data)
	}
	i += offset + 1
	if data[i-1] == '\r' && i < len(data) && data[i] == '\n' {
		i++
	}
	return i
}

func lineBreak(data []byte) string {
	i := bytes.IndexAny(data, "\r\n")
	switch {
	case i < 0 || data[i] == '\n':
		return "\n"
	case i+1 < len(data) && data[i+1] == '\n':
		return "\r\n"
	default:
		return "\r"
	}
}

func lineAt(data []byte, p int) (next, indent int, content []byte) {
	next = lineEnd(data, p)
	line := bytes.TrimRight(data[p:next], " \t\r\n")
	content = bytes.TrimLeft(line, " \t")
	return next, len(line) - len(content), content
}

func lineBreakBefore(data []byte, pos int, nl string) string {
	if pos > 0 && data[pos-1] != '\n' && data[pos-1] != '\r' {
		return nl
	}
	return ""
}

func isHeadingLine(content []byte, heading string) bool {
	rest, ok := bytes.CutPrefix(content, []byte("#"))
	return ok && heading != "" && string(bytes.TrimSpace(rest)) == heading
}

func hasCommentLine(segment []byte) bool {
	for p := 0; p < len(segment); {
		next, _, content := lineAt(segment, p)
		if bytes.HasPrefix(content, []byte("#")) {
			return true
		}
		p = next
	}
	return false
}
