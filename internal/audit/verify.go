package audit

import (
	"bufio"
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"time"
)

// maxLine bounds one record. A hostile file must not be able to ask a verifier
// for unbounded memory before it has been rejected: the largest legitimate
// record is an entry with a 1024-byte key, which is an order of magnitude below
// this.
const maxLine = 1 << 20

// ErrTampered reports a log whose contents do not match its own chain.
var ErrTampered = errors.New("audit: the log does not verify")

// VerifyOptions configures a verification pass.
type VerifyOptions struct {
	// PublicKey verifies the checkpoint signatures. A nil key checks the chain
	// only -- which detects every edit, reorder and splice within the file, but
	// nothing about who wrote it. Result.SignaturesChecked says which happened,
	// and a caller that reports a verdict must report that too.
	PublicKey ed25519.PublicKey
	// OnEntry is called for each verified entry, in order. It is how a caller
	// reads a log without the verifier holding all of it in memory.
	OnEntry func(*Entry) error
	// OnCheckpoint is called for each checkpoint that passed, with the chain it
	// belongs to. A caller comparing the log against a checkpoint recorded
	// elsewhere needs every one of them, not just the last: the one an operator
	// wrote down is rarely the newest.
	OnCheckpoint func(chain string, point *Checkpoint) error
}

// Result describes a verified log file.
type Result struct {
	Head        Head
	Chain       string
	Entries     uint64
	FinalHash   string
	First, Last time.Time

	Checkpoints    int
	LastCheckpoint *Checkpoint
	// SignedThrough is the highest sequence number covered by a verified
	// signature. Entries past it are chained but not signed, and are what an
	// attacker holding the file can still remove undetectably.
	SignedThrough     uint64
	SignaturesChecked bool

	// TornTail reports a final line that was cut off mid-write. It is what a
	// host crash between checkpoints looks like, and it is reported rather than
	// treated as tampering because the two are indistinguishable from the file
	// alone -- which is exactly what a checkpoint published elsewhere is for.
	TornTail bool
	// Complete offset of the last intact record, which is where a torn tail is
	// cut back to before the log is continued.
	IntactBytes int64
}

// Verify checks a log file's chain and, given a public key, its signatures.
func Verify(r io.Reader, opts VerifyOptions) (*Result, error) {
	br := bufio.NewReader(io.LimitReader(r, maxLogBytes))
	result := &Result{SignaturesChecked: opts.PublicKey != nil}

	var (
		offset int64
		lineNo int
		prev   string
	)
	for {
		line, err := readLine(br)
		if len(line) == 0 && errors.Is(err, io.EOF) {
			break
		}
		if err != nil && !errors.Is(err, io.EOF) {
			return nil, err
		}
		lineNo++

		// A final line with no newline was being written when the process
		// stopped. Anything before the end of the file is a different matter: a
		// record cut short in the middle of a file was cut by something other
		// than a crash.
		if errors.Is(err, io.EOF) && !bytes.HasSuffix(line, []byte("\n")) {
			result.TornTail = true
			break
		}
		if int64(len(line)) > maxLine {
			return nil, fmt.Errorf("%w: line %d is %d bytes, over the limit",
				ErrMalformed, lineNo, len(line))
		}

		record, err := parseLine(bytes.TrimRight(line, "\n"))
		if err != nil {
			return nil, fmt.Errorf("line %d: %w", lineNo, err)
		}
		if prev, err = verifyRecord(record, lineNo, prev, result, opts); err != nil {
			return nil, err
		}

		offset += int64(len(line))
		result.IntactBytes = offset
	}

	if result.Chain == "" {
		return nil, fmt.Errorf("%w: the log has no head record", ErrMalformed)
	}
	result.FinalHash = prev
	return result, nil
}

// maxLogBytes bounds a single verification pass. It is generous -- 64 GiB is far
// past any rotation size -- and exists only so that a reader cannot be made to
// run forever on a file that grows as fast as it is read.
const maxLogBytes = 64 << 30

// verifyRecord checks one record against the chain so far and returns the new
// chain hash.
func verifyRecord(
	record Record, lineNo int, prev string, result *Result, opts VerifyOptions,
) (string, error) {
	switch record.Type {
	case TypeHead:
		if prev != "" {
			return "", fmt.Errorf("%w: line %d is a second head record", ErrTampered, lineNo)
		}
		return verifyHead(record.Head, result, opts)

	case TypeEntry:
		if prev == "" {
			return "", fmt.Errorf("%w: line %d is an entry before any head", ErrTampered, lineNo)
		}
		return verifyEntry(record.Entry, lineNo, prev, result, opts)

	case TypeCheckpoint:
		if prev == "" {
			return "", fmt.Errorf("%w: line %d is a checkpoint before any head", ErrTampered, lineNo)
		}
		return prev, verifyCheckpoint(record.Checkpoint, lineNo, prev, result, opts)
	}
	return "", fmt.Errorf("%w: line %d has unknown type %q", ErrMalformed, lineNo, record.Type)
}

func verifyHead(head *Head, result *Result, opts VerifyOptions) (string, error) {
	if head.Version != Version {
		return "", fmt.Errorf("audit: log format version %d, this build reads %d",
			head.Version, Version)
	}
	want, err := head.chainHashOf()
	if err != nil {
		return "", err
	}
	if head.Hash != want {
		return "", fmt.Errorf("%w: the head record's own hash is wrong", ErrTampered)
	}
	if opts.PublicKey != nil {
		recorded := base64.StdEncoding.EncodeToString(opts.PublicKey)
		if head.PublicKey != recorded {
			return "", fmt.Errorf("%w: %s", ErrWrongKey, head.Chain)
		}
	}
	result.Head, result.Chain = *head, head.Chain
	return head.Hash, nil
}

func verifyEntry(
	entry *Entry, lineNo int, prev string, result *Result, opts VerifyOptions,
) (string, error) {
	// Bounded before anything is hashed. Both fields are cast to fixed-width
	// unsigned integers for the chain hash, and a negative value in a hostile
	// file would wrap into a large one -- consistently, so it would verify,
	// leaving a record that says a request moved 18 exabytes. Rejecting the
	// value is simpler than specifying the wrap, and keeps section 14.2 of
	// docs/FORMAT.md something an independent verifier can implement literally.
	switch {
	case entry.Bytes < 0:
		return "", fmt.Errorf("%w: entry %d records %d bytes", ErrMalformed, entry.Seq, entry.Bytes)
	case entry.Status < 0 || entry.Status > 999:
		return "", fmt.Errorf("%w: entry %d records status %d", ErrMalformed, entry.Seq, entry.Status)
	}
	if entry.Seq != result.Entries+1 {
		return "", fmt.Errorf("%w: line %d is entry %d where %d was expected; "+
			"an entry has been removed, reordered or inserted",
			ErrTampered, lineNo, entry.Seq, result.Entries+1)
	}
	want, err := entry.chainHashOf(result.Chain, prev)
	if err != nil {
		return "", err
	}
	if entry.Hash != want {
		return "", fmt.Errorf("%w: entry %d does not hash to what it claims; "+
			"it has been edited, or the entry before it has", ErrTampered, entry.Seq)
	}

	at := parseTime(entry.Time)
	if result.Entries == 0 {
		result.First = at
	}
	result.Last = at
	result.Entries = entry.Seq

	if opts.OnEntry != nil {
		if err := opts.OnEntry(entry); err != nil {
			return "", err
		}
	}
	return entry.Hash, nil
}

func verifyCheckpoint(
	point *Checkpoint, lineNo int, prev string, result *Result, opts VerifyOptions,
) error {
	if point.Seq != result.Entries || point.Hash != prev {
		return fmt.Errorf("%w: the checkpoint on line %d claims the chain stood at "+
			"entry %d, but it stood at %d", ErrTampered, lineNo, point.Seq, result.Entries)
	}
	result.Checkpoints++
	result.LastCheckpoint = point

	if opts.PublicKey == nil {
		return nil
	}
	msg, err := point.signedMessage(result.Chain)
	if err != nil {
		return err
	}
	sig, err := base64.StdEncoding.DecodeString(point.Signature)
	if err != nil {
		return fmt.Errorf("%w: the signature on line %d is not valid base64",
			ErrMalformed, lineNo)
	}
	if !ed25519.Verify(opts.PublicKey, msg, sig) {
		return fmt.Errorf("%w: the checkpoint signature on line %d does not verify",
			ErrTampered, lineNo)
	}
	result.SignedThrough = point.Seq
	if opts.OnCheckpoint != nil {
		return opts.OnCheckpoint(result.Chain, point)
	}
	return nil
}

// readLine reads one line, newline included, bounded by maxLine.
func readLine(br *bufio.Reader) ([]byte, error) {
	line, err := br.ReadBytes('\n')
	if len(line) > maxLine {
		return line[:maxLine], fmt.Errorf("%w: a record exceeds %d bytes", ErrMalformed, maxLine)
	}
	return line, err
}

// VerifyChain verifies a sequence of rotated log files as one chain.
//
// The files must be given oldest first. Each one is verified on its own, and
// then its head is checked to continue the file before it: a rotation records
// the previous chain's id and final hash, so a file quietly removed from the
// middle of a sequence is a break rather than a gap nobody notices.
func VerifyChain(readers []NamedReader, opts VerifyOptions) ([]*Result, error) {
	results := make([]*Result, 0, len(readers))
	for i, source := range readers {
		result, err := Verify(source.Reader, opts)
		if err != nil {
			return results, fmt.Errorf("%s: %w", source.Name, err)
		}
		if i > 0 {
			before := results[i-1]
			switch {
			case result.Head.PrevChain != before.Chain:
				return results, fmt.Errorf("%w: %s continues chain %q, but the file "+
					"before it is chain %q", ErrTampered, source.Name,
					result.Head.PrevChain, before.Chain)
			case result.Head.PrevHash != before.FinalHash:
				return results, fmt.Errorf("%w: %s continues a chain that ended at a "+
					"different hash than %s did", ErrTampered, source.Name, readers[i-1].Name)
			}
		}
		results = append(results, result)
	}
	if len(results) == 0 {
		return nil, errors.New("audit: no log files to verify")
	}
	return results, nil
}

// NamedReader is one log file to verify, with a name for error messages.
type NamedReader struct {
	Name   string
	Reader io.Reader
}
