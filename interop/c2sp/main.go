// Command c2sp checks the checkpoints of fixtures/inclusion-v1 with independent C2SP libraries:
// golang.org/x/mod/sumdb/note (signed notes, Ed25519 log signatures, type 0x01) and
// github.com/transparency-dev/formats (cosignature/v1, type 0x04, and checkpoint bodies).
//
// It reads the set's manifest.json and, for every bundle and consistency case:
//
//   - accepted: the library verifies the log signature of each checkpoint (a bundle's, or a
//     consistency document's older and newer), the checkpoint body parses with the expected origin,
//     size and root hash, and for a bundle at least m of the trusted witnesses' cosignatures verify,
//     with the names and times the manifest expects;
//   - refused with a signature error (bad_log_signature, log_signature_missing, bad_cosignature,
//     too_few_cosignatures): the library refuses too, and for the same reason.
//
// The spec is stricter than the library in one rule a library cannot know: a cosignature time above
// 253402300799 (spec §5.3). For those cases the checker confirms the library accepts the signature, so
// the refusal rests on that rule alone. Every other case is out of scope here (forms, proofs, trust
// configurations), and the reference verifiers cover it.
//
// Usage: go run . <fixtures/inclusion-v1>. Exit 0 when every case agrees, 1 on any disagreement, 2 on a
// file that cannot be read.
package main

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/transparency-dev/formats/log"
	cosig "github.com/transparency-dev/formats/note"
	"golang.org/x/mod/sumdb/note"
)

const (
	algEd25519      = 0x01
	algCosigV1      = 0x04
	maxCosigTime    = 253402300799
	accepted        = "accepted"
	checkpointForm  = "checkpoint_form"
	originMismatch  = "origin_mismatch"
	badLogSig       = "bad_log_signature"
	logSigMissing   = "log_signature_missing"
	badCosig        = "bad_cosignature"
	tooFewCosigs    = "too_few_cosignatures"
	timeFormat      = "2006-01-02T15:04:05Z"
	stricterTimeTag = "cosignature time above 253402300799 (spec §5.3)"
)

var signatureErrors = map[string]bool{badLogSig: true, logSigMissing: true, badCosig: true, tooFewCosigs: true}

type manifestCase struct {
	Name   string          `json:"name"`
	Check  string          `json:"check"`
	Doc    *string         `json:"doc"`
	Trust  string          `json:"trust"`
	Expect json.RawMessage `json:"expect"`
}

type expectation struct {
	Verdict   string `json:"verdict"`
	Error     string `json:"error"`
	TreeSize  uint64 `json:"tree_size"`
	RootHash  string `json:"root_hash"`
	OlderSize uint64 `json:"older_size"`
	NewerSize uint64 `json:"newer_size"`
	Witnesses []struct {
		Name string `json:"name"`
		Time string `json:"time"`
	} `json:"witnesses"`
}

type trustConfig struct {
	Logs []struct {
		LogID   string `json:"log_id"`
		KeyName string `json:"key_name"`
		Key     string `json:"key"`
	} `json:"logs"`
	Witnesses []struct {
		Name string `json:"name"`
		Key  string `json:"key"`
	} `json:"witnesses"`
	M *int `json:"m"`
}

type document struct {
	LogID      string `json:"log_id"`
	Checkpoint string `json:"checkpoint"`
	Older      string `json:"older"`
	Newer      string `json:"newer"`
}

// vkey is the C2SP verifier key <name>+<hex key ID>+<base64(type || public key)>.
func vkey(name string, typ byte, pubB64url string) (string, error) {
	pub, err := base64.RawURLEncoding.DecodeString(pubB64url)
	if err != nil {
		return "", err
	}
	h := sha256.New()
	h.Write([]byte(name))
	h.Write([]byte{'\n', typ})
	h.Write(pub)
	id := binary.BigEndian.Uint32(h.Sum(nil)[:4])
	return fmt.Sprintf("%s+%08x+%s", name, id, base64.StdEncoding.EncodeToString(append([]byte{typ}, pub...))), nil
}

type keys struct {
	log       note.Verifier
	witnesses []note.Verifier
	m         int
}

func loadKeys(dir, trustPath, logID string) (*keys, error) {
	var t trustConfig
	if err := readJSON(filepath.Join(dir, trustPath), &t); err != nil {
		return nil, err
	}
	k := &keys{m: 1}
	if t.M != nil {
		k.m = *t.M
	}
	for _, l := range t.Logs {
		if l.LogID != logID {
			continue
		}
		vk, err := vkey(l.KeyName, algEd25519, l.Key)
		if err != nil {
			return nil, err
		}
		if k.log, err = note.NewVerifier(vk); err != nil {
			return nil, err
		}
	}
	if k.log == nil {
		return nil, fmt.Errorf("%s holds no log %s", trustPath, logID)
	}
	for _, w := range t.Witnesses {
		vk, err := vkey(w.Name, algCosigV1, w.Key)
		if err != nil {
			return nil, err
		}
		v, err := cosig.NewVerifierForCosignatureV1(vk)
		if err != nil {
			return nil, err
		}
		k.witnesses = append(k.witnesses, v)
	}
	return k, nil
}

func same(s note.Signature, v note.Verifier) bool { return s.Name == v.Name() && s.Hash == v.KeyHash() }

type witnessTime struct {
	name string
	time uint64
}

// open verifies one checkpoint with the library and names the outcome in the spec's terms.
func open(text, logID string, k *keys, withWitnesses bool) (string, *log.Checkpoint, []witnessTime, string) {
	vs := []note.Verifier{k.log}
	if withWitnesses {
		vs = append(vs, k.witnesses...)
	}
	n, err := note.Open([]byte(text), note.VerifierList(vs...))
	var invalid *note.InvalidSignatureError
	var unverified *note.UnverifiedNoteError
	switch {
	case errors.As(err, &invalid):
		if invalid.Name == k.log.Name() && invalid.Hash == k.log.KeyHash() {
			return badLogSig, nil, nil, err.Error()
		}
		return badCosig, nil, nil, err.Error()
	case errors.As(err, &unverified):
		return logSigMissing, nil, nil, err.Error()
	case err != nil:
		return checkpointForm, nil, nil, err.Error()
	}
	logSigned := false
	var ws []witnessTime
	for _, s := range n.Sigs {
		if same(s, k.log) {
			logSigned = true
			continue
		}
		for _, w := range k.witnesses {
			if same(s, w) {
				t, err := cosig.CoSigV1Timestamp(s)
				if err != nil {
					return badCosig, nil, nil, err.Error()
				}
				ws = append(ws, witnessTime{s.Name, uint64(t.Unix())})
			}
		}
	}
	if !logSigned {
		return logSigMissing, nil, nil, "no verified line from the log key"
	}
	cp := &log.Checkpoint{}
	rest, err := cp.Unmarshal([]byte(n.Text))
	if err != nil {
		return checkpointForm, nil, nil, err.Error()
	}
	if len(rest) != 0 {
		return checkpointForm, nil, nil, "extension lines"
	}
	if cp.Origin != logID {
		return originMismatch, nil, nil, fmt.Sprintf("origin %q", cp.Origin)
	}
	if withWitnesses && len(ws) < k.m {
		return tooFewCosigs, cp, ws, fmt.Sprintf("%d of m = %d", len(ws), k.m)
	}
	return accepted, cp, ws, ""
}

type tally struct {
	checkpoints, logSigs, cosigs, acceptedCases, refusalCases, stricter int
	disagreements                                                       []string
}

func (t *tally) disagree(name, format string, args ...any) {
	t.disagreements = append(t.disagreements, name+": "+fmt.Sprintf(format, args...))
}

func checkBundle(dir string, c manifestCase, e expectation, d document, t *tally) error {
	k, err := loadKeys(dir, c.Trust, d.LogID)
	if err != nil {
		return err
	}
	got, cp, ws, detail := open(d.Checkpoint, d.LogID, k, true)
	if e.Verdict == accepted {
		t.acceptedCases++
		if got != accepted {
			t.disagree(c.Name, "manifest accepted, library %s (%s)", got, detail)
			return nil
		}
		t.checkpoints++
		t.logSigs++
		t.cosigs += len(ws)
		if cp.Size != e.TreeSize || base64.StdEncoding.EncodeToString(cp.Hash) != e.RootHash {
			t.disagree(c.Name, "checkpoint body size %d root %s, manifest %d %s",
				cp.Size, base64.StdEncoding.EncodeToString(cp.Hash), e.TreeSize, e.RootHash)
		}
		sort.Slice(ws, func(i, j int) bool {
			if ws[i].time != ws[j].time {
				return ws[i].time < ws[j].time
			}
			return ws[i].name < ws[j].name
		})
		var gotW, wantW []string
		for _, w := range ws {
			gotW = append(gotW, w.name+"@"+fmtTime(w.time))
		}
		for _, w := range e.Witnesses {
			wantW = append(wantW, w.Name+"@"+w.Time)
		}
		if strings.Join(gotW, ",") != strings.Join(wantW, ",") {
			t.disagree(c.Name, "witnesses %v, manifest %v", gotW, wantW)
		}
		return nil
	}
	if !signatureErrors[e.Error] {
		return nil
	}
	if e.Error == badCosig && got == accepted && anyAbove(ws, maxCosigTime) {
		t.stricter++
		fmt.Printf("stricter than the library: %s (%s); the library verifies the signature\n", c.Name, stricterTimeTag)
		return nil
	}
	t.refusalCases++
	if got != e.Error {
		t.disagree(c.Name, "manifest refused %s, library %s (%s)", e.Error, got, detail)
	}
	return nil
}

func checkConsistency(dir string, c manifestCase, e expectation, d document, t *tally) error {
	if e.Verdict != accepted && !signatureErrors[e.Error] {
		return nil
	}
	k, err := loadKeys(dir, c.Trust, d.LogID)
	if err != nil {
		return err
	}
	// A consistency document checks the log's lines only (spec §7.2): witness lines are not given keys.
	gotOld, old, _, detOld := open(d.Older, d.LogID, k, false)
	gotNew, nw, _, detNew := open(d.Newer, d.LogID, k, false)
	got, detail := gotOld, detOld
	if got == accepted {
		got, detail = gotNew, detNew
	}
	if e.Verdict == accepted {
		t.acceptedCases++
		if got != accepted {
			t.disagree(c.Name, "manifest accepted, library %s (%s)", got, detail)
			return nil
		}
		t.checkpoints += 2
		t.logSigs += 2
		if old.Size != e.OlderSize || nw.Size != e.NewerSize {
			t.disagree(c.Name, "sizes %d to %d, manifest %d to %d", old.Size, nw.Size, e.OlderSize, e.NewerSize)
		}
		return nil
	}
	t.refusalCases++
	if got != e.Error {
		t.disagree(c.Name, "manifest refused %s, library %s (%s)", e.Error, got, detail)
	}
	return nil
}

func anyAbove(ws []witnessTime, limit uint64) bool {
	for _, w := range ws {
		if w.time > limit {
			return true
		}
	}
	return false
}

func fmtTime(s uint64) string {
	if s > maxCosigTime {
		return fmt.Sprintf("%d", s)
	}
	return timeOf(s)
}

func timeOf(s uint64) string { return time.Unix(int64(s), 0).UTC().Format(timeFormat) }

func readJSON(path string, v any) error {
	b, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	return json.Unmarshal(b, v)
}

func run(dir string) (*tally, error) {
	var m struct {
		Cases []manifestCase `json:"cases"`
	}
	if err := readJSON(filepath.Join(dir, "manifest.json"), &m); err != nil {
		return nil, err
	}
	t := &tally{}
	for _, c := range m.Cases {
		if (c.Check != "bundle" && c.Check != "consistency") || c.Doc == nil {
			continue
		}
		var e expectation
		if err := json.Unmarshal(c.Expect, &e); err != nil {
			return nil, fmt.Errorf("%s: %w", c.Name, err)
		}
		if e.Verdict != accepted && !signatureErrors[e.Error] {
			continue
		}
		var d document
		if err := readJSON(filepath.Join(dir, *c.Doc), &d); err != nil {
			return nil, fmt.Errorf("%s: %w", c.Name, err)
		}
		check := checkBundle
		if c.Check == "consistency" {
			check = checkConsistency
		}
		if err := check(dir, c, e, d, t); err != nil {
			return nil, fmt.Errorf("%s: %w", c.Name, err)
		}
	}
	return t, nil
}

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: c2sp <fixtures/inclusion-v1>")
		os.Exit(2)
	}
	t, err := run(os.Args[1])
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	for _, d := range t.disagreements {
		fmt.Println("DISAGREE " + d)
	}
	fmt.Printf("c2sp-interop: %d accepted cases (%d checkpoints, %d log signatures, %d witness cosignatures verified); "+
		"%d signature refusals checked; %d stricter than the library; %d disagreements\n",
		t.acceptedCases, t.checkpoints, t.logSigs, t.cosigs, t.refusalCases, t.stricter, len(t.disagreements))
	if len(t.disagreements) > 0 || t.acceptedCases == 0 || t.refusalCases == 0 {
		os.Exit(1)
	}
}
