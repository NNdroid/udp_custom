package tunnel

import (
	"encoding/binary"
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/klauspost/reedsolomon"
)

const (
	fecDataShardsMax    = 8
	fecParityShardsMax  = 4
	fecLengthPrefixSize = 2
	fecFlushDelay       = 15 * time.Millisecond
	fecRecentDataLimit  = 64
	fecMaxPendingBlocks = 16
	fecBlockTTL         = 2 * time.Second
	fecBootstrapBlocks  = 4
	// EWMA denominator for the loss estimator. See observeOutcome for why it is
	// 64 rather than 32.
	fecLossAlpha = 64
	// fecBootstrapLossRate is the rate below which parity stays at zero (see
	// fecParityForLoss). fecAdaptiveLoss.loss uses it as the lead a peer's loss
	// report may run ahead of local ARQ evidence, so a fresh path can still see
	// a real burst before its first retransmit.
	fecBootstrapLossRate = 0.005

	// fecMemoMinBlocks gates the session-to-session loss memo: below this many
	// emitted FEC blocks the ARQ sample size is too small to trust as a
	// bootstrap for the NEXT session, so the estimate is discarded.
	fecMemoMinBlocks = 32
	// fecLossMemoTTL bounds how long a previous session's loss estimate may
	// seed a new one. Path conditions change faster than MTU does, so this is
	// deliberately shorter than mtuProbeCacheTTL.
	fecLossMemoTTL = 5 * time.Minute

	// CMD_FEC reuses authenticated header fields instead of spending payload
	// bytes on metadata. Seq is the block's first DATA sequence; Flags packs
	// k/m/parity-index. Bits 0..1 are reserved by protocol-wide FEC capability
	// and loss-feedback flags.
	fecDataShift   = 4
	fecDataMask    = uint16(0x7 << fecDataShift) // k-1, 0..7 => 1..8
	fecParityShift = 7
	fecParityMask  = uint16(0x3 << fecParityShift) // m-1, 0..3 => 1..4
	fecIndexShift  = 9
	fecIndexMask   = uint16(0x3 << fecIndexShift) // parity index, 0..3
	fecMetaMask    = fecDataMask | fecParityMask | fecIndexMask

	// Extended-parity encoding, negotiated via FLAG_FEC_EXT_PARITY. CMD_FEC
	// frames carry no other flags, so bits 2 and 3 are free there: bit 2 is
	// the high bit of ParityShards-1 (m 5..8), bit 3 the high bit of Index
	// (4..7). RS(8,8) tolerates losing half the block's shards — beyond that
	// only ARQ can help anyway.
	fecParityExtFlag      = uint16(1 << 2)
	fecIndexExtFlag       = uint16(1 << 3)
	fecParityShardsExtMax = 8
)

// fecEnabled follows the same nil-means-enabled convention as MTU probing.
func fecEnabled(v *bool) bool { return v == nil || *v }

// fecDataPayloadCap reserves only the two-byte original-length prefix used by
// Reed-Solomon data shards. All other FEC metadata lives in the authenticated
// UDPC header, so adaptive FEC costs just two bytes of DATA payload capacity
// and never pushes a parity datagram beyond the converged max_pkt budget.
func fecDataPayloadCap(recordPayloadCap int) int {
	cap := recordPayloadCap - fecLengthPrefixSize
	if cap < 1 {
		return 1
	}
	return cap
}

type fecLossEstimator struct {
	mu    sync.Mutex
	value float64
}

func (e *fecLossEstimator) observeOutcome(lost bool) {
	sample := 0.0
	if lost {
		sample = 1
	}
	e.mu.Lock()
	// 1/64 EWMA: fast enough to converge within a few hundred packets, slow
	// enough that one dropped or reordered datagram cannot swing parity by a
	// whole bucket. At 1/32 a single lost sample jumped the value by 1/32 =
	// 3.1%, already above the 2.5% threshold, so one reorder bought about 58
	// records of parity-2 transmission before the estimate decayed back.
	e.value += (sample - e.value) / fecLossAlpha
	e.mu.Unlock()
}

func (e *fecLossEstimator) observeValue(sample, alpha float64) {
	if sample < 0 {
		sample = 0
	}
	if sample > 1 {
		sample = 1
	}
	if alpha <= 0 || alpha > 1 {
		alpha = 0.25
	}
	e.mu.Lock()
	e.value += (sample - e.value) * alpha
	e.mu.Unlock()
}

func (e *fecLossEstimator) loss() float64 {
	e.mu.Lock()
	v := e.value
	e.mu.Unlock()
	return v
}

func (e *fecLossEstimator) basisPoints() uint16 {
	v := e.loss()
	if v <= 0 {
		return 0
	}
	if v >= 1 {
		return 10000
	}
	return uint16(v*10000 + 0.5)
}

type fecAdaptiveLoss struct {
	local  fecLossEstimator
	remote fecLossEstimator
}

func (a *fecAdaptiveLoss) observeAck(retransmitted bool) {
	a.local.observeOutcome(retransmitted)
}

func (a *fecAdaptiveLoss) observeRemoteBasisPoints(bp uint16) {
	if bp > 10000 {
		bp = 10000
	}
	a.remote.observeValue(float64(bp)/10000, 0.25)
}

func (a *fecAdaptiveLoss) loss() float64 {
	local := a.local.loss()
	remote := a.remote.loss()
	if remote <= local {
		return local
	}
	// remote is the peer's FEC recovery rate, which is a function of the parity
	// this side emits: more parity buys more recoveries, which advertises a higher
	// rate, which buys more parity. Unclamped it is a positive feedback loop that
	// settled near 35% on a 0.5% loss path and parked parity at its ceiling. Cap
	// the lead the peer's report may run ahead of the sender's own ARQ evidence by
	// a factor of two, plus a floor at the parity-1 threshold so a burst is still
	// visible before the first local retransmit. The cap shrinks as local falls,
	// which is the negative feedback the parity overhead needs.
	ceiling := 2*local + fecBootstrapLossRate
	if remote > ceiling {
		remote = ceiling
	}
	return remote
}

func fecParityForLoss(loss float64) int {
	return fecParityForLossExt(loss, false)
}

// fecParityForLossExt picks the parity count for the observed loss. Peers that
// negotiated FLAG_FEC_EXT_PARITY unlock deeper buckets: RS(8,8) spends 50%
// overhead to survive losing half a block's shards, which is the deepest loss
// regime where parity still beats waiting for ARQ.
func fecParityForLossExt(loss float64, ext bool) int {
	if ext {
		switch {
		case loss < 0.005:
			return 0
		case loss < 0.025:
			return 1
		case loss < 0.06:
			return 2
		case loss < 0.12:
			return 3
		case loss < 0.20:
			return 4
		case loss < 0.30:
			return 6
		default:
			return 8
		}
	}
	switch {
	case loss < 0.005:
		return 0
	case loss < 0.025:
		return 1
	case loss < 0.06:
		return 2
	case loss < 0.12:
		return 3
	default:
		return 4
	}
}

type fecSourceShard struct {
	seq     uint64
	payload []byte
}

type fecParityShard struct {
	BaseSeq      uint64
	DataShards   int
	ParityShards int
	Index        int
	Data         []byte
	// Ext marks shard produced by a sender whose peer negotiated the extended
	// parity encoding; applyToFrame then sets bits 2/3 of the CMD_FEC flags.
	Ext bool
}

// applyToFrame stores FEC block metadata in authenticated header fields. Data
// is the raw parity shard and therefore exactly the RS shard size; no outer FEC
// envelope is needed.
func (p fecParityShard) applyToFrame(f *UDPCFrame) bool {
	maxParity := fecParityShardsMax
	if p.Ext {
		maxParity = fecParityShardsExtMax
	}
	if f == nil || p.BaseSeq == 0 || p.DataShards < 1 || p.DataShards > fecDataShardsMax ||
		p.ParityShards < 1 || p.ParityShards > maxParity ||
		p.Index < 0 || p.Index >= p.ParityShards || len(p.Data) < fecLengthPrefixSize ||
		len(p.Data) > UDPC_MAX_DATA {
		return false
	}
	f.Seq = p.BaseSeq
	f.Flags &^= fecMetaMask
	if p.Ext {
		f.Flags &^= fecParityExtFlag | fecIndexExtFlag
	}
	// The m and index fields are 2 bits wide on the wire; the extension adds
	// their high bit elsewhere in the flags. Masking the low bits is what
	// keeps m-1=7 (0b111) from spilling into the index field's bit 9.
	f.Flags |= uint16((p.DataShards-1)&7) << fecDataShift
	f.Flags |= uint16((p.ParityShards-1)&3) << fecParityShift
	f.Flags |= uint16(p.Index&3) << fecIndexShift
	if p.Ext {
		if p.ParityShards-1 >= 4 {
			f.Flags |= fecParityExtFlag
		}
		if p.Index >= 4 {
			f.Flags |= fecIndexExtFlag
		}
	}
	f.Data = p.Data
	return true
}

func parseFECParityFrame(frame *UDPCFrame) (fecParityShard, error) {
	return parseFECParityFrameExt(frame, false)
}

// parseFECParityFrameExt decodes CMD_FEC metadata. ext must be the negotiated
// FLAG_FEC_EXT_PARITY outcome for the session: without it bits 2/3 are treated
// as zero, so frames from pre-extension peers parse identically, and a new
// sender never emits extended metadata to a peer that did not negotiate it.
func parseFECParityFrameExt(frame *UDPCFrame, ext bool) (fecParityShard, error) {
	if frame == nil || frame.Cmd != CMD_FEC || frame.Seq == 0 || len(frame.Data) < fecLengthPrefixSize {
		return fecParityShard{}, fmt.Errorf("invalid fec frame")
	}
	m1 := int((frame.Flags & fecParityMask) >> fecParityShift)
	idx := int((frame.Flags & fecIndexMask) >> fecIndexShift)
	maxParity := fecParityShardsMax
	if ext {
		maxParity = fecParityShardsExtMax
		if frame.Flags&fecParityExtFlag != 0 {
			m1 += 4
		}
		if frame.Flags&fecIndexExtFlag != 0 {
			idx += 4
		}
	}
	p := fecParityShard{
		BaseSeq:      frame.Seq,
		DataShards:   int((frame.Flags&fecDataMask)>>fecDataShift) + 1,
		ParityShards: m1 + 1,
		Index:        idx,
		Data:         append([]byte(nil), frame.Data...),
	}
	if p.DataShards < 1 || p.DataShards > fecDataShardsMax ||
		p.ParityShards < 1 || p.ParityShards > maxParity ||
		p.Index < 0 || p.Index >= p.ParityShards {
		return fecParityShard{}, fmt.Errorf("invalid fec metadata")
	}
	if p.BaseSeq > ^uint64(0)-uint64(p.DataShards-1) {
		return fecParityShard{}, fmt.Errorf("fec sequence range overflow")
	}
	return p, nil
}

type fecSender struct {
	mu       sync.Mutex
	pending  []fecSourceShard
	timer    *time.Timer
	closed   bool
	blocks   uint64
	adaptive fecAdaptiveLoss
	// extParity mirrors the negotiated FLAG_FEC_EXT_PARITY outcome: parity may
	// exceed fecParityShardsMax and CMD_FEC flags carry the extension bits.
	extParity bool

	encodeMu sync.Mutex
	codecs   map[uint16]reedsolomon.Encoder
	emit     func(fecParityShard)
}

var fecSourcesPool = sync.Pool{New: func() any { p := make([]fecSourceShard, 0, fecDataShardsMax); return &p }}
var fecSlabPool = sync.Pool{New: func() any { p := make([]byte, (fecDataShardsMax+fecParityShardsExtMax)*UDPC_MAX_DATA); return &p }}

func newFECSender(emit func(fecParityShard)) *fecSender {
	return newFECSenderExt(emit, false)
}

func newFECSenderExt(emit func(fecParityShard), extParity bool) *fecSender {
	return &fecSender{emit: emit, codecs: make(map[uint16]reedsolomon.Encoder), extParity: extParity}
}

// fecLossMemo carries one session's final ARQ loss estimate into the next
// session on the same Client. Without it every session starts its estimator
// at zero, so on a genuinely lossy path the first seconds run in pure
// retransmission mode until the EWMA converges — exactly the reconnect
// window a weak network hits hardest. The seed washes out as fresh samples
// arrive (observeOutcome is an EWMA over outcomes), so a stale or wrong
// value self-corrects within a few hundred packets.
type fecLossMemo struct {
	mu    sync.Mutex
	value float64
	at    time.Time
}

func (m *fecLossMemo) put(loss float64) {
	m.mu.Lock()
	m.value = loss
	m.at = time.Now()
	m.mu.Unlock()
}

func (m *fecLossMemo) get() (float64, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.at.IsZero() || time.Since(m.at) > fecLossMemoTTL {
		return 0, false
	}
	return m.value, true
}

// memoSnapshot reports the sender's own ARQ-based loss estimate and whether
// enough blocks have flowed for it to mean anything (the remote component is
// deliberately excluded: it mixes in peer recovery feedback, which depends on
// the parity the sender itself emitted).
func (s *fecSender) memoSnapshot() (float64, bool) {
	s.mu.Lock()
	blocks := s.blocks
	s.mu.Unlock()
	if blocks < fecMemoMinBlocks {
		return 0, false
	}
	return s.adaptive.local.loss(), true
}

// seedLoss pre-loads the local loss estimator with a previous session's
// estimate at full weight, so the very first parity decision of a new session
// already reflects the remembered path quality.
func (s *fecSender) seedLoss(loss float64) {
	s.adaptive.local.observeValue(loss, 1.0)
}

func (s *fecSender) codec(dataShards, parityShards, shardSize int) (reedsolomon.Encoder, error) {
	key := uint16(dataShards)<<8 | uint16(parityShards)
	if enc := s.codecs[key]; enc != nil {
		return enc, nil
	}
	enc, err := reedsolomon.New(dataShards, parityShards, reedsolomon.WithAutoGoroutines(shardSize))
	if err != nil {
		return nil, err
	}
	s.codecs[key] = enc
	return enc, nil
}

func (s *fecSender) observeAck(retransmitted bool) { s.adaptive.observeAck(retransmitted) }
func (s *fecSender) observeRemoteBasisPoints(bp uint16) {
	s.adaptive.observeRemoteBasisPoints(bp)
}

func (s *fecSender) add(seq uint64, payload []byte) {
	if seq == 0 || len(payload) == 0 {
		return
	}
	var blocks [][]fecSourceShard
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return
	}
	// After bootstrap, a clean path needs neither owned DATA copies nor a
	// per-block flush timer. ARQ/remote feedback reactivates parity on loss.
	if len(s.pending) == 0 && s.blocks >= fecBootstrapBlocks && fecParityForLoss(s.adaptive.loss()) == 0 {
		s.mu.Unlock()
		return
	}
	if n := len(s.pending); n > 0 && seq != s.pending[n-1].seq+1 {
		blocks = append(blocks, s.detachLocked())
	}
	if s.pending == nil {
		s.pending = *fecSourcesPool.Get().(*[]fecSourceShard)
	}
	owned := fecSourceShard{seq: seq, payload: append([]byte(nil), payload...)}
	s.pending = append(s.pending, owned)
	if len(s.pending) == 1 {
		if s.timer == nil {
			s.timer = time.AfterFunc(fecFlushDelay, s.flushTimer)
		} else {
			s.timer.Reset(fecFlushDelay)
		}
	}
	if len(s.pending) >= fecDataShardsMax {
		blocks = append(blocks, s.detachLocked())
	}
	s.mu.Unlock()

	for _, block := range blocks {
		s.emitBlock(block)
		releaseFECSources(block)
	}
}

func (s *fecSender) detachLocked() []fecSourceShard {
	if len(s.pending) == 0 {
		return nil
	}
	block := s.pending
	s.pending = nil
	if s.timer != nil {
		s.timer.Stop()
	}
	return block
}

func (s *fecSender) flushTimer() {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return
	}
	block := s.detachLocked()
	s.mu.Unlock()
	s.emitBlock(block)
	releaseFECSources(block)
}

func releaseFECSources(block []fecSourceShard) {
	if cap(block) == fecDataShardsMax {
		clear(block)
		p := block[:0]
		fecSourcesPool.Put(&p)
	}
}

func (s *fecSender) emitBlock(block []fecSourceShard) {
	if len(block) == 0 || s.emit == nil {
		return
	}
	for i := 1; i < len(block); i++ {
		if block[i].seq != block[0].seq+uint64(i) {
			return
		}
	}

	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return
	}
	s.blocks++
	blockNo := s.blocks
	s.mu.Unlock()

	parityShards := fecParityForLossExt(s.adaptive.loss(), s.extParity)
	// Bootstrap with one parity shard for a few blocks so a new path can
	// measure recoverable loss before its first ARQ timeout. Clean paths then
	// naturally fall to zero parity.
	if blockNo <= fecBootstrapBlocks && parityShards < 1 {
		parityShards = 1
	}
	dataShards := len(block)
	// More parity than dataShards-1 recovers nothing extra: with k data and m
	// parity the block needs k survivors out of k+m, so beyond k-1 every extra
	// parity datagram is pure waste. The timer flush made this common — a
	// 1-record block flushed 15 ms after a lull paid up to four parity
	// datagrams to protect one record, which is what pushed the FEC-to-DATA
	// ratio past 100% on a 10% loss profile. A block of one falls out of this
	// cap at zero and is left to ARQ, which is correct if slower.
	if parityShards > dataShards-1 {
		parityShards = dataShards - 1
	}
	if parityShards <= 0 {
		return
	}
	maxParity := fecParityShardsMax
	if s.extParity {
		maxParity = fecParityShardsExtMax
	}
	if parityShards > maxParity {
		parityShards = maxParity
	}

	maxPayload := 0
	for _, src := range block {
		if len(src.payload) > maxPayload {
			maxPayload = len(src.payload)
		}
	}
	shardSize := fecLengthPrefixSize + maxPayload
	if shardSize < fecLengthPrefixSize || shardSize > UDPC_MAX_DATA {
		return
	}

	shards := make([][]byte, dataShards+parityShards)
	pooled := fecSlabPool.Get().(*[]byte)
	slab := (*pooled)[:len(shards)*shardSize]
	clear(slab)
	defer fecSlabPool.Put(pooled)
	for i, src := range block {
		shard := slab[i*shardSize : (i+1)*shardSize]
		binary.BigEndian.PutUint16(shard[:fecLengthPrefixSize], uint16(len(src.payload)))
		copy(shard[fecLengthPrefixSize:], src.payload)
		shards[i] = shard
	}
	for i := dataShards; i < len(shards); i++ {
		shards[i] = slab[i*shardSize : (i+1)*shardSize]
	}

	// One session may flush from a timer while the next full block is being
	// completed. Serialize use of its cached encoders; network sends happen
	// after this lock is released.
	s.encodeMu.Lock()
	enc, err := s.codec(dataShards, parityShards, shardSize)
	if err == nil {
		err = enc.Encode(shards)
	}
	s.encodeMu.Unlock()
	if err != nil {
		return
	}

	for i := 0; i < parityShards; i++ {
		parity := append([]byte(nil), shards[dataShards+i]...)
		s.emit(fecParityShard{
			BaseSeq:      block[0].seq,
			DataShards:   dataShards,
			ParityShards: parityShards,
			Index:        i,
			Data:         parity,
			Ext:          s.extParity,
		})
	}
}

func (s *fecSender) close() {
	s.mu.Lock()
	if !s.closed {
		s.closed = true
		if s.timer != nil {
			s.timer.Stop()
			s.timer = nil
		}
		if cap(s.pending) == fecDataShardsMax {
			clear(s.pending)
			p := s.pending[:0]
			fecSourcesPool.Put(&p)
		}
		s.pending = nil
	}
	s.mu.Unlock()
}

type fecRecovered struct {
	Seq     uint64
	Payload []byte
}

type fecRecvBlock struct {
	baseSeq      uint64
	dataShards   int
	parityShards int
	shardSize    int
	parity       [][]byte
	updatedAt    time.Time
}

type fecReceiver struct {
	mu        sync.Mutex
	recent    map[uint64][]byte
	highest   uint64
	lastPrune uint64
	blocks    map[uint64]*fecRecvBlock
	codecs    map[uint16]reedsolomon.Encoder
	loss      fecLossEstimator
	// extParity mirrors the negotiated FLAG_FEC_EXT_PARITY outcome: parity
	// metadata may use the extended k/m/index encoding.
	extParity bool
}

func newFECReceiver() *fecReceiver {
	return newFECReceiverExt(false)
}

func newFECReceiverExt(extParity bool) *fecReceiver {
	return &fecReceiver{
		recent:    make(map[uint64][]byte),
		blocks:    make(map[uint64]*fecRecvBlock),
		codecs:    make(map[uint16]reedsolomon.Encoder),
		extParity: extParity,
	}
}

func (r *fecReceiver) codec(dataShards, parityShards, shardSize int) (reedsolomon.Encoder, error) {
	key := uint16(dataShards)<<8 | uint16(parityShards)
	if enc := r.codecs[key]; enc != nil {
		return enc, nil
	}
	enc, err := reedsolomon.New(dataShards, parityShards, reedsolomon.WithAutoGoroutines(shardSize))
	if err != nil {
		return nil, err
	}
	r.codecs[key] = enc
	return enc, nil
}

func (r *fecReceiver) feedbackBasisPoints() uint16 { return r.loss.basisPoints() }

func (r *fecReceiver) onData(seq uint64, payload []byte) []fecRecovered {
	if seq == 0 {
		return nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()

	now := time.Now()
	if _, exists := r.recent[seq]; !exists {
		// Retained unconditionally: the sender decides parity after this block's
		// DATA has already been sent, so whether this record will ever be needed
		// for reconstruction cannot be known here. The cost is one copy per
		// record on a clean path; once the feedback loop in
		// fecAdaptiveLoss.loss is broken the parity overhead itself is what
		// dominates, not this.
		r.recent[seq] = append([]byte(nil), payload...)
		r.loss.observeOutcome(false)
		if seq > r.highest {
			r.highest = seq
		}
	}
	r.pruneRecentLocked()

	var out []fecRecovered
	for _, block := range r.blocks {
		end := block.baseSeq + uint64(block.dataShards)
		if seq >= block.baseSeq && seq < end {
			out = append(out, r.tryRecoverLocked(block)...)
		}
	}
	r.pruneBlocksLocked(now)
	if len(out) > 1 {
		sort.Slice(out, func(i, j int) bool { return out[i].Seq < out[j].Seq })
	}
	return out
}

func (r *fecReceiver) onParityFrame(frame *UDPCFrame) []fecRecovered {
	p, err := parseFECParityFrameExt(frame, r.extParity)
	if err != nil {
		return nil
	}
	now := time.Now()
	r.mu.Lock()
	defer r.mu.Unlock()

	block := r.blocks[p.BaseSeq]
	if block == nil {
		block = &fecRecvBlock{
			baseSeq:      p.BaseSeq,
			dataShards:   p.DataShards,
			parityShards: p.ParityShards,
			shardSize:    len(p.Data),
			parity:       make([][]byte, p.ParityShards),
			updatedAt:    now,
		}
		r.blocks[p.BaseSeq] = block
	} else if block.dataShards != p.DataShards || block.parityShards != p.ParityShards || block.shardSize != len(p.Data) {
		return nil
	}
	block.updatedAt = now
	if block.parity[p.Index] == nil {
		block.parity[p.Index] = p.Data
	}

	out := r.tryRecoverLocked(block)
	r.pruneBlocksLocked(now)
	if len(out) > 1 {
		sort.Slice(out, func(i, j int) bool { return out[i].Seq < out[j].Seq })
	}
	return out
}

func (r *fecReceiver) tryRecoverLocked(block *fecRecvBlock) []fecRecovered {
	if block == nil {
		return nil
	}
	// Count first: a complete block or insufficient parity needs no shard
	// construction at all. Previously even the clean case copied every DATA.
	available, missingCount := 0, 0
	for i := 0; i < block.dataShards; i++ {
		if payload, ok := r.recent[block.baseSeq+uint64(i)]; ok {
			if len(payload) > block.shardSize-fecLengthPrefixSize {
				return nil
			}
			available++
		} else {
			missingCount++
		}
	}
	if missingCount == 0 {
		delete(r.blocks, block.baseSeq)
		return nil
	}
	for _, p := range block.parity {
		if p != nil {
			available++
		}
	}
	if available < block.dataShards || missingCount > block.parityShards {
		return nil
	}
	shards := make([][]byte, block.dataShards+block.parityShards)
	pooled := fecSlabPool.Get().(*[]byte)
	slab := (*pooled)[:block.dataShards*block.shardSize]
	clear(slab)
	defer fecSlabPool.Put(pooled)
	missing := make([]int, 0, block.parityShards)
	present := 0
	for i := 0; i < block.dataShards; i++ {
		seq := block.baseSeq + uint64(i)
		payload, ok := r.recent[seq]
		if !ok {
			missing = append(missing, i)
			continue
		}
		if len(payload) > block.shardSize-fecLengthPrefixSize {
			return nil
		}
		shard := slab[i*block.shardSize : (i+1)*block.shardSize]
		binary.BigEndian.PutUint16(shard[:fecLengthPrefixSize], uint16(len(payload)))
		copy(shard[fecLengthPrefixSize:], payload)
		shards[i] = shard
		present++
	}
	if len(missing) == 0 {
		delete(r.blocks, block.baseSeq)
		return nil
	}
	for i, parity := range block.parity {
		if parity != nil {
			shards[block.dataShards+i] = parity
			present++
		}
	}
	if present < block.dataShards || len(missing) > block.parityShards {
		return nil
	}

	enc, err := r.codec(block.dataShards, block.parityShards, block.shardSize)
	if err != nil || enc.ReconstructData(shards) != nil {
		return nil
	}

	out := make([]fecRecovered, 0, len(missing))
	for _, idx := range missing {
		shard := shards[idx]
		if len(shard) != block.shardSize {
			return nil
		}
		n := int(binary.BigEndian.Uint16(shard[:fecLengthPrefixSize]))
		if n < 0 || n > block.shardSize-fecLengthPrefixSize {
			return nil
		}
		seq := block.baseSeq + uint64(idx)
		payload := append([]byte(nil), shard[fecLengthPrefixSize:fecLengthPrefixSize+n]...)
		// Cache for a later block that still needs this shard, then hand the same
		// buffer to the caller. The copy is not redundant: reedsolomon rebuilds a
		// missing shard into a freshly aligned allocation (AllocAligned, not the
		// pooled slab), so a future change to that dependency or to shard reuse
		// could start aliasing these buffers with a buffer that outlives this
		// call. Owning the bytes here keeps r.recent and the caller independent.
		r.recent[seq] = payload
		out = append(out, fecRecovered{Seq: seq, Payload: payload})
	}
	// A reconstructed shard means the sender over-committed its parity estimate, so
	// the receive side has to feed that back to the sender. Keep this: it is the
	// only signal that FEC itself is doing useful work, and fecAdaptiveLoss.loss
	// clamps the effect so it cannot turn into a positive feedback loop.
	r.loss.observeOutcome(true)
	delete(r.blocks, block.baseSeq)
	return out
}

func (r *fecReceiver) pruneRecentLocked() {
	if r.highest <= fecRecentDataLimit || r.highest-r.lastPrune < fecDataShardsMax {
		return
	}
	cutoff := r.highest - fecRecentDataLimit
	for seq := range r.recent {
		if seq < cutoff {
			delete(r.recent, seq)
		}
	}
	r.lastPrune = r.highest
}

func (r *fecReceiver) pruneBlocksLocked(now time.Time) {
	for base, block := range r.blocks {
		if now.Sub(block.updatedAt) > fecBlockTTL {
			delete(r.blocks, base)
		}
	}
	for len(r.blocks) > fecMaxPendingBlocks {
		var oldestBase uint64
		var oldest time.Time
		first := true
		for base, block := range r.blocks {
			if first || block.updatedAt.Before(oldest) {
				oldestBase, oldest, first = base, block.updatedAt, false
			}
		}
		delete(r.blocks, oldestBase)
	}
}
