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
	fecWireVersion      = 1
	fecDataShardsMax    = 8
	fecParityShardsMax  = 4
	fecParityHeaderSize = 14 // version+k+m+index+baseSeq+shardSize
	fecLengthPrefixSize = 2
	fecFlushDelay       = 15 * time.Millisecond
	fecRecentDataLimit  = 64
	fecMaxPendingBlocks = 16
	fecBlockTTL         = 2 * time.Second
	fecBootstrapBlocks  = 4
)

// fecEnabled follows the same nil-means-enabled convention as MTU probing.
func fecEnabled(v *bool) bool { return v == nil || *v }

// fecDataPayloadCap reserves enough room for the parity record's metadata and
// per-shard length prefix. A parity record is itself a normal authenticated
// UDPC record, so this keeps every FEC datagram inside the already-converged
// max_pkt budget and never relies on IP fragmentation.
func fecDataPayloadCap(recordPayloadCap int) int {
	cap := recordPayloadCap - fecParityHeaderSize - fecLengthPrefixSize
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
	// 1/32 EWMA: fast enough to react within a few dozen packets, but slow
	// enough that one reordered datagram does not swing parity wildly.
	e.value += (sample - e.value) / 32
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
	if remote > local {
		return remote
	}
	return local
}

func fecParityForLoss(loss float64) int {
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
	ShardSize    int
	Data         []byte
}

func (p fecParityShard) marshalBinary() []byte {
	if p.BaseSeq == 0 || p.DataShards < 1 || p.DataShards > fecDataShardsMax ||
		p.ParityShards < 1 || p.ParityShards > fecParityShardsMax ||
		p.Index < 0 || p.Index >= p.ParityShards || p.ShardSize < fecLengthPrefixSize ||
		p.ShardSize > 0xffff || len(p.Data) != p.ShardSize {
		return nil
	}
	out := make([]byte, fecParityHeaderSize+p.ShardSize)
	out[0] = fecWireVersion
	out[1] = byte(p.DataShards)
	out[2] = byte(p.ParityShards)
	out[3] = byte(p.Index)
	binary.BigEndian.PutUint64(out[4:12], p.BaseSeq)
	binary.BigEndian.PutUint16(out[12:14], uint16(p.ShardSize))
	copy(out[fecParityHeaderSize:], p.Data)
	return out
}

func parseFECParity(data []byte) (fecParityShard, error) {
	if len(data) < fecParityHeaderSize+fecLengthPrefixSize {
		return fecParityShard{}, fmt.Errorf("fec parity too short")
	}
	if data[0] != fecWireVersion {
		return fecParityShard{}, fmt.Errorf("unsupported fec version %d", data[0])
	}
	p := fecParityShard{
		DataShards:   int(data[1]),
		ParityShards: int(data[2]),
		Index:        int(data[3]),
		BaseSeq:      binary.BigEndian.Uint64(data[4:12]),
		ShardSize:    int(binary.BigEndian.Uint16(data[12:14])),
	}
	if p.BaseSeq == 0 || p.DataShards < 1 || p.DataShards > fecDataShardsMax ||
		p.ParityShards < 1 || p.ParityShards > fecParityShardsMax ||
		p.Index < 0 || p.Index >= p.ParityShards || p.ShardSize < fecLengthPrefixSize {
		return fecParityShard{}, fmt.Errorf("invalid fec parity metadata")
	}
	if p.BaseSeq > ^uint64(0)-uint64(p.DataShards-1) {
		return fecParityShard{}, fmt.Errorf("fec sequence range overflow")
	}
	if len(data) != fecParityHeaderSize+p.ShardSize {
		return fecParityShard{}, fmt.Errorf("invalid fec parity shard length")
	}
	p.Data = append([]byte(nil), data[fecParityHeaderSize:]...)
	return p, nil
}

type fecSender struct {
	mu       sync.Mutex
	pending  []fecSourceShard
	timer    *time.Timer
	closed   bool
	blocks   uint64
	adaptive fecAdaptiveLoss

	encodeMu sync.Mutex
	codecs   map[uint16]reedsolomon.Encoder
	emit     func(fecParityShard)
}

func newFECSender(emit func(fecParityShard)) *fecSender {
	return &fecSender{emit: emit, codecs: make(map[uint16]reedsolomon.Encoder)}
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
	owned := fecSourceShard{seq: seq, payload: append([]byte(nil), payload...)}

	var blocks [][]fecSourceShard
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return
	}
	if n := len(s.pending); n > 0 && seq != s.pending[n-1].seq+1 {
		blocks = append(blocks, s.detachLocked())
	}
	s.pending = append(s.pending, owned)
	if len(s.pending) == 1 {
		s.timer = time.AfterFunc(fecFlushDelay, s.flushTimer)
	}
	if len(s.pending) >= fecDataShardsMax {
		blocks = append(blocks, s.detachLocked())
	}
	s.mu.Unlock()

	for _, block := range blocks {
		s.emitBlock(block)
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
		s.timer = nil
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

	parityShards := fecParityForLoss(s.adaptive.loss())
	// Bootstrap with one parity shard for a few blocks so a new path can
	// measure recoverable loss before its first ARQ timeout. Clean paths then
	// naturally fall to zero parity.
	if blockNo <= fecBootstrapBlocks && parityShards < 1 {
		parityShards = 1
	}
	if parityShards <= 0 {
		return
	}
	if parityShards > fecParityShardsMax {
		parityShards = fecParityShardsMax
	}

	maxPayload := 0
	for _, src := range block {
		if len(src.payload) > maxPayload {
			maxPayload = len(src.payload)
		}
	}
	shardSize := fecLengthPrefixSize + maxPayload
	if shardSize < fecLengthPrefixSize {
		return
	}

	dataShards := len(block)
	shards := make([][]byte, dataShards+parityShards)
	for i, src := range block {
		shard := make([]byte, shardSize)
		binary.BigEndian.PutUint16(shard[:fecLengthPrefixSize], uint16(len(src.payload)))
		copy(shard[fecLengthPrefixSize:], src.payload)
		shards[i] = shard
	}
	for i := dataShards; i < len(shards); i++ {
		shards[i] = make([]byte, shardSize)
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
			ShardSize:    shardSize,
			Data:         parity,
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
}

func newFECReceiver() *fecReceiver {
	return &fecReceiver{
		recent: make(map[uint64][]byte),
		blocks: make(map[uint64]*fecRecvBlock),
		codecs: make(map[uint16]reedsolomon.Encoder),
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

	if _, exists := r.recent[seq]; !exists {
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
	r.pruneBlocksLocked(time.Now())
	sort.Slice(out, func(i, j int) bool { return out[i].Seq < out[j].Seq })
	return out
}

func (r *fecReceiver) onParity(data []byte) []fecRecovered {
	p, err := parseFECParity(data)
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
			shardSize:    p.ShardSize,
			parity:       make([][]byte, p.ParityShards),
			updatedAt:    now,
		}
		r.blocks[p.BaseSeq] = block
	} else if block.dataShards != p.DataShards || block.parityShards != p.ParityShards || block.shardSize != p.ShardSize {
		return nil
	}
	block.updatedAt = now
	if block.parity[p.Index] == nil {
		block.parity[p.Index] = p.Data
	}

	out := r.tryRecoverLocked(block)
	r.pruneBlocksLocked(now)
	sort.Slice(out, func(i, j int) bool { return out[i].Seq < out[j].Seq })
	return out
}

func (r *fecReceiver) tryRecoverLocked(block *fecRecvBlock) []fecRecovered {
	if block == nil {
		return nil
	}
	shards := make([][]byte, block.dataShards+block.parityShards)
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
		shard := make([]byte, block.shardSize)
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
		r.recent[seq] = payload
		r.loss.observeOutcome(true)
		out = append(out, fecRecovered{Seq: seq, Payload: append([]byte(nil), payload...)})
	}
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
