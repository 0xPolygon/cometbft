package conn

import (
	"sync"
	"sync/atomic"
)

type outboundMessage struct {
	data    []byte
	receipt *sendReceipt
}

type sendReceipt struct {
	once     sync.Once
	callback func(bool)
	written  bool // protected by MConnection.receiptMu
}

// TrySendTracked reports completion only after the last packet's local flush.
// A false return means the caller retains ownership; no callback will run.
func (c *MConnection) TrySendTracked(chID byte, data []byte, done func(bool)) bool {
	c.receiptMu.Lock()
	if c.receiptsClosed || !c.IsRunning() {
		c.receiptMu.Unlock()
		return false
	}
	select {
	case <-c.quitSendRoutine:
		c.receiptMu.Unlock()
		return false
	default:
	}
	ch, ok := c.channelsIdx[chID]
	if !ok {
		c.receiptMu.Unlock()
		return false
	}
	receipt := &sendReceipt{callback: done}
	if c.receipts == nil {
		c.receipts = make(map[*sendReceipt]struct{})
	}
	c.receipts[receipt] = struct{}{}
	select {
	case ch.sendQueue <- outboundMessage{data: data, receipt: receipt}:
		atomic.AddInt32(&ch.sendQueueSize, 1)
	default:
		delete(c.receipts, receipt)
		c.receiptMu.Unlock()
		return false
	}
	c.receiptMu.Unlock()
	select {
	case c.send <- struct{}{}:
	default:
	}
	return true
}

func (c *MConnection) markWritten(receipt *sendReceipt) {
	c.receiptMu.Lock()
	defer c.receiptMu.Unlock()
	receipt.written = true
}

func (c *MConnection) finishFlushed(success bool) {
	c.receiptMu.Lock()
	var completed []*sendReceipt
	for receipt := range c.receipts {
		if receipt.written || c.receiptsClosed {
			completed = append(completed, receipt)
			delete(c.receipts, receipt)
		}
	}
	c.receiptMu.Unlock()
	for _, receipt := range completed {
		receipt.once.Do(func() { receipt.callback(success) })
	}
}

func (c *MConnection) cancelReceipts() {
	c.receiptMu.Lock()
	c.receiptsClosed = true
	c.receiptMu.Unlock()
	c.finishFlushed(false)
}
