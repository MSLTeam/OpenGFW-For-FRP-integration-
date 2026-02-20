package frp

import (
	"fmt"
	"sync"
)

type SessionManager struct {
	engine *Engine

	mu sync.Mutex

	tcpStreams map[string]*TCPStream
	udpStreams map[string]*UDPStream
}

func NewSessionManager(engine *Engine) *SessionManager {
	return &SessionManager{
		engine:     engine,
		tcpStreams: make(map[string]*TCPStream),
		udpStreams: make(map[string]*UDPStream),
	}
}

func (m *SessionManager) FeedTCP(sessionID string, meta StreamMeta, rev, start, end bool, skip int, data []byte) (InspectionReport, error) {
	if sessionID == "" {
		return InspectionReport{}, fmt.Errorf("empty session id")
	}

	stream, err := m.getOrCreateTCP(sessionID, meta)
	if err != nil {
		return InspectionReport{}, err
	}

	rep := stream.Feed(rev, start, end, skip, data)
	if end && !rep.Done {
		rep = mergeReports(rep, stream.Close(false))
	}
	if rep.Done || end {
		m.mu.Lock()
		delete(m.tcpStreams, sessionID)
		m.mu.Unlock()
	}
	return rep, nil
}

func (m *SessionManager) CloseTCP(sessionID string, limited bool) (InspectionReport, bool) {
	m.mu.Lock()
	stream, ok := m.tcpStreams[sessionID]
	if ok {
		delete(m.tcpStreams, sessionID)
	}
	m.mu.Unlock()
	if !ok {
		return InspectionReport{}, false
	}
	return stream.Close(limited), true
}

func (m *SessionManager) FeedUDP(sessionID string, meta StreamMeta, rev bool, data []byte) (InspectionReport, error) {
	if sessionID == "" {
		return InspectionReport{}, fmt.Errorf("empty session id")
	}

	stream, err := m.getOrCreateUDP(sessionID, meta)
	if err != nil {
		return InspectionReport{}, err
	}

	rep := stream.Feed(rev, data)
	if rep.Done {
		m.mu.Lock()
		delete(m.udpStreams, sessionID)
		m.mu.Unlock()
	}
	return rep, nil
}

func (m *SessionManager) CloseUDP(sessionID string, limited bool) (InspectionReport, bool) {
	m.mu.Lock()
	stream, ok := m.udpStreams[sessionID]
	if ok {
		delete(m.udpStreams, sessionID)
	}
	m.mu.Unlock()
	if !ok {
		return InspectionReport{}, false
	}
	return stream.Close(limited), true
}

func (m *SessionManager) getOrCreateTCP(sessionID string, meta StreamMeta) (*TCPStream, error) {
	m.mu.Lock()
	stream, ok := m.tcpStreams[sessionID]
	m.mu.Unlock()
	if ok {
		return stream, nil
	}
	s, err := m.engine.NewTCPStream(meta)
	if err != nil {
		return nil, err
	}
	m.mu.Lock()
	// Double check in case of race.
	if exist, ok := m.tcpStreams[sessionID]; ok {
		m.mu.Unlock()
		return exist, nil
	}
	m.tcpStreams[sessionID] = s
	m.mu.Unlock()
	return s, nil
}

func (m *SessionManager) getOrCreateUDP(sessionID string, meta StreamMeta) (*UDPStream, error) {
	m.mu.Lock()
	stream, ok := m.udpStreams[sessionID]
	m.mu.Unlock()
	if ok {
		return stream, nil
	}
	s, err := m.engine.NewUDPStream(meta)
	if err != nil {
		return nil, err
	}
	m.mu.Lock()
	// Double check in case of race.
	if exist, ok := m.udpStreams[sessionID]; ok {
		m.mu.Unlock()
		return exist, nil
	}
	m.udpStreams[sessionID] = s
	m.mu.Unlock()
	return s, nil
}

func mergeReports(a, b InspectionReport) InspectionReport {
	out := a
	if b.Updated {
		out.Updated = true
	}
	if b.Done {
		out.Done = true
	}
	if b.Proxy != nil {
		out.Proxy = b.Proxy
	}
	if b.Traffic != nil {
		out.Traffic = b.Traffic
	}
	if b.Action != "" {
		out.Action = b.Action
	}
	if b.Reason != "" {
		out.Reason = b.Reason
	}
	return out
}
