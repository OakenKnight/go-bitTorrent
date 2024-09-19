package handshake

import (
	"fmt"
	"io"
)

type Handshake struct {
	Pstr     string
	InfoHash [20]byte
	PeerID   [20]byte
}

func (h *Handshake) Serialize() []byte {
	buf := make([]byte, len(h.Pstr)+49)
	buf[0] = byte(len(h.Pstr))
	curr := 1
	curr += copy(buf[curr:], h.Pstr)
	curr += copy(buf[curr:], make([]byte, 8)) // 8 reserved bytes
	curr += copy(buf[curr:], h.InfoHash[:])
	curr += copy(buf[curr:], h.PeerID[:])
	return buf
}

// New creates a new handshake with the standard pstr
func New(infoHash, peerID [20]byte) *Handshake {
	return &Handshake{
		Pstr:     "BitTorrent protocol",
		InfoHash: infoHash,
		PeerID:   peerID,
	}
}

func Read(r io.Reader) (*Handshake, error) {
	lengthBuf := make([]byte, 1)
	_, err := io.ReadFull(r, lengthBuf)
	if err != nil {
		return nil, err
	}
	pstrlen := int(lengthBuf[0])

	if pstrlen == 0 {
		err := fmt.Errorf("pstrlen cannot be 0")
		return nil, err
	}
	handshakeBuffer := make([]byte, 48+pstrlen)
	_, err = io.ReadFull(r, handshakeBuffer)
	if err != nil {
		return nil, err
	}

	var infoHash, peerID [20]byte
	copy(infoHash[:], handshakeBuffer[pstrlen+8:pstrlen+28])
	copy(peerID[:], handshakeBuffer[pstrlen+28:])
	hs := Handshake{
		Pstr:     string(handshakeBuffer[:pstrlen]),
		InfoHash: infoHash,
		PeerID:   peerID,
	}
	return &hs, nil
}
