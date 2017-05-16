package main

import (
	"encoding/binary"
	"fmt"
	"net"
	"sync"
)

type nat_info struct {
	Ip       [16]byte
	Port     uint16
	Nat_type uint16
}

const (
	Enroll      = 1
	GetPeerInfo = 2
	NotifyPeer  = 3
)

var seq uint32 = 1
var peers map[uint32]nat_info
var peers_conn map[uint32]net.Conn
var m sync.Mutex

func main() {
	peers = make(map[uint32]nat_info)
	peers_conn = make(map[uint32]net.Conn)

	l, _ := net.Listen("tcp", ":9988")

	defer l.Close()

	for {
		conn, err := l.Accept()
		if err != nil {
			continue
		}

		go handleConn(conn)
	}
}

// 2 bytes for message type
func handleConn(c net.Conn) {
	defer c.Close()
	var peerID uint32 = 0
	for {
		// read message type first
		data := make([]byte, 2)
		_, err := c.Read(data)
		if err != nil {
			m.Lock()
			fmt.Printf("error: %v, peer %d disconnected\n", err, peerID)
			delete(peers, peerID)
			delete(peers_conn, peerID)
			m.Unlock()
			return
		}

		switch binary.BigEndian.Uint16(data[:]) {
		case Enroll:
			var peer nat_info
			err = binary.Read(c, binary.BigEndian, &peer)
			if err != nil {
				continue
			}

			fmt.Println("peer enrolled, addr: ", string(peer.Ip[:]), peer.Port, peer.Nat_type)

			m.Lock()
			seq++
			peerID = seq
			peers[peerID] = peer
			peers_conn[peerID] = c
			fmt.Println("new peer, id : ", peerID)
			m.Unlock()
			err = binary.Write(c, binary.BigEndian, peerID)
			if err != nil {
				continue
			}
		case GetPeerInfo:
			var peer_id uint32
			binary.Read(c, binary.BigEndian, &peer_id)
			if val, ok := peers[peer_id]; ok {
				binary.Write(c, binary.BigEndian, val)
			} else {
				var offline uint8 = 0
				binary.Write(c, binary.BigEndian, offline)
				fmt.Printf("%d offline\n", peer_id)
			}
		case NotifyPeer:
			var peer_id uint32
			binary.Read(c, binary.BigEndian, &peer_id)
			fmt.Println("notify to peer", peer_id)
			if val, ok := peers_conn[peer_id]; ok {
				if err = binary.Write(val, binary.BigEndian, peers[peerID]); err != nil {
					// unable to notify peer
					fmt.Println("offline")
				}
			} else {
				fmt.Println("offline")
			}
		default:
			fmt.Println("illegal message")
		}
	}

	return
}
