package main

import (
	"net"
	"log"
)


func main() {
	localAddr, err := net.ResolveUDPAddr("udp4", "0.0.0.0:68")
	
	if err != nil {
		log.Fatal("error:", err)
	}
	
	remoteAddr := net.UDPAddr{IP: net.ParseIP("255.255.255.255"), Port: 67}

	conn, err := net.DialUDP("udp4", localAddr, &remoteAddr)

	if err != nil {
		log.Fatal("error:", err)
	}


	defer conn.Close()


}
