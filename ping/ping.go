package main

import (
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/routing"
	"log"
	"net"
)

func main() {
	var target net.IP
	target = net.ParseIP("192.168.1.1")
	target = target.To4()

	router, err := routing.New()
	if err != nil {
	}

	iface, gw, src, err := router.Route(target)
	if err != nil {
	}

	log.Printf("%v %v", gw, src)

	handle, err := pcap.OpenLive(iface.Name, 65536, true, pcap.BlockForever)
	if err != nil {
		log.Fatal("pcap openlive err:", err)
	}

	defer handle.Close()

	dstMac, err := Arp(target, handle)
	if err != nil {
		log.Fatal("ARP err:", err)
	}

	eth := layers.Ethernet{
		SrcMAC:       iface.HardwareAddr,
		DstMAC:       dstMac,
		EthernetType: layers.EthernetTypeIPv4,
	}

	ip := layers.IPv4{
		DstIP:    target,
		SrcIP:    src,
		Protocol: layers.IPProtocolICMPv4,
		Version: 4,
		TTL: 255,
		IHL: 5,
		Length: 32,
	}

	icmp := layers.ICMPv4{
		TypeCode: layers.ICMPv4TypeEchoRequest << 8,
		Id: 1000,
		Seq: 1,
	}

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{}

	if err = gopacket.SerializeLayers(buf, opts, &eth, &ip, &icmp,
		gopacket.Payload([]byte{1, 2, 3, 4})); err != nil {
		log.Fatal("serialize err:", err)
	}

	log.Printf("%v", buf.Bytes())

	if err := handle.WritePacketData(buf.Bytes()); err != nil {
		log.Fatal("send err", err)
	}

}
