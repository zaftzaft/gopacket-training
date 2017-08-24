package main

import (
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/routing"
	"log"
	"net"
	"time"
)

// https://github.com/google/gopacket/blob/master/examples/synscan/main.go
func main() {
	var target net.IP
	target = net.ParseIP("192.168.1.170")
	target = target.To4()

	router, err := routing.New()
	if err != nil {
		log.Fatal("routing error:", err)
	}

	iface, gw, src, err := router.Route(target)
	if err != nil {
		log.Fatal("Route err:", err)
	}
	log.Printf("arp %v with interface %v, gateway %v, src %v", target, iface.Name, gw, src)

	eth := layers.Ethernet{
		SrcMAC:       iface.HardwareAddr,
		DstMAC:       net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
		EthernetType: layers.EthernetTypeARP,
	}

	arp := layers.ARP{
		AddrType:          layers.LinkTypeEthernet,
		Protocol:          layers.EthernetTypeIPv4,
		HwAddressSize:     6,
		ProtAddressSize:   4,
		Operation:         layers.ARPRequest,
		SourceHwAddress:   []byte(iface.HardwareAddr),
		SourceProtAddress: []byte(src),
		DstHwAddress:      []byte{0, 0, 0, 0, 0, 0},
		DstProtAddress:    []byte(target),
	}

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{}

	if err := gopacket.SerializeLayers(buf, opts, &eth, &arp); err != nil {
		log.Fatal("Serialize err:", err)
	}

	log.Printf("%v", buf.Bytes())


	handle, err := pcap.OpenLive(iface.Name, 65536, true, pcap.BlockForever)
	if err != nil {
		log.Fatal("pcap openlive err:", err)
	}

	defer handle.Close()

	if err := handle.WritePacketData(buf.Bytes()); err != nil {
		log.Fatal("write err:", err)
	}


	start := time.Now()
	for {
		if time.Since(start) > time.Second*3 {
			log.Fatal("arp timeout")
			break
		}
		data, _, err := handle.ReadPacketData()
		if err == pcap.NextErrorTimeoutExpired {
			continue
		} else if err != nil {
			log.Fatal("read err", err)
			break
		}

		packet := gopacket.NewPacket(data, layers.LayerTypeEthernet, gopacket.NoCopy)
		if arpLayer := packet.Layer(layers.LayerTypeARP); arpLayer != nil {
			arp := arpLayer.(*layers.ARP)
			if net.IP(arp.SourceProtAddress).Equal(net.IP(target)) {
				log.Printf("%v", net.HardwareAddr(arp.SourceHwAddress))
				break
			}
		}

	}


}
