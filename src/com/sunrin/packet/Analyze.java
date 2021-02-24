package com.sunrin.packet;

import org.jnetpcap.Pcap;
import org.jnetpcap.PcapHeader;
import org.jnetpcap.PcapIf;
import org.jnetpcap.nio.JBuffer;
import org.jnetpcap.nio.JMemory;
import org.jnetpcap.packet.JRegistry;
import org.jnetpcap.packet.Payload;
import org.jnetpcap.packet.PcapPacket;
import org.jnetpcap.packet.format.FormatUtils;
import org.jnetpcap.protocol.lan.Ethernet;
import org.jnetpcap.protocol.network.Ip4;
import org.jnetpcap.protocol.tcpip.Tcp;

import java.util.ArrayList;

public class Analyze {
    public Analyze() {

        ArrayList<PcapIf> allDevs = new ArrayList<PcapIf>();

        StringBuilder errbuf = new StringBuilder();

        int r = Pcap.findAllDevs(allDevs, errbuf);

        if (r == Pcap.NOT_OK || allDevs.isEmpty()) {
            System.out.println("Can't Find The Network Device" + errbuf.toString());
            return;
        }

        System.out.println("< Searching Network Device >");
        int i = 0;

        for (PcapIf device : allDevs) {
            String description = (device.getDescription() != null) ? device.getDescription() : "Not Explain About Device";
            System.out.printf("[%d번] : %s [%s]\n", ++i, device.getName(), description);
        }

        PcapIf device = allDevs.get(1);
        System.out.printf("Select Device : %s\n", (device.getDescription() != null) ? device.getDescription() : device.getName());

        int snaplen = 64 * 1024;
        int flags = Pcap.MODE_NON_PROMISCUOUS;
        int timeout = 10 * 1000;
        Pcap pcap = Pcap.openLive(device.getName(), snaplen, flags, timeout, errbuf);

        if (pcap == null) {
            System.out.printf("Network Device Access Failed. Error: " + errbuf.toString());
            return;
        }

        Ethernet eth = new Ethernet();
        Ip4 ip = new Ip4();
        Tcp tcp = new Tcp();

        Payload payload = new Payload();
        PcapHeader header = new PcapHeader(JMemory.POINTER);
        JBuffer buf = new JBuffer(JMemory.POINTER);

        int id = JRegistry.mapDLTToId(pcap.datalink());

        while (pcap.nextEx(header, buf) == Pcap.NEXT_EX_OK) {
            PcapPacket packet = new PcapPacket(header, buf);

            packet.scan(id);

            System.out.printf("[ #%d ] \n", packet.getFrameNumber());
            System.out.println("##################################### Packet #####################################");

            if (packet.hasHeader(eth)) {
                System.out.printf("Start Mac Address = %s\nFinal Mac Address = %s\n", FormatUtils.mac(eth.source()), FormatUtils.mac(eth.destination()));
            }

            if (packet.hasHeader(ip)) {
                System.out.printf("Start IP Address = %s\nFinal IP Address = %s\n", FormatUtils.ip(ip.source()), FormatUtils.ip(ip.destination()));
            }

            if (packet.hasHeader(tcp)) {
                System.out.printf("Start TCP Address = %s\nFinal TCP Address = %s\n", tcp.source(), tcp.destination());
            }
            if (packet.hasHeader(payload)) {
                System.out.printf("Length Of Payload = %d\n", payload.getLength());
                System.out.print(payload.toHexdump());
            }
        }
        pcap.close();
    }
}
