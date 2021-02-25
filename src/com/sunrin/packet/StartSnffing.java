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
import org.jnetpcap.protocol.tcpip.Http;
import org.jnetpcap.protocol.tcpip.Tcp;

import java.net.URLDecoder;
import java.util.ArrayList;

public class StartSnffing extends Thread {

    public void threadInterrupt() {
        this.interrupt();
        return;
    }

    public void run() {
        PcapIf device = InfoDTO.getDevice();
        System.out.printf("Select Device : %s\n", (device.getDescription() != null) ? device.getDescription() : device.getName());

        StringBuilder errbuf = new StringBuilder();

        int snaplen = 64 * 1024;
        int flags = Pcap.MODE_NON_PROMISCUOUS;
        int timeout = 10 * 1000;
        Pcap pcap = Pcap.openLive(device.getName(), snaplen, flags, timeout, errbuf);

        if (pcap == null) {
            System.out.printf("Network Device Access Failed. Error: " + errbuf.toString());
            return;
        }

        Tcp tcp = new Tcp();
        Ethernet eth = new Ethernet();
        Http http = new Http();
        Ip4 ip4 = new Ip4();

        Payload payload = new Payload();
        PcapHeader header = new PcapHeader(JMemory.POINTER);
        JBuffer buf = new JBuffer(JMemory.POINTER);

        int id = JRegistry.mapDLTToId(pcap.datalink()); // Interface Number
//        System.out.println(id);

        while (pcap.nextEx(header, buf) == Pcap.NEXT_EX_OK)
        {
            // while(true){
            try {
                PcapPacket pack = new PcapPacket(header, buf);

                pack.scan(id); // Interface Number

                System.out.println("[ #" + pack.getFrameNumber() + " ] ##################################### Packet #####################################");

                if (pack.hasHeader(tcp) && pack.hasHeader(http))
                {
                    pack.getHeader(eth);
                    pack.getHeader(tcp);
                    pack.getHeader(ip4);

                    if (tcp.destination() == 80) {
                        if (http.hasField(Http.Request.Accept) && http.fieldValue(Http.Request.Accept).contains("text/html")) {

                            String dstIp = FormatUtils.ip(ip4.destination());
                            String srcIp = FormatUtils.ip(ip4.source());
                            String dstMac = FormatUtils.mac(eth.destination());
                            String srcMac = FormatUtils.mac(eth.source());

                            String host = http.fieldValue(Http.Request.Host);
                            String url = host + http.fieldValue(Http.Request.RequestUrl);
                            String referer = http.fieldValue(Http.Request.Referer);

                            System.out.println("Source IP = " + srcIp + " || " + "Destination IP = " + dstIp);
                            System.out.println("Source MAC = " + srcMac + " || " + "Destination MAC = " + dstMac);
                            System.out.println("Host : " + host);
                            System.out.println("Url : " + url);
                            System.out.println("Referer : " + referer);

                            System.out.println(http.toString());

                            if (http.contentType().contains("application/x-www-form-urlencoded")) {
                                String data = new String(tcp.getPayload());
                                ArrayList<String> SnffingData = new ArrayList<>();
                                SnffingData.add("Referer : " + referer + "\n");
                                data = URLDecoder.decode(data.split("\n")[data.split("\n").length - 1]);
                                System.out.println(data);
                                for (String parameter : data.split("&")) {
                                    System.out.println(parameter);
                                    SnffingData.add(parameter + "\n");
                                }

                                SnffingData.add("--------------------------------\n");
//                            System.out.println(SnffingData);
                                InfoDTO.setSniffingData(SnffingData);
                                InfoDTO.setReferer(referer);
//                            SniffingForm sniffingForm = new SniffingForm();
//                            sniffingForm.run();
//                            new SniffingForm();

                            }

                            // RecorderService.recordHttpRequest(srcMac, srcIp, dstIp, host, url, referer);
                            // superFlowMap.nextPacket(packet, superFlowMap);
                            // https://nealvs.wordpress.com/2013/12/16/using-jnetpcap-to-read-http-packets/
                        }
                    }
                }
            } catch (Exception e) {
                e.printStackTrace();
            }
        }
    }

}
