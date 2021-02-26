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

public class StartSnffing implements Runnable {

    private Thread thisThread;
    private String threadName;

    final private static int STATE_INIT = 0x1;
    final private static int STATE_STARTED = 0x1 << 1;
    final private static int STATE_SUSPENDED = 0x1 << 2;
    final private static int STATE_STOPPED = 0x1 << 3;

    final private Tcp tcp = new Tcp();
    final private Ethernet eth = new Ethernet();
    final private Http http = new Http();
    final private Ip4 ip4 = new Ip4();

    final private int snaplen = 64 * 1024;
    final private int flags = Pcap.MODE_NON_PROMISCUOUS;
    final private int timeout = 1 * 1000;
    private StringBuilder errbuf = new StringBuilder();

    private static PcapIf device;

    private Pcap pcap;

    private volatile int stateCode = STATE_INIT;

    public StartSnffing() {
    }

    public StartSnffing(String threadName) {
        this.threadName = threadName;
    }

    public void start() {
        synchronized (this) {
            if (stateCode == STATE_STARTED)
                throw new IllegalStateException("already started");

            device = InfoDTO.getDevice();
            System.out.printf("Select Device : %s\n", (device.getDescription() != null) ? device.getDescription() : device.getName());
            pcap = Pcap.openLive(device.getName(), snaplen, flags, timeout, errbuf);

            thisThread = new Thread(this);
            if (threadName != null) thisThread.setName(threadName);
            thisThread.start();
            stateCode = STATE_STARTED;
        }
    }

    public void stop() {
        synchronized (this) {
            if (stateCode == STATE_STOPPED)
                throw new IllegalStateException("already stopped");
            this.stateCode = STATE_STOPPED;
            pcap.close();
            thisThread.interrupt();
        }
    }

    public void resume() {
        synchronized (this) {
            if (stateCode == STATE_STARTED || stateCode == STATE_INIT) return;
            if (stateCode == STATE_STOPPED)
                throw new IllegalStateException("already stopped");
            stateCode = STATE_STARTED;
            thisThread.interrupt(); // 꼭 해줘야 한다.
        }
    }

    public void suspend() {
        synchronized (this) {
            if (stateCode == STATE_SUSPENDED) return;
            if (stateCode == STATE_INIT)
                throw new IllegalStateException("not started yet");
            if (stateCode == STATE_STOPPED)
                throw new IllegalStateException("already stopped");
            stateCode = STATE_SUSPENDED;
        }
    }

    public void run() {

        PcapHeader header = new PcapHeader(JMemory.POINTER);
        JBuffer buf = new JBuffer(JMemory.POINTER);

        int id = JRegistry.mapDLTToId(pcap.datalink()); // Interface Number

        while (true) {
            // 상태 코드가 일시 정지라면 while문에서 계속 대기하도록 한다.
            while (stateCode == STATE_SUSPENDED) {
                try {
                    System.out.println("[handle] suspending...");
                    Thread.sleep(24 * 60 * 60 * 1000);
                } catch (InterruptedException e) {
                    if (stateCode != STATE_SUSPENDED) {
                        System.out.println("[handle] resuming...");
                        break;
                    }
                }
            }

            if (stateCode == STATE_STOPPED) {
                System.out.println("[handle] stopping...");
                break;
            }
            processComplexJob(header, buf, id);
        }
    }

    private void processComplexJob(PcapHeader header, JBuffer buf, int id) {
        if (pcap.nextEx(header, buf) == Pcap.NEXT_EX_OK || true) {
            try {
                PcapPacket pack = new PcapPacket(header, buf);

                pack.scan(id); // Interface Number

                System.out.println("[ #" + pack.getFrameNumber() + " ] Packet");

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

//                            System.out.println(http.toString());

                            try {
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

                                    InfoDTO.setSniffingData(SnffingData);
                                    InfoDTO.setReferer(referer);
                                }
                            } catch (Exception er) {
                                // er.printStackTrace();
                            }

                            // RecorderService.recordHttpRequest(srcMac, srcIp, dstIp, host, url, referer);
                            // superFlowMap.nextPacket(packet, superFlowMap);
                            // https://nealvs.wordpress.com/2013/12/16/using-jnetpcap-to-read-http-packets/
                        }
                    }
                }
            } catch (Exception e) {
//                e.printStackTrace();
            }
        } else {
            pcap.close();
        }
    }
}