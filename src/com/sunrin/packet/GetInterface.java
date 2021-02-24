package com.sunrin.packet;

import org.jnetpcap.Pcap;
import org.jnetpcap.PcapIf;

import java.util.ArrayList;

public class GetInterface {
    public GetInterface() {
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

        InfoDTO.setDevices(allDevs);
    }
}
