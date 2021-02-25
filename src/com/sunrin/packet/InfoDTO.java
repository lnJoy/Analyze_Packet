package com.sunrin.packet;

import org.jnetpcap.PcapIf;

import java.util.ArrayList;

public class InfoDTO {
    static private ArrayList<PcapIf> devices;
    static private PcapIf device;

    static private ArrayList<String> SniffingData;
    static private String Referer;

    public static String getReferer() {
        return Referer;
    }

    public static void setReferer(String referer) {
        Referer = referer;
    }

    public static ArrayList<String> getSniffingData() {
        return SniffingData;
    }

    public static void setSniffingData(ArrayList<String> sniffingData) {
        SniffingData = sniffingData;
    }

    public static ArrayList<PcapIf> getDevices() {
        return devices;
    }

    public static void setDevices(ArrayList<PcapIf> devices) {
        InfoDTO.devices = devices;
    }

    public static PcapIf getDevice() {
        return device;
    }

    public static void setDevice(PcapIf device) {
        InfoDTO.device = device;
    }
}
