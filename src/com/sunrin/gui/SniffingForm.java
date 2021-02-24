package com.sunrin.gui;

import com.sunrin.packet.InfoDTO;

import javax.swing.*;
import java.util.ArrayList;

public class SniffingForm extends JPanel implements Runnable {
    private Thread thread;

    private JPanel snifferPanel;
    private JTextArea SniffingDataList;

    private DefaultListModel model;

    private String before = "";

    public SniffingForm() {
        SniffingDataList = new JTextArea();
        if (thread == null) {
            thread = new Thread(this);
            // thread.start();
        }
    }

    public void setSniffingData(ArrayList<String> getSniffingData) {
        for (String data : getSniffingData) {
            SniffingDataList.append(data);
            // System.out.println(data);
        }
    }

    @Override
    public void run() {
        while(true){
            try {
                if(InfoDTO.getSniffingData() != null) {
                    for (String data : InfoDTO.getSniffingData()) { before += data; }
                    for (String data : InfoDTO.getSniffingData()) {
                        System.out.print(before);
                        if(!SniffingDataList.getText().split("ㅡ")[SniffingDataList.getText().split("ㅡ").length - 1].equals(before))
                            SniffingDataList.append(data);
                        // System.out.println(data);
                    }
                }
                Thread.sleep(1000);
            } catch (Exception e) {
                // e.printStackTrace();
            }
        }
    }
}
