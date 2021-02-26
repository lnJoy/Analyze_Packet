package com.sunrin.gui;

import com.sunrin.packet.InfoDTO;

import javax.swing.*;

public class SniffingForm extends JPanel implements Runnable {
    private Thread thread;

    private JPanel snifferPanel;
    private JTextArea SniffingDataList;

    private String before = "";

    public SniffingForm() {

         SniffingDataList.setEditable(false);
         SniffingDataList.setDragEnabled(true);

        if (thread == null) {
            thread = new Thread(this);
            thread.start();
        }
    }

    @Override
    public void run() {
        int cnt = 0;
        while (true) {
            try {
                if (InfoDTO.getSniffingData() != null) {
                    StringBuilder stringBuilder = new StringBuilder();
                    stringBuilder.append(InfoDTO.getSniffingData());

                    String[] previousInfo = SniffingDataList.getText().split("\n");
                    String previousReferer = "";
                    for (String s : previousInfo) {
                        if (s.contains("Referer")) {
                            previousReferer = s.replace("Referer : ", "");
                        }
                    }
                    // System.out.println(previousReferer + ", " + InfoDTO.getReferer());

                    if(cnt == 0 || !previousReferer.equals(InfoDTO.getReferer())) {
                        for (String data : InfoDTO.getSniffingData()) {
                            SniffingDataList.append(data);
                        }
                        cnt++;
                    }
                }
                Thread.sleep(1000);
            } catch (Exception e) {
                // e.printStackTrace();
            }
        }
    }
}
