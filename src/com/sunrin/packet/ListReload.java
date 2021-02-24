package com.sunrin.packet;

import javax.swing.*;

public class ListReload extends Thread{

    private DefaultListModel model;
    private JList SniffingDataList;

    public ListReload(DefaultListModel model, JList SniffingDataList) {
        this.model = model;
        this.SniffingDataList = SniffingDataList;
    }

    @Override
    public void run() {
        while(true) {
            try {
                if(InfoDTO.getSniffingData() != null) {
                    for (String data : InfoDTO.getSniffingData()) {
                        model.addElement(data);
                    }
                    SniffingDataList = new JList(model);
                    Thread.sleep(2000);
                }
//                System.out.println("Hello");
            } catch (Exception e) {
                // e.printStackTrace();
            }
        }
    }
}
