package com.sunrin.gui;

import com.sunrin.packet.InfoDTO;
import com.sunrin.packet.ListReload;

import javax.swing.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;

public class SniffingForm extends JFrame {
    private JPanel snifferPanel;
    private JList SniffingDataList;
    private JButton button1;

    private DefaultListModel model;

    public SniffingForm() {
//        new ListReload(model, SniffingDataList).start();

        button1.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                if(InfoDTO.getSniffingData() != null) {

                    // SniffingDataList = new JList(model);
                }
                for (String data : InfoDTO.getSniffingData()) {
                    model.addElement(data);
                    System.out.println(data);
                }
            }
        });
    }
}
