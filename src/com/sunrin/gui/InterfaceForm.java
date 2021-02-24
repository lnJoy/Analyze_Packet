package com.sunrin.gui;

import com.sunrin.packet.InfoDTO;
import com.sunrin.packet.StartSnffing;
import org.jnetpcap.PcapIf;

import javax.swing.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.util.ArrayList;

public class InterfaceForm extends JFrame {
    private JPanel interPanel;
    private JButton select;
    private JComboBox interface_list;
    private JButton start;
    private JButton stop;
    private JLabel label;
    private JLabel selected;

    public InterfaceForm() {

        ArrayList<PcapIf> devices = InfoDTO.getDevices();

        select.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                try {
                    String item = interface_list.getSelectedItem().toString();
                    selected.setText(item);
                    InfoDTO.setDevice(devices.get(interface_list.getSelectedIndex()));
                    System.out.println("Select : " + devices.get(interface_list.getSelectedIndex()).getDescription());
                } catch (Exception er) {
                    // er.printStackTrace();
                }
            }
        });

        for (PcapIf device : devices) {
            String description = (device.getDescription() != null) ? device.getDescription() : "Not Explain About Device";
            interface_list.addItem(description);
        }

        start.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                try {
                    new StartSnffing();
                } catch (Exception err) {
                    // err.printStackTrace();
                }
            }
        });
    }
}
