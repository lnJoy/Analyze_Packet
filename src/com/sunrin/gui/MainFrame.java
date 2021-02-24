package com.sunrin.gui;

import com.sunrin.packet.GetInterface;

import javax.swing.*;

public class MainFrame extends JFrame {
    public MainFrame() {
        JFrame frame = new JFrame("Analyze Packet");
        frame.setContentPane(new MainForm().getMainPanel());
        frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        frame.setVisible(true);
        frame.pack();
    }
}
