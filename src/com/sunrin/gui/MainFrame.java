package com.sunrin.gui;

import com.sunrin.packet.GetInterface;

import javax.swing.*;

public class MainFrame extends JFrame {
    public MainFrame() {
        JFrame frame = new JFrame("Analyze Packet");
        frame.setContentPane(new MainForm().getMainPanel());
        frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        frame.setSize(480, 320);
        frame.setResizable(false);
        frame.setVisible(true);
        frame.pack();
    }
}
