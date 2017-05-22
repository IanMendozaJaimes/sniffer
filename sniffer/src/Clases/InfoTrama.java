package Clases;

import org.jnetpcap.packet.PcapPacket;

public class InfoTrama {
    
    private PcapPacket packet;
    private String user;
    private int numero;

    public PcapPacket getPacket() {
        return packet;
    }

    public void setPacket(PcapPacket packet) {
        this.packet = packet;
    }

    public String getUser() {
        return user;
    }

    public void setUser(String user) {
        this.user = user;
    }

    public int getNumero() {
        return numero;
    }

    public void setNumero(int numero) {
        this.numero = numero;
    }
}
