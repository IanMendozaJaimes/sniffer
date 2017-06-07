package Clases;

import static Clases.Checksum.calculateChecksum;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import javax.swing.JTextArea;
import org.jnetpcap.Pcap;
import org.jnetpcap.PcapAddr;
import org.jnetpcap.PcapIf;
import org.jnetpcap.PcapSockAddr;

public class Generar {
    private Pcap pcap;
    private ByteBuffer tramaLista;
    private JTextArea consola;
    private List<PcapIf> dispositivos;
    private StringBuilder err;
    private String interfaz;
    private PcapIf disp;
    
    public Generar(JTextArea con, String interfaz){
        dispositivos = new ArrayList<PcapIf>();
        err = new StringBuilder();
        pcap = null;
        consola = con;
        this.interfaz = interfaz;
    }
    
    public void enviarTrama(byte[] trama){
        tramaLista = ByteBuffer.wrap(trama);
        if(pcap.sendPacket(tramaLista) != Pcap.OK){
            imprimir("Ha ocurrido un error al enviar la trama: " + pcap.getErr());
        }
    }
    
    public void obtenerDispositivos(){
        int r = Pcap.findAllDevs(dispositivos, err);
        if(r == Pcap.NOT_OK || dispositivos.isEmpty()){
            System.err.printf("No es posible leer los dispositivos: %s", err.toString());
        }
    }
    
    public void imprimirDispositivos() throws IOException{
        int i = 0;
        for(PcapIf dispositivo:dispositivos){
            String descripcion = (dispositivo.getDescription() != null) ? dispositivo.getDescription():"No hay una descripción disponible";
            final byte[] mac = dispositivo.getHardwareAddress();
            String dir_mac = (mac==null)?"No tiene dirección MAC":asString(mac);
            consola.setText(consola.getText() + "#" + i + ": " + dispositivo.getName() + "["+ descripcion +"] MAC:[" + dir_mac + "]\n");
            List<PcapAddr> direcciones = dispositivo.getAddresses();
            for(PcapAddr direccion:direcciones){
                imprimir(direccion.getAddr().toString() + "\n");
            }
            i++;
        }
    }
    
    private void iniciarPcap() throws IOException{
        obtenerDispositivos();
        disp = dispositivos.get(getNumeroDispositivo(interfaz));
        int snaplen = 1000 * 1024; // Capture all packets, no trucation  
        int flags = Pcap.MODE_PROMISCUOUS; // capture all packets  
        int timeout = 2000; // 10 seconds in millis  
        pcap = Pcap.openLive(disp.getName(), snaplen, flags, timeout, err);
    }
    
    private int getNumeroDispositivo(String mac) throws IOException{
        int num = 0;
        
        for(PcapIf dispositivo:dispositivos){
           byte[] macArreglo = dispositivo.getHardwareAddress();
           String dir_mac = (macArreglo==null)?"No tiene dirección MAC":asString(macArreglo);
           if(dir_mac.equals(mac)){
               return num;
           }
           num++;
        }
        
        return -1;
    }
    
    public byte[] generarARP(String ipDestino) throws IOException{
        byte trama[] = new byte[42];
        byte mac[];
        
        iniciarPcap();
        mac = disp.getHardwareAddress();
        
        //mac destino
        for(int i = 0; i < 6; i++){
            trama[i] = (byte) 0xFF;
        }
        
        //mac origen
        for(int i = 6; i < 12; i++){
            trama[i] = mac[i - 6];
        }
        
        //tipo 
        trama[12] = (byte) 0x08;
        trama[13] = (byte) 0x06;
        
        //tipo de hardware
        trama[14] = (byte) 0x00;
        trama[15] = (byte) 0x01;
        
        //tipo de protocolo
        trama[16] = (byte) 0x08;
        trama[17] = (byte) 0x00;
        
        //tam de hardware
        trama[18] = (byte) 0x06;
        
        //tam protocolo
        trama[19] = (byte) 0x04;
        
        //tipo de operacion, en este caso de pregunta
        trama[20] = (byte) 0x00;
        trama[21] = (byte) 0x01;
        
        //mac remitente
        for(int i = 22; i < 28; i++){
            trama[i] = mac[i - 22];
        }
        
        //ip remitente
        byte ip[] = getIP();
        for(int i = 28; i < 32; i++){
            trama[i] = ip[i - 28];
        }
        
        //mac destino
        for(int i = 32; i < 38; i++){
            trama[i] = (byte) 0x00;
        }
        
        //ip destino
        byte ipD[] = convertirIP(ipDestino);
        for(int i = 38; i < 42; i++){
            trama[i] = ipD[i - 38];
        }
        
        return trama;
    }
    
    public byte[] generarICMP() throws IOException{
        byte trama[] = new byte[38];
        
        byte mac[];
        
        iniciarPcap();
        mac = disp.getHardwareAddress();
        
        //===================ETHERNET=====================//
        
        //mac destino
        for(int i = 0; i < 6; i++){
            trama[i] = (byte) 0xFF;
        }
        
        //mac origen
        for(int i = 6; i < 12; i++){
            trama[i] = mac[i - 6];
        }
        
        //tipo
        trama[12] = (byte) 0x80;
        trama[13] = (byte) 0x00;
                
        //==============EMPEZAMOS CON IP===============//
        
        //version y IHL
        trama[14] = (byte) 0x45;
        
        //servicios diferenciados
        trama[15] = (byte) 0x00;
        
        //tam total
        trama[16] = (byte) 0x00;
        trama[17] = (byte) 0x18;
        
        //identificador
        trama[18] = (byte) 0x44;
        trama[19] = (byte) 0x44;
        
        //banderas
        trama[20] = (byte) 0x00;
        
        //offset
        trama[21] = (byte) 0x00;
        
        //tiempo de vida
        trama[22] = (byte) 0xFF;
        
        //protocolo, aqui es donde le decimos que va el ICMP
        trama[23] = (byte) 0x01;
        
        //checksum, todavia no tenemos la cabecera completa asi que lo ponemos en cero, de momento claro
        trama[24] = (byte) 0x00;
        trama[25] = (byte) 0x00;
        
        //ip origen
        byte ip[] = getIP();
        for(int i = 26; i < 30; i++){
            trama[i] = ip[i - 26];
        }
        
        //ip destino
        for(int i = 30; i < 34; i++){
            trama[i] = (byte) 0xFF;
        }
        
        //ahora si, calculamos el checksum
        byte temp[] = new byte[20];
        for(int i = 0; i < temp.length; i++){
            temp[i] = trama[i+14];
        }
        long tem = calculateChecksum(temp);
        trama[24] = (byte) (tem >> 8);
        trama[25] = (byte) tem;
        
        //============ICMP==============//
        
        //tipo
        trama[34] = (byte) 0x08;
        
        //codigo
        trama[35] = (byte) 0x00;
        
        //checksum, lo mesmo
        trama[36] = (byte) 0x00;
        trama[37] = (byte) 0x00;
        
        byte temp2[] = new byte[4];
        for (int i = 0; i < 4; i++) {
            temp2[i] = trama[i+34];
        }
        long tem2 = calculateChecksum(temp2);
        trama[36] = (byte) (tem2 >> 8);
        trama[37] = (byte) tem2;
        
        return trama;
    }
    
    private byte[] convertirIP(String ip){
        byte ipConvertida[] = new byte[4];
        int i = 0;
        
        String temp[] = new String[4];
        temp[0] = "";
        temp[1] = "";
        temp[2] = "";
        temp[3] = "";
        
        for(int k = 0; k < ip.length(); k++){
            if(ip.charAt(k) != '.')
                temp[i] += ip.charAt(k);
            else
                i++;
        }
        
        System.out.println("ME LLEGO: " + temp.length);
        
        i = 0;
        for(String n:temp){
            System.out.println(n);
            ipConvertida[i] = (byte) Integer.parseInt(n);
            i++;
        }
        
        return ipConvertida;
    }
    
    private byte[] getIP(){
        byte ip[] = new byte[4];

        Iterator<PcapAddr> it1 = disp.getAddresses().iterator();

        while(it1.hasNext()){
            PcapAddr dir = it1.next();//dir, familia, mascara,bc
            PcapSockAddr direccion1 = dir.getAddr();
            byte[]d_ip = direccion1.getData(); //esta sera la ip origen
            int familia=direccion1.getFamily();
            int[]ipv4_1 = new int[4];

            if(familia==org.jnetpcap.PcapSockAddr.AF_INET){
                ipv4_1[0]=((int)d_ip[0]<0)?((int)d_ip[0])+256:(int)d_ip[0];
                ipv4_1[1]=((int)d_ip[1]<0)?((int)d_ip[1])+256:(int)d_ip[1];
                ipv4_1[2]=((int)d_ip[2]<0)?((int)d_ip[2])+256:(int)d_ip[2];
                ipv4_1[3]=((int)d_ip[3]<0)?((int)d_ip[3])+256:(int)d_ip[3];
                String ip_interfaz = ipv4_1[0]+"."+ipv4_1[1]+"."+ipv4_1[2]+"."+ipv4_1[3];
                System.out.println("LA IP ES: " + ip_interfaz);
                ip[0] = (byte) ipv4_1[0];
                ip[1] = (byte) ipv4_1[1];
                ip[2] = (byte) ipv4_1[2];
                ip[3] = (byte) ipv4_1[3];
                System.out.printf("%02x %02x %02x %02x", ip[0], ip[1], ip[2], ip[3]);
            }
            
        }
        
        return ip;
    }
    
    public void imprimir(String texto){
        consola.setText(consola.getText() + "\n" + texto);
    }
    
    private static String asString(final byte[] mac){
        final StringBuilder buf = new StringBuilder();
        for(byte b:mac){
            if(buf.length() != 0){
                buf.append(':');
            }
            if(b >= 0 && b < 16){
                buf.append('0');
            }
            buf.append(Integer.toHexString((b < 0)? b + 256:b).toUpperCase());
        }
        return buf.toString();
    }
}


