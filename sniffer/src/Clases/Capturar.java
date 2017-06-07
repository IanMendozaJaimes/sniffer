package Clases;

import java.io.File;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import javax.swing.DefaultListModel;
import javax.swing.JList;
import javax.swing.JTextArea;
import org.jnetpcap.JBufferHandler;
import org.jnetpcap.Pcap;
import org.jnetpcap.PcapAddr;
import org.jnetpcap.PcapBpfProgram;
import org.jnetpcap.PcapDumper;
import org.jnetpcap.PcapHandler;
import org.jnetpcap.PcapHeader;
import org.jnetpcap.PcapIf;
import org.jnetpcap.nio.JBuffer;
import org.jnetpcap.packet.PcapPacket;
import org.jnetpcap.packet.PcapPacketHandler;

public class Capturar {
    private List<PcapIf> dispositivos;
    private StringBuilder err;
    private Pcap pcap;
    private JTextArea consola;
    
    public Capturar(JTextArea con){
        dispositivos = new ArrayList<PcapIf>();
        err = new StringBuilder();
        pcap = null;
        consola = con;
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
    
    //sin paramentros, es una captura al vuelo
    public void capturarTramas() throws IOException{
        obtenerDispositivos();
        imprimirDispositivos();
        
        int num_dispositivo = 0;
        Configuracion conf = new Configuracion();
        
        num_dispositivo = getNumeroDispositivo(conf.getMAC());
        if(num_dispositivo == -1){
            imprimir("No hay una direccion mac válida, configurala por favor.");
            return;
        }
        
        PcapIf dispositivo = dispositivos.get(num_dispositivo);
        
        int snaplen = 64 * 1024;
        int flags = conf.getPromiscuo();
        int timeout = (int) (conf.getTiempo() * 1000);
        
        pcap = Pcap.openLive(dispositivo.getName(), snaplen, flags, timeout, err);
        
        if(pcap == null){
            imprimir("Error al abrir el dispositivo para capturar" + err.toString());
            return;
        }
        
        filtro();
    }
    
    public void capturarTramas(int bandera, String expr) throws IOException{
        obtenerDispositivos();
        imprimirDispositivos();
        
        int num_dispositivo = 0;
        Configuracion conf = new Configuracion();
        
        num_dispositivo = getNumeroDispositivo(conf.getMAC());
        if(num_dispositivo == -1){
            imprimir("No hay una direccion mac válida, configurala por favor.");
            return;
        }
        
        PcapIf dispositivo = dispositivos.get(num_dispositivo);
        
        int snaplen = 64 * 1024;
        int flags = conf.getPromiscuo();
        int timeout = (int) (conf.getTiempo() * 1000);
        
        pcap = Pcap.openLive(dispositivo.getName(), snaplen, flags, timeout, err);
        
        if(pcap == null){
            imprimir("Error al abrir el dispositivo para capturar" + err.toString());
            return;
        }
        
        filtro(expr);
    }
    
    public int getNumeroDispositivo(String mac) throws IOException{
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
    
    //con parametro, es una captura de un archivo
    public void capturarTramas(String nomArchivo){
        pcap = Pcap.openOffline(nomArchivo, err);
        if(pcap == null){
            System.err.printf("Error al abrir el archivo a capturar: " + err.toString());
            return;
        }
    }
    
    
    private void filtro(){
        PcapBpfProgram filtro = new PcapBpfProgram();
        String expresion = ""; //puerto 80
        int optimize = 0; //1 es true, 0 false
        int netmask = 0;
        int r2d2 = pcap.compile(filtro, expresion, optimize, netmask);
        
        if(r2d2 != Pcap.OK){
            imprimir("Error: " + pcap.getErr());
        }
        
        pcap.setFilter(filtro);
    }
    
    private void filtro(String expr){
        imprimir(expr);
        PcapBpfProgram filtro = new PcapBpfProgram();
        String expresion = expr; //puerto 80
        int optimize = 0; //1 es true, 0 false
        int netmask = 0;
        int r2d2 = pcap.compile(filtro, expresion, optimize, netmask);
        
        if(r2d2 != Pcap.OK){
            imprimir("Error: " + pcap.getErr());
        }
        
        pcap.setFilter(filtro);
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
    
    public void guardar(String nombreArchivo, int num_tramas){
        PcapDumper dumper = pcap.dumpOpen(nombreArchivo);
        pcap.loop(num_tramas, dumper);
        dumper.close();
        imprimir("Se guardo con exito el arhcivo: " + nombreArchivo + ", con un número de tramas de: " + num_tramas);
    }
    
    public InfoTrama manejadorPaquetes(){
        final InfoTrama info = new InfoTrama();
        PcapPacketHandler<String> manejador = new PcapPacketHandler<String>(){
            @Override
            public void nextPacket(PcapPacket packet, String user) {
                info.setPacket(packet);
                info.setUser(user);

                System.out.printf("\n\nPaquete recibido el %s caplen=%-4d longitud=%-4d %s\n\n",
				    new Date(packet.getCaptureHeader().timestampInMillis()),
				    packet.getCaptureHeader().caplen(),  // Length actually captured
				    packet.getCaptureHeader().wirelen(), // Original length
				    user                                 // User supplied object
				    );
                /******Desencapsulado********/
                for(int i=0;i<packet.size();i++){
                System.out.printf("%02X ",packet.getUByte(i));
                if(i%16==15)
                    System.out.println("");
                }
                //System.out.println("\n\nEncabezado: "+ packet.toHexdump());
                info.analizarTrama();
            }
        };
        pcap.loop(1, manejador, " ");
        return info;
    }
    
    public void imprimir(String texto){
        consola.setText(consola.getText() + "\n" + texto);
    }
}
