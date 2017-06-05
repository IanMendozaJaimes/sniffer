package Clases;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.List;
import javax.swing.JTextArea;
import org.jnetpcap.Pcap;
import org.jnetpcap.PcapAddr;
import org.jnetpcap.PcapIf;

public class Generar {
    private Pcap pcap;
    private ByteBuffer tramaLista;
    private JTextArea consola;
    private List<PcapIf> dispositivos;
    private StringBuilder err;
    
    public Generar(JTextArea con){
        dispositivos = new ArrayList<PcapIf>();
        err = new StringBuilder();
        pcap = null;
        consola = con;
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


