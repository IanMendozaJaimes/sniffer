package Clases;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import javax.swing.JTextArea;
import org.jnetpcap.Pcap;
import org.jnetpcap.PcapAddr;
import org.jnetpcap.PcapIf;

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
                consola.setText(consola.getText() + direccion.getAddr().toString() + "\n");
            }
            i++;
        }
    }
    
    public void capturarTramas(){
        obtenerDispositivos();
        
    }
    
    public void capturarTramas(String nomArchivo){
        pcap = Pcap.openOffline(nomArchivo, err);
        if(pcap == null){
            System.err.printf("Error al abrir el archivo a capturar: " + err.toString());
            return;
        }
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
