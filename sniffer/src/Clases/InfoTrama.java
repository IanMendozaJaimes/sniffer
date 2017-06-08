package Clases;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.Date;
import org.jnetpcap.packet.PcapPacket;
import org.jnetpcap.protocol.network.Arp;
import org.jnetpcap.protocol.network.Icmp;
import org.jnetpcap.protocol.network.Ip4;
import org.jnetpcap.protocol.tcpip.Tcp;
import org.jnetpcap.protocol.tcpip.Udp;

public class InfoTrama {
    
    private PcapPacket packet;
    private String user;
    private int numero;
    private byte[] origen;
    private byte[] destino;
    private int tipo;
    private int tam;
    private int contador;
    private String origenEscrito;
    private String destinoEscrito;
    private String tipoEscrito;
    private String tiempoEscrito;
    private String analisisEscrito;
    private String tamEscrito;
    
    public InfoTrama(){
        origen = new byte[6];
        destino = new byte[6];
    }

    public int getTam() {
        return tam;
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
    
    private String getTramaCompleta(){
        StringBuilder buf = new StringBuilder();
        buf.append("\n\t");
        for (int i = 0; i < packet.size(); i++) {
            if(packet.getByte(i) >= 0 && packet.getByte(i) < 16){
                buf.append('0');
            }
            buf.append(Integer.toHexString((packet.getByte(i) < 0)? packet.getByte(i) + 256:packet.getByte(i)).toUpperCase());
            buf.append(" ");
            if(i%16 == 15){
                buf.append("\n\t");
            }
        }
        return buf.toString();
    }
    
    private static String getIP(byte[] arreglo){
        StringBuilder buf = new StringBuilder();
        for(byte b:arreglo){
            if(buf.length() != 0){
                buf.append('.');
            }
            buf.append((b < 0)? b + 256:b);
        }
        return buf.toString();
    }
    
    public void analizarTrama(){
        ByteBuffer bf = ByteBuffer.allocate(2);
        bf.order(ByteOrder.BIG_ENDIAN);
       
        for(int i = 0; i < 12; ++i){
            if(i < 6){
                destino[i] = packet.getByte(i);
            }
            else{
                origen[i-6] = packet.getByte(i);
            }
        }
        
        origenEscrito = asString(origen);
        destinoEscrito = asString(destino);
        
        bf.put(packet.getByte(12));
        bf.put(packet.getByte(13));
        
        tipo = bf.getShort(0);
        tipo &= 0xffff;
        
        tam = packet.getCaptureHeader().wirelen();
        tamEscrito = String.valueOf(tam);
        
        tiempoEscrito = String.valueOf(new Date(packet.getCaptureHeader().timestampInMillis()).getSeconds() / 60f);
        
        analisisEscrito = "TRAMA" + getTramaCompleta() + "\n\n";
       
        for(int i=0;i<packet.size();i++){
            System.out.printf("%02X ",packet.getUByte(i));
            if(i%16==15)
                System.out.println("");
        }
        
        if(tipo > 1500){
            manejarEthernet();
        }
        else{
            manejarIEEE();
        }
    }
    
    private void manejarEthernet(){
        Ip4 ip = new Ip4();
        tipoEscrito = "ETHERNET";
        analisisEscrito += "ETHERNET II \n\tDestino: " + destinoEscrito + "\n\tOrigen: " + origenEscrito + "\n\n";
        if(packet.hasHeader(ip)){
            analisisEscrito += "INTERNET PROTOCOL Version 4";
            analisisEscrito += "\n\tVersion: " + ip.version();
            analisisEscrito += "\n\tIHL: " + ip.hlen();
            analisisEscrito += "\n\tServicios diferenciados: " + ip.tos_ECN();
            analisisEscrito += "\n\tLongitud total: " + ip.length();
            analisisEscrito += "\n\tIdentificador: " + ip.id();
            analisisEscrito += "\n\tBanderas:";
            analisisEscrito += "\n\t\t" + ip.flags_DFDescription();
            analisisEscrito += "\n\tOffset: " + ip.offset();
            analisisEscrito += "\n\tTTL: " + ip.ttl();
            analisisEscrito += "\n\tProtocolo: " + ip.type();
            analisisEscrito += "\n\tChecksum: " + ip.checksum();
            analisisEscrito += "\n\tIP Origen: " + getIP(ip.source());
            analisisEscrito += "\n\tIP Destino: " + getIP(ip.destination()) + "\n\n";
            Tcp tcp = new Tcp();
            if(packet.hasHeader(tcp)){
                tipoEscrito = "TCP";
                analisisEscrito += "TRANSMISSION CONTROL PROTOCOL";
                analisisEscrito += "\n\tPuerto origen: " + tcp.source();
                analisisEscrito += "\n\tPuerto destino: " + tcp.destination();
                analisisEscrito += "\n\tSecuencia: " + tcp.seq();
                analisisEscrito += "\n\tACK: " + tcp.ack();
                analisisEscrito += "\n\tIHL: " + tcp.hlen();
                analisisEscrito += "\n\tRSV: " + tcp.reserved();
                analisisEscrito += "\n\tBanderas:";
                analisisEscrito += "\n\t\tCWR: " + tcp.flags_CWR();
                analisisEscrito += "\n\t\tECE: " + tcp.flags_ECE();
                analisisEscrito += "\n\t\tURG: " + tcp.flags_URG();
                analisisEscrito += "\n\t\tACK: " + tcp.flags_ACK();
                analisisEscrito += "\n\t\tPSH: " + tcp.flags_PSH();
                analisisEscrito += "\n\t\tRST: " + tcp.flags_RST();
                analisisEscrito += "\n\t\tSYN: " + tcp.flags_SYN();
                analisisEscrito += "\n\t\tFIN: " + tcp.flags_FIN();
                analisisEscrito += "\n\tVentana: " + tcp.window();
                analisisEscrito += "\n\tChecksum: " + tcp.checksum();
                analisisEscrito += "\n\tApuntador urgente: " + tcp.urgent();
            }
            else{
                Udp udp = new Udp();
                if(packet.hasHeader(udp)){
                    tipoEscrito = "UDP";
                    analisisEscrito += "USER DATAGRAM PROTOCOL";
                    analisisEscrito += "\n\tPuerto origen: " + udp.source();
                    analisisEscrito += "\n\tPuerto destino: " + udp.destination();
                    analisisEscrito += "\n\tLongitud: " + udp.length();
                    analisisEscrito += "\n\tChecksum: " + udp.checksum() + " " + udp.checksumDescription();
                }
                else{
                    Icmp icmp = new Icmp();
                    if(packet.hasHeader(icmp)){
                        tipoEscrito = "ICMP";
                        analisisEscrito += "INTERNET CONTROL MESSAGE PROTOCOL";
                        analisisEscrito += "\n\tTipo: " + icmp.type() + " " + icmp.typeDescription();
                        analisisEscrito += "\n\tCódigo: " + icmp.code();
                        analisisEscrito += "\n\tChecksum: " + icmp.checksum() + " " + icmp.checksumDescription();
                    }
                    else{
                        tipoEscrito = "IP";
                    }
                }
            }
        }
        else{
            Arp arp = new Arp();
            if(packet.hasHeader(arp)){
                tipoEscrito = "ARP";
                analisisEscrito += "ADDRESS RESOLUTION PROTOCOL";
                analisisEscrito += "\n\tTipo de harware: " + arp.hardwareType() + " " + arp.hardwareTypeDescription();
                analisisEscrito += "\n\tTipo de protocolo: " + arp.protocolType() + " " + arp.protocolTypeDescription();
                analisisEscrito += "\n\tHLEN: " + arp.hlen();
                analisisEscrito += "\n\tPLEN: " + arp.plen();
                analisisEscrito += "\n\tOperación: " + arp.operation() + " " + arp.operationDescription();
                analisisEscrito += "\n\tMAC del Remitente: " + asString(arp.sha());
                analisisEscrito += "\n\tIP del Remitente: " + getIP(arp.spa());
                analisisEscrito += "\n\tMAC del Destinatario: " + asString(arp.tha());
                analisisEscrito += "\n\tIP del Destinatario: " + getIP(arp.tpa());
            }
        }
    }
    
    private void manejarIEEE(){
        tipoEscrito = "LLC";
        analisisEscrito += "LOGICAL LINK CONTROL";
        int dsap = packet.getUByte(14)& 0x00000001;
        String i_g = (dsap==1)?"G":(dsap==0)?"I":"Otro";
        //System.out.printf("\n |-->DSAP: %02X   %s",packet.getUByte(14),i_g);
        analisisEscrito += "\n\tDSAP: " + String.format("%02X", packet.getUByte(14)) + " " + i_g;
        int ssap = packet.getUByte(15)& 0x00000001;
        String c_r = (ssap==1)?"Respuesta":(ssap==0)?"Comando":"Otro";
        //System.out.printf("\n |-->SSAP: %02X   %s",packet.getUByte(15), c_r);
        analisisEscrito += "\n\tSSAP: " + String.format("%02X", packet.getUByte(15)) + " " + c_r;

        String binary="", binary2="", Auxbinary="", Auxbinary2="";
        if(packet.getUByte(13)<=3){                                        
            binary = Integer.toBinaryString(packet.getUByte(16));
            for (int i = binary.length(); i < 8; i++) {
            binary = "0" + binary;
            }
            for(int j = binary.length()-1; j >=0; j--){
                Auxbinary = Auxbinary + binary.charAt(j);
            }
            //System.out.printf("\n |-->Campo de control:" + Auxbinary);
            analisisEscrito += "\n\tCampo de control: " + Auxbinary;

        }
        else{//invertir cadena de bits del control para analisis 
            binary = Integer.toBinaryString(packet.getUByte(16));
            binary2 = Integer.toBinaryString(packet.getUByte(17));
            for (int i = binary.length(); i < 8; i++) {
            binary = "0" + binary;
            }
            for (int i = binary2.length(); i < 8; i++) {
            binary2 = "0" + binary2;
            }
            for(int j = binary.length()-1; j >=0; j--){
                Auxbinary = Auxbinary + binary.charAt(j);
            }
            for(int j = binary2.length()-1; j >=0; j--){
                Auxbinary2 = Auxbinary2 + binary2.charAt(j);
            }
            Auxbinary=Auxbinary.concat(Auxbinary2);
            //System.out.printf("\n |-->Campo de control:" + Auxbinary);
            analisisEscrito += "\n\tCampo de control: " + Auxbinary;
        }
                String TipoTrama="";
                String Trama="";
                String PF="";
                if(Auxbinary.charAt(0)=='1' && Auxbinary.charAt(1)=='1')
                {
                    Trama="U";
                    for(int k=0; k < 8; k++){
                        if(k==4){
                            PF=PF+Auxbinary.charAt(k);
                        }    
                        if(k==0 || k==1 || k==4){
                            continue;
                        }
                        else{
                            TipoTrama= TipoTrama + Auxbinary.charAt(k);
                        }
                    }

                }

                String AuxNR="", AuxNS="",AuxNR2="", AuxNS2="";
                int NS=0, NR=0;

                if(Auxbinary.charAt(0)=='1' && Auxbinary.charAt(1)=='0'){
                    Trama="S";
                    for(int k=0; k < Auxbinary.length(); k++){
                        if(k>=9){
                            AuxNR=AuxNR+Auxbinary.charAt(k);
                        }
                        if(k==8){
                            PF=PF+Auxbinary.charAt(k);
                        }
                        if(k==2 || k==3){
                            TipoTrama= TipoTrama + Auxbinary.charAt(k);
                        }
                    }
                    //System.out.printf("\n |-->NrBinary:" + AuxNR);
                    analisisEscrito += "\n\tNrBinary: " + AuxNR;
                    for (int x=AuxNR.length()-1;x>=0;x--){
                        AuxNR2= AuxNR2 + AuxNR.charAt(x);
                    }                                                
                    NR=Integer.parseInt(AuxNR2,2);                                                
                }

                if(Auxbinary.charAt(0)=='0'){
                    Trama="I";
                    for(int k=0; k < Auxbinary.length(); k++){
                        if(k==8){
                            PF=PF+Auxbinary.charAt(k);
                        }
                        if(k>0 && k<8){
                            AuxNS=AuxNS+Auxbinary.charAt(k);
                        }
                        if(k>8 && k<16){
                            AuxNR=AuxNR+Auxbinary.charAt(k);
                        }
                    }
                    //System.out.printf("\n |-->NsBinary:" + AuxNS);
                    //System.out.printf("\n |-->NrBinary:" + AuxNR);
                    
                    analisisEscrito += "\n\tNsBinary: " + AuxNS;
                    analisisEscrito += "\n\tNrBinary: " + AuxNR;

                    for (int x=AuxNS.length()-1;x>=0;x--){
                        AuxNS2= AuxNS2 + AuxNS.charAt(x);
                    }
                    for (int x=AuxNR.length()-1;x>=0;x--){
                        AuxNR2= AuxNR2 + AuxNR.charAt(x);
                    }
                    NS=Integer.parseInt(AuxNS2,2);
                    NR=Integer.parseInt(AuxNR2,2);
                }

                //System.out.printf("\n |-->P/F:" + PF);
                analisisEscrito += "\n\tP/F: " + PF;

            if(Trama.compareTo("I")==0){
                //System.out.printf("\n |-->Tipo de trama:" + Trama);
                //System.out.printf("\n |-->N(S): %d", NS);
                //System.out.printf("\n |-->N(R): %d", NR);
                
                analisisEscrito += "\n\tTipo de trama: " + Trama;
                analisisEscrito += "\n\tN(S): " + NS;
                analisisEscrito += "\n\tN(R): " + NR;

                if(PF.compareTo("1")==0){
                 //System.out.printf("\n |-->P/F:" + c_r);
                 analisisEscrito += "\n\tP/F: " + c_r;
                }
                else{
                 //System.out.printf("\n |-->P/F:" + "-");
                 analisisEscrito += "\n\tP/F: -";
                }
            }

            if(Trama.compareTo("S")==0){

                if(TipoTrama.compareTo("00")==0){
                    //System.out.printf("\n |-->Tipo de trama:" + Trama + "(RR)");
                    //System.out.printf("\n |-->N(R): %d", NR);
                    analisisEscrito += "\n\tTipo de trama: " + Trama + "(RR)";
                    analisisEscrito += "\n\tN(R): " + NR;
                }
                if(TipoTrama.compareTo("01")==0){
                    //System.out.printf("\n |-->Tipo de trama:" + Trama + "(REJ)");
                    //System.out.printf("\n |-->N(R): %d", NR);
                    analisisEscrito += "\n\tTipo de trama: " + Trama + "(REJ)";
                    analisisEscrito += "\n\tN(R): " + NR;
                }
                if(TipoTrama.compareTo("10")==0){
                    //System.out.printf("\n |-->Tipo de trama:" + Trama + "(RNR)");
                    //System.out.printf("\n |-->N(R): %d", NR);
                    analisisEscrito += "\n\tTipo de trama: " + Trama + "(RNR)";
                    analisisEscrito += "\n\tN(R): " + NR;
                }
                if(TipoTrama.compareTo("11")==0){
                    //System.out.printf("\n |-->Tipo de trama:" + Trama + "(SREJ)");
                    //System.out.printf("\n |-->N(R): %d", NR);
                    analisisEscrito += "\n\tTipo de trama: " + Trama + "(SREJ)";
                    analisisEscrito += "\n\tN(R): " + NR;
                }

                if(PF.compareTo("1")==0){
                 //System.out.printf("\n |-->P/F:" + c_r); 
                 analisisEscrito += "\n\tP/F: " + c_r;
                }
                else{
                 //System.out.printf("\n |-->P/F:" + "-");
                 analisisEscrito += "\n\tP/F: " + "-";
                }
            }
            if(ssap==0 && Trama.compareTo("U")==0){

                if(TipoTrama.compareTo("00001")==0){
                    //System.out.printf("\n |-->Tipo de trama:" + Trama + "(SNRM)");
                    analisisEscrito += "\n\tTipo de trama: " + Trama + "(SNRM)";
                }
                if(TipoTrama.compareTo("11011")==0){
                    //System.out.printf("\n |-->Tipo de trama:" + Trama + "(SNRME)");
                    analisisEscrito += "\n\tTipo de trama: " + Trama + "(SNRME)";
                }
                if(TipoTrama.compareTo("11000")==0){
                    //System.out.printf("\n |-->Tipo de trama:" + Trama + "(SARM)");
                    analisisEscrito += "\n\tTipo de trama: " + Trama + "(SARM)";
                }
                if(TipoTrama.compareTo("11010")==0){
                    //System.out.printf("\n |-->Tipo de trama:" + Trama + "(SARME)");
                    analisisEscrito += "\n\tTipo de trama: " + Trama + "(SARME)";
                }
                if(TipoTrama.compareTo("11100")==0){
                   // System.out.printf("\n |-->Tipo de trama:" + Trama + "(SABM)");
                    analisisEscrito += "\n\tTipo de trama: " + Trama + "(SABM)";
                }
                if(TipoTrama.compareTo("11110")==0){
                   // System.out.printf("\n |-->Tipo de trama:" + Trama + "(SABME)");
                    analisisEscrito += "\n\tTipo de trama: " + Trama + "(SABME)";
                }
                if(TipoTrama.compareTo("00000")==0){
                   // System.out.printf("\n |-->Tipo de trama:" + Trama + "(UI)");
                    analisisEscrito += "\n\tTipo de trama: " + Trama + "(UI)";
                }
                if(TipoTrama.compareTo("00110")==0){
                    //System.out.printf("\n |-->Tipo de trama:" + Trama + "(-)");
                    analisisEscrito += "\n\tTipo de trama: " + Trama + "(-)";
                }
                if(TipoTrama.compareTo("00010")==0){
                    //System.out.printf("\n |-->Tipo de trama:" + Trama + "(DISC)");
                    analisisEscrito += "\n\tTipo de trama: " + Trama + "(DISC)";
                }
                if(TipoTrama.compareTo("10000")==0){
                   // System.out.printf("\n |-->Tipo de trama:" + Trama + "(SIM)");
                    analisisEscrito += "\n\tTipo de trama: " + Trama + "(SIM)";
                }
                if(TipoTrama.compareTo("00100")==0){
                    //System.out.printf("\n |-->Tipo de trama:" + Trama + "(UP)");
                    analisisEscrito += "\n\tTipo de trama: " + Trama + "(UP)";
                }
                if(TipoTrama.compareTo("11001")==0){
                   // System.out.printf("\n |-->Tipo de trama:" + Trama + "(RSET)");
                    analisisEscrito += "\n\tTipo de trama: " + Trama + "(RSET)";
                }
                if(TipoTrama.compareTo("11101")==0){
                   // System.out.printf("\n |-->Tipo de trama:" + Trama + "(XID)");
                    analisisEscrito += "\n\tTipo de trama: " + Trama + "(XID)";
                }
                if(TipoTrama.compareTo("10001")==0){
                   // System.out.printf("\n |-->Tipo de trama:" + Trama + "(-)");
                    analisisEscrito += "\n\tTipo de trama: " + Trama + "(-)";
                }

                if(PF.compareTo("1")==0){
                // System.out.printf("\n |-->P/F:" + "Comando"); 
                 analisisEscrito += "\n\tP/F: Comando";
                }
                else{
                // System.out.printf("\n |-->P/F:" + "-");
                 analisisEscrito += "\n\tP/F: -";
                }

        }

        if(ssap==1 && Trama.compareTo("U")==0){

            if(TipoTrama.compareTo("00001")==0){
                    //System.out.printf("\n |-->Tipo de trama:" + Trama + "(-)");
                    analisisEscrito += "\n\tTipo de trama: " + Trama + "(-)";
                }
                if(TipoTrama.compareTo("11011")==0){
                    //System.out.printf("\n |-->Tipo de trama:" + Trama + "(-)");
                    analisisEscrito += "\n\tTipo de trama: " + Trama + "(-)";
                }
                if(TipoTrama.compareTo("11000")==0){
                    //System.out.printf("\n |-->Tipo de trama:" + Trama + "(DM)");
                    analisisEscrito += "\n\tTipo de trama: " + Trama + "(DM)";
                }
                if(TipoTrama.compareTo("11010")==0){
//                    System.out.printf("\n |-->Tipo de trama:" + Trama + "(-)");
                    analisisEscrito += "\n\tTipo de trama: " + Trama + "(-)";
                }
                if(TipoTrama.compareTo("11100")==0){
//                    System.out.printf("\n |-->Tipo de trama:" + Trama + "(-)");
                    analisisEscrito += "\n\tTipo de trama: " + Trama + "(-)";
                }
                if(TipoTrama.compareTo("11110")==0){
//                    System.out.printf("\n |-->Tipo de trama:" + Trama + "(-)");
                    analisisEscrito += "\n\tTipo de trama: " + Trama + "(-)";
                }
                if(TipoTrama.compareTo("00000")==0){
//                    System.out.printf("\n |-->Tipo de trama:" + Trama + "(UI)");
                    analisisEscrito += "\n\tTipo de trama: " + Trama + "(UI)";
                }
                if(TipoTrama.compareTo("00110")==0){
//                    System.out.printf("\n |-->Tipo de trama:" + Trama + "(UA)");
                    analisisEscrito += "\n\tTipo de trama: " + Trama + "(UA)";
                }
                if(TipoTrama.compareTo("00010")==0){
//                    System.out.printf("\n |-->Tipo de trama:" + Trama + "(RD)");
                    analisisEscrito += "\n\tTipo de trama: " + Trama + "(RD)";
                }
                if(TipoTrama.compareTo("10000")==0){
//                    System.out.printf("\n |-->Tipo de trama:" + Trama + "(RIM)");
                    analisisEscrito += "\n\tTipo de trama: " + Trama + "(RIM)";
                }
                if(TipoTrama.compareTo("00100")==0){
//                    System.out.printf("\n |-->Tipo de trama:" + Trama + "(-)");
                    analisisEscrito += "\n\tTipo de trama: " + Trama + "(-)";
                }
                if(TipoTrama.compareTo("11001")==0){
//                    System.out.printf("\n |-->Tipo de trama:" + Trama + "(-)");
                    analisisEscrito += "\n\tTipo de trama: " + Trama + "(-)";
                }
                if(TipoTrama.compareTo("11101")==0){
//                    System.out.printf("\n |-->Tipo de trama:" + Trama + "(XID)");
                    analisisEscrito += "\n\tTipo de trama: " + Trama + "(XID)";
                }
                if(TipoTrama.compareTo("10001")==0){
//                    System.out.printf("\n |-->Tipo de trama:" + Trama + "(FRMR)");
                    analisisEscrito += "\n\tTipo de trama: " + Trama + "(FRMR)";
                }

                if(PF.compareTo("1")==0){
//                 System.out.printf("\n |-->P/F:" + "Respuesta");   
                    analisisEscrito += "\n\tP/F: Respuesta";
                }
                else{
//                 System.out.printf("\n |-->P/F:" + "-");
                 analisisEscrito += "\n\tP/F: -";
                }
        }
    }

    public PcapPacket getPacket() {
        return packet;
    }

    public void setPacket(PcapPacket packet) {
        this.packet = packet;
    }

    public String getUser() {
        return user;
    }

    public byte[] getOrigen() {
        return origen;
    }

    public byte[] getDestino() {
        return destino;
    }

    public int getTipo() {
        return tipo;
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
    
    public String getOrigenEscrito() {
        return origenEscrito;
    }

    public String getDestinoEscrito() {
        return destinoEscrito;
    }

    public String getTipoEscrito() {
        return tipoEscrito;
    }

    public String getTiempoEscrito() {
        return tiempoEscrito;
    }

    public String getAnalisisEscrito() {
        return analisisEscrito;
    }

    public String getTamEscrito() {
        return tamEscrito;
    }
}
