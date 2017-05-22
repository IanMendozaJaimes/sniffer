package Clases;


public class Configuracion {
    
    //me faltan parametros pero no se cuales...
    private String MAC;
    private int tamPaquete;
    private float tiempo;
    private int num_dispositivo;
    
    public Configuracion(){
        MAC = "";
        tamPaquete = 500;
        tiempo = 20;
        num_dispositivo = 1;
    }

    public String getMAC() {
        return MAC;
    }

    public int getTamPaquete() {
        return tamPaquete;
    }

    public int getNum_dispositivo() {
        return num_dispositivo;
    }

    public float getTiempo() {
        return tiempo;
    }
}
