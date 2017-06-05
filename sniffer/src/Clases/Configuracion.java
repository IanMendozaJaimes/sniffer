package Clases;

import java.io.File;
import java.io.FileWriter;
import org.jdom2.Document;
import org.jdom2.Element;
import org.jdom2.input.SAXBuilder;
import org.jdom2.output.XMLOutputter;


public class Configuracion {
    
    private String MAC;
    private int tamPaquete;
    private float tiempo;
    private int promiscuo;
    
    public Configuracion(){
        iniciarParametros();
    }
    
    public void iniciarParametros(){
        try{
            File archivo = new File("configuracion.xml");
            if(!archivo.exists()){
                cambiarParametros("", 500, 20, 1);
                nuevaConfiguracion();
                return;
            }
            SAXBuilder builder = new SAXBuilder();
            Document documento = (Document)builder.build(archivo);
            Element raiz = documento.getRootElement();
            
            this.MAC = raiz.getChildText("mac");
            this.tamPaquete = Integer.parseInt(raiz.getChildText("tamPaquete"));
            this.tiempo = Float.parseFloat(raiz.getChildText("tiempo"));
            this.promiscuo = Integer.parseInt(raiz.getChildText("promiscuo"));
        }
        catch(Exception e){
            System.out.println("Error al abrir el archivo de configuracion.xml " + e.toString());
        }
    }
    
    public void cambiarParametros(String mac, int tamPaquete, float tiempo, int promiscuo){
        this.MAC = mac;
        this.tamPaquete = tamPaquete;
        this.tiempo = tiempo;
        this.promiscuo = promiscuo;
    }
    
    public void nuevaConfiguracion(){
        try{
            Element raiz = new Element("configuracion");
            Element tamanioEtiqueta = new Element("tamPaquete");
            Element tiempoEtiqueta = new Element("tiempo");
            Element macEtiqueta = new Element("mac");
            Element promiscuoEtiqueta = new Element("promiscuo");
            
            tamanioEtiqueta.setText(String.valueOf(tamPaquete));
            tiempoEtiqueta.setText(String.valueOf(tiempo));
            macEtiqueta.setText(MAC);
            promiscuoEtiqueta.setText(String.valueOf(promiscuo));
            
            raiz.addContent(tamanioEtiqueta);
            raiz.addContent(tiempoEtiqueta);
            raiz.addContent(macEtiqueta);
            raiz.addContent(promiscuoEtiqueta);
            
            Document nuevo_documento = new Document(raiz);
            XMLOutputter fmt = new XMLOutputter();
            FileWriter writer = new FileWriter("configuracion.xml");
            fmt.output(nuevo_documento, writer);
            writer.flush();
            writer.close();
        }
        catch(Exception e){
            System.out.println("Error al crear el archivo xml de configuracion: " + e.toString());
        }
    }

    public String getMAC() {
        return MAC;
    }

    public int getTamPaquete() {
        return tamPaquete;
    }

    public float getTiempo() {
        return tiempo;
    }
    
    public int getPromiscuo() {
        return promiscuo;
    }
}
