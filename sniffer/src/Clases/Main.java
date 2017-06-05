/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

package Clases;

import java.awt.Point;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Date;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.swing.JFileChooser;
import javax.swing.JFrame;
import javax.swing.JTable;
import javax.swing.event.ListSelectionEvent;
import javax.swing.event.ListSelectionListener;
import javax.swing.table.DefaultTableModel;
import org.jfree.chart.ChartFactory;
import org.jfree.chart.ChartPanel;
import org.jfree.chart.JFreeChart;
import org.jfree.chart.plot.PlotOrientation;
import org.jfree.data.category.DefaultCategoryDataset;

/**
 *
 * @author Ian
 */
public class Main extends javax.swing.JFrame {
    
    private Paqueteria manejador;
    private Sincronizador s;
    private Capturar captura;
    private DefaultTableModel modelo;
    private ArrayList<InfoTrama> listaInfoTramas;
    private int num_trama;

    public Main() throws IOException {
        initComponents();
        s = new Sincronizador();
        captura = null;
        modelo = (DefaultTableModel)tablaTramas.getModel();
        listaInfoTramas = new ArrayList<>();
        num_trama = 0;
        tablaTramas.setModel(modelo);
        tablaTramas.addMouseListener(new MouseAdapter(){
            public void mousePressed(MouseEvent t){
                JTable tabla = (JTable) t.getSource();
                Point p = t.getPoint();
                int row = tablaTramas.rowAtPoint(p);
                if(t.getClickCount() == 2 && row != 1){
                    abrirTrama tram = new abrirTrama(listaInfoTramas.get(row));
                    tram.start();
                }
            }
        });
    }

    /**
     * This method is called from within the constructor to initialize the form.
     * WARNING: Do NOT modify this code. The content of this method is always
     * regenerated by the Form Editor.
     */
    @SuppressWarnings("unchecked")
    // <editor-fold defaultstate="collapsed" desc="Generated Code">//GEN-BEGIN:initComponents
    private void initComponents() {

        jScrollPane2 = new javax.swing.JScrollPane();
        consola = new javax.swing.JTextArea();
        capturar = new javax.swing.JButton();
        detener = new javax.swing.JButton();
        panel = new javax.swing.JScrollPane();
        tablaTramas = new javax.swing.JTable();
        menu = new javax.swing.JMenuBar();
        jMenu1 = new javax.swing.JMenu();
        jMenuItem1 = new javax.swing.JMenuItem();
        jMenuItem2 = new javax.swing.JMenuItem();
        jMenuItem3 = new javax.swing.JMenuItem();
        jMenu2 = new javax.swing.JMenu();
        jMenu3 = new javax.swing.JMenu();
        jMenuItem5 = new javax.swing.JMenuItem();
        jMenu4 = new javax.swing.JMenu();
        jMenuItem4 = new javax.swing.JMenuItem();

        setDefaultCloseOperation(javax.swing.WindowConstants.EXIT_ON_CLOSE);

        consola.setColumns(20);
        consola.setRows(5);
        jScrollPane2.setViewportView(consola);

        capturar.setText("Capturar");
        capturar.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                capturarActionPerformed(evt);
            }
        });

        detener.setText("Detener");
        detener.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                detenerActionPerformed(evt);
            }
        });

        tablaTramas.setModel(new javax.swing.table.DefaultTableModel(
            new Object [][] {

            },
            new String [] {
                "No.", "Tiempo", "Destino", "Origen", "Protocolo", "Longitud"
            }
        ) {
            boolean[] canEdit = new boolean [] {
                false, false, false, false, false, false
            };

            public boolean isCellEditable(int rowIndex, int columnIndex) {
                return canEdit [columnIndex];
            }
        });
        panel.setViewportView(tablaTramas);

        jMenu1.setText("Capturar");

        jMenuItem1.setText("Tramas al vuelo");
        jMenuItem1.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                jMenuItem1ActionPerformed(evt);
            }
        });
        jMenu1.add(jMenuItem1);

        jMenuItem2.setText("Seleccionar archivo");
        jMenuItem2.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                jMenuItem2ActionPerformed(evt);
            }
        });
        jMenu1.add(jMenuItem2);

        jMenuItem3.setText("Guardar");
        jMenuItem3.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                jMenuItem3ActionPerformed(evt);
            }
        });
        jMenu1.add(jMenuItem3);

        menu.add(jMenu1);

        jMenu2.setText("Generar");
        menu.add(jMenu2);

        jMenu3.setText("Estadísticas");

        jMenuItem5.setText("Graficar");
        jMenuItem5.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                jMenuItem5ActionPerformed(evt);
            }
        });
        jMenu3.add(jMenuItem5);

        menu.add(jMenu3);

        jMenu4.setText("Configuración");

        jMenuItem4.setText("Parámetros");
        jMenuItem4.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                jMenuItem4ActionPerformed(evt);
            }
        });
        jMenu4.add(jMenuItem4);

        menu.add(jMenu4);

        setJMenuBar(menu);

        javax.swing.GroupLayout layout = new javax.swing.GroupLayout(getContentPane());
        getContentPane().setLayout(layout);
        layout.setHorizontalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(javax.swing.GroupLayout.Alignment.TRAILING, layout.createSequentialGroup()
                .addContainerGap()
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.TRAILING)
                    .addComponent(panel, javax.swing.GroupLayout.DEFAULT_SIZE, 789, Short.MAX_VALUE)
                    .addComponent(jScrollPane2, javax.swing.GroupLayout.Alignment.LEADING)
                    .addGroup(javax.swing.GroupLayout.Alignment.LEADING, layout.createSequentialGroup()
                        .addComponent(capturar, javax.swing.GroupLayout.PREFERRED_SIZE, 140, javax.swing.GroupLayout.PREFERRED_SIZE)
                        .addGap(18, 18, 18)
                        .addComponent(detener, javax.swing.GroupLayout.PREFERRED_SIZE, 149, javax.swing.GroupLayout.PREFERRED_SIZE)
                        .addGap(0, 0, Short.MAX_VALUE)))
                .addContainerGap())
        );
        layout.setVerticalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(javax.swing.GroupLayout.Alignment.TRAILING, layout.createSequentialGroup()
                .addGap(23, 23, 23)
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(capturar)
                    .addComponent(detener))
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                .addComponent(panel, javax.swing.GroupLayout.PREFERRED_SIZE, 321, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                .addComponent(jScrollPane2, javax.swing.GroupLayout.DEFAULT_SIZE, 142, Short.MAX_VALUE)
                .addContainerGap())
        );

        pack();
    }// </editor-fold>//GEN-END:initComponents

    private void jMenuItem1ActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_jMenuItem1ActionPerformed
        //tramas al vuelo
        try{
            captura = new Capturar(consola);
            captura.obtenerDispositivos();
            captura.imprimirDispositivos();
            captura.capturarTramas();
        }
        catch(Exception e){
            System.out.println("Errores locos");
        }
    }//GEN-LAST:event_jMenuItem1ActionPerformed

    private void jMenuItem2ActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_jMenuItem2ActionPerformed
        //seleccionar archivo
        try{
            String nombreArchivo = "";
            JFileChooser file = new JFileChooser();
            int temp = file.showOpenDialog(this);
            if(temp == JFileChooser.APPROVE_OPTION){
                nombreArchivo = file.getSelectedFile().getName();
            }
            if(!nombreArchivo.equals("")){
                captura = new Capturar(consola);
                captura.obtenerDispositivos();
                captura.imprimirDispositivos();
                captura.capturarTramas(nombreArchivo);
                imprimir("Se ha seleccionado el archivo: " + nombreArchivo);
            }
            else{
                imprimir("Se ha cancelado la selección de archivo.");
            }
        }
        catch(Exception e){
            System.out.println("Errores locos");
        }
    }//GEN-LAST:event_jMenuItem2ActionPerformed

    private void capturarActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_capturarActionPerformed
        //iniciar captura de paquetes
        s.contando = true;
        manejador = new Paqueteria(500, s);
        manejador.start();
    }//GEN-LAST:event_capturarActionPerformed

    private void detenerActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_detenerActionPerformed
        //detener captura de paquetes
        s.cambiar();
    }//GEN-LAST:event_detenerActionPerformed

    private void jMenuItem3ActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_jMenuItem3ActionPerformed
        //guardar
        try{
            String nombreArchivo = "";
            JFileChooser file = new JFileChooser();
            int temp = file.showOpenDialog(this);
            if(temp == JFileChooser.APPROVE_OPTION){
                nombreArchivo = file.getSelectedFile().getName();
            }
            if(!nombreArchivo.equals("")){
                captura.guardar(nombreArchivo, num_trama);
                imprimir("Se ha seleccionado el archivo: " + nombreArchivo);
            }
            else{
                imprimir("Se ha cancelado la selección de archivo.");
            }
        }
        catch(Exception e){
            System.out.println("Errores locos");
        }
    }//GEN-LAST:event_jMenuItem3ActionPerformed

    private void jMenuItem4ActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_jMenuItem4ActionPerformed
        //abrir ventana de configuracion
        captura = null;
        abrirConf abrir = new abrirConf();
        abrir.start();
        try{
            abrir.join();
        }
        catch(Exception e){
            System.out.println("Error en el hilo: " + e.toString());
        }
    }//GEN-LAST:event_jMenuItem4ActionPerformed

    private void jMenuItem5ActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_jMenuItem5ActionPerformed
        // Graficar
        
//        if(listaInfoTramas.isEmpty()){
//            consola.setText(consola.getText() + "\n No hay tramas que graficar.");
//            return;
//        }
        
        abrirGraficas grafica = new abrirGraficas(listaInfoTramas);
        grafica.start();
    }//GEN-LAST:event_jMenuItem5ActionPerformed
    
    public void imprimir(String texto){
        consola.setText(consola.getText() + "\n" + texto);
    }

    public static void main(String args[]) {
        /* Set the Nimbus look and feel */
        //<editor-fold defaultstate="collapsed" desc=" Look and feel setting code (optional) ">
        /* If Nimbus (introduced in Java SE 6) is not available, stay with the default look and feel.
         * For details see http://download.oracle.com/javase/tutorial/uiswing/lookandfeel/plaf.html 
         */
        try {
            for (javax.swing.UIManager.LookAndFeelInfo info : javax.swing.UIManager.getInstalledLookAndFeels()) {
                if ("Nimbus".equals(info.getName())) {
                    javax.swing.UIManager.setLookAndFeel(info.getClassName());
                    break;
                }
            }
        } catch (ClassNotFoundException ex) {
            java.util.logging.Logger.getLogger(Main.class.getName()).log(java.util.logging.Level.SEVERE, null, ex);
        } catch (InstantiationException ex) {
            java.util.logging.Logger.getLogger(Main.class.getName()).log(java.util.logging.Level.SEVERE, null, ex);
        } catch (IllegalAccessException ex) {
            java.util.logging.Logger.getLogger(Main.class.getName()).log(java.util.logging.Level.SEVERE, null, ex);
        } catch (javax.swing.UnsupportedLookAndFeelException ex) {
            java.util.logging.Logger.getLogger(Main.class.getName()).log(java.util.logging.Level.SEVERE, null, ex);
        }
        //</editor-fold>

        /* Create and display the form */
        java.awt.EventQueue.invokeLater(new Runnable() {
            @Override
            public void run() {
                try {
                    new Main().setVisible(true);
                } catch (IOException ex) {
                    Logger.getLogger(Main.class.getName()).log(Level.SEVERE, null, ex);
                }
            }
        });
    }
    
    class abrirConf extends Thread{        
        @Override
        public void run(){
            ConfiguracionVentana conf = new ConfiguracionVentana(consola);
            conf.setVisible(true);
            conf.setDefaultCloseOperation(DISPOSE_ON_CLOSE);
        }
    }
    
    class abrirTrama extends Thread{
        
        private InfoTrama trama;
        
        public abrirTrama(InfoTrama inf){
            this.trama = inf;
        }
        
        @Override
        public void run(){
            InfoVentana infoV = new InfoVentana(trama);
            infoV.setVisible(true);
            infoV.setDefaultCloseOperation(DISPOSE_ON_CLOSE);
        }
    }
    
    class abrirGraficas extends Thread{
        
        private ArrayList<InfoTrama> lista;
        
        public abrirGraficas(ArrayList<InfoTrama> lista){
            this.lista = lista;
        }
        
        @Override
        public void run(){
            JFreeChart grafica;
            DefaultCategoryDataset datos;
            String tipos[] = {"ETHERNET", "IP", "TCP", "UDP", "ARP", "ICMP", "LLC"};
            int contadores[];
            
            datos = new DefaultCategoryDataset();
            contadores = new int[tipos.length];

            for (int i = 0; i < contadores.length; i++) {
                contadores[i] = 0;
            }

            for (int i = 0; i < lista.size(); i++) {
                String t = lista.get(i).getTipoEscrito();
                for (int j = 0; j < tipos.length; j++) {
                    if(t.equals(tipos[j])){
                        contadores[j] += 1;
                        break;
                    }
                }
            }

            for (int i = 0; i < tipos.length; i++) {
                datos.addValue(contadores[i], "Cantidad", tipos[i]);
            }

            grafica = ChartFactory.createBarChart("Cantidad de tramas de cada tipo capturadas", "Cantidad", "Tipo", datos, PlotOrientation.HORIZONTAL, false, true, false);
            
            ChartPanel panel = new ChartPanel(grafica);
            JFrame ventana = new JFrame("Estadísticas");
            ventana.getContentPane().add(panel);
            ventana.pack();
            ventana.setVisible(true);
            ventana.setDefaultCloseOperation(JFrame.DISPOSE_ON_CLOSE);
        }
    }
    
    class Paqueteria extends Thread{
        private long conteo = 0;
        private int tiempo = 0;
        private Sincronizador sinc;
        
        public Paqueteria(int tiempo, Sincronizador sinc){
            this.tiempo = tiempo;
            this.sinc = sinc;
        }
        
        @Override
        public void run(){
            if(captura == null){
                imprimir("Seleccione una opción de captura para poder comenzar.");
                return;
            }
            sinc.ocupado = true;
            while(sinc.contando){
                
                InfoTrama temp;
                String datos[] = new String[6];
                temp = captura.manejadorPaquetes();
                temp.setNumero(num_trama);
                
                try{
                    if(temp.getTipoEscrito().equals("")){return;}
                    datos[0] = String.valueOf(temp.getNumero());
                    datos[1] = temp.getTiempoEscrito();
                    datos[2] = temp.getDestinoEscrito();
                    datos[3] = temp.getOrigenEscrito();
                    datos[4] = temp.getTipoEscrito();
                    datos[5] = temp.getTamEscrito();
                }
                catch(Exception e){
                    System.out.println("ERROR: " + e.toString());
                    return;
                }
                
                listaInfoTramas.add(temp);
                modelo.addRow(datos);
                tablaTramas.setModel(modelo);
                
                num_trama++;
                sinc.ocupado = false;
                try {
                    sleep(tiempo);
                } catch (InterruptedException ex) {
                    Logger.getLogger(Main.class.getName()).log(Level.SEVERE, null, ex);
                }
                sinc.ocupado = true;
            }
        }
    }
    
    class Sincronizador{
        boolean contando = true;
        boolean ocupado = true;
        
        public synchronized void cambiar(){
            while(ocupado == true){
                try {
                    wait();
                } catch (InterruptedException ex) {
                    Logger.getLogger(Main.class.getName()).log(Level.SEVERE, null, ex);
                }
            }
            contando = false;
        }
    }

    // Variables declaration - do not modify//GEN-BEGIN:variables
    private javax.swing.JButton capturar;
    private javax.swing.JTextArea consola;
    private javax.swing.JButton detener;
    private javax.swing.JMenu jMenu1;
    private javax.swing.JMenu jMenu2;
    private javax.swing.JMenu jMenu3;
    private javax.swing.JMenu jMenu4;
    private javax.swing.JMenuItem jMenuItem1;
    private javax.swing.JMenuItem jMenuItem2;
    private javax.swing.JMenuItem jMenuItem3;
    private javax.swing.JMenuItem jMenuItem4;
    private javax.swing.JMenuItem jMenuItem5;
    private javax.swing.JScrollPane jScrollPane2;
    private javax.swing.JMenuBar menu;
    private javax.swing.JScrollPane panel;
    private javax.swing.JTable tablaTramas;
    // End of variables declaration//GEN-END:variables
}
