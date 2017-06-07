/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

package Clases;

import java.io.IOException;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.swing.JTextArea;

/**
 *
 * @author Ian
 */
public class ArpVentana extends javax.swing.JFrame {

    private JTextArea consola;
    private Sincronizador s;
    
    public ArpVentana(JTextArea consola) {
        initComponents();
        
        Configuracion conf = new Configuracion();
        
        s = new Sincronizador();
        
        this.consola = consola;
        txtMacOrigen.setText(conf.getMAC());
    }

    private ArpVentana() {
        throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
    }

    
    @SuppressWarnings("unchecked")
    // <editor-fold defaultstate="collapsed" desc="Generated Code">//GEN-BEGIN:initComponents
    private void initComponents() {

        jLabel1 = new javax.swing.JLabel();
        txtMacOrigen = new javax.swing.JTextField();
        jLabel2 = new javax.swing.JLabel();
        jLabel3 = new javax.swing.JLabel();
        txtIpDestino = new javax.swing.JTextField();
        generar = new javax.swing.JButton();
        parar = new javax.swing.JButton();
        txtNumTramas = new javax.swing.JTextField();
        jLabel4 = new javax.swing.JLabel();

        setDefaultCloseOperation(javax.swing.WindowConstants.EXIT_ON_CLOSE);

        jLabel1.setText("Generar tramas ARP");

        jLabel2.setText("MAC Origen");

        jLabel3.setText("IP Destino");

        generar.setText("Generar");
        generar.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                generarActionPerformed(evt);
            }
        });

        parar.setText("Parar");
        parar.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                pararActionPerformed(evt);
            }
        });

        jLabel4.setText("Número de tramas a generar (en blanco para indeterminado)");

        javax.swing.GroupLayout layout = new javax.swing.GroupLayout(getContentPane());
        getContentPane().setLayout(layout);
        layout.setHorizontalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(layout.createSequentialGroup()
                .addContainerGap()
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addComponent(txtNumTramas)
                    .addComponent(txtMacOrigen)
                    .addComponent(jLabel2, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                    .addComponent(txtIpDestino)
                    .addGroup(layout.createSequentialGroup()
                        .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                            .addComponent(jLabel1, javax.swing.GroupLayout.PREFERRED_SIZE, 230, javax.swing.GroupLayout.PREFERRED_SIZE)
                            .addComponent(jLabel3)
                            .addComponent(jLabel4))
                        .addGap(0, 0, Short.MAX_VALUE))
                    .addGroup(layout.createSequentialGroup()
                        .addComponent(generar, javax.swing.GroupLayout.PREFERRED_SIZE, 160, javax.swing.GroupLayout.PREFERRED_SIZE)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED, 50, Short.MAX_VALUE)
                        .addComponent(parar, javax.swing.GroupLayout.PREFERRED_SIZE, 160, javax.swing.GroupLayout.PREFERRED_SIZE)))
                .addContainerGap())
        );
        layout.setVerticalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(layout.createSequentialGroup()
                .addContainerGap()
                .addComponent(jLabel1)
                .addGap(28, 28, 28)
                .addComponent(jLabel2)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(txtMacOrigen, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addGap(18, 18, 18)
                .addComponent(jLabel3)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(txtIpDestino, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addGap(18, 18, 18)
                .addComponent(jLabel4)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(txtNumTramas, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED, 37, Short.MAX_VALUE)
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(generar)
                    .addComponent(parar))
                .addGap(23, 23, 23))
        );

        pack();
    }// </editor-fold>//GEN-END:initComponents

    private void generarActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_generarActionPerformed
        // Empezar a generar tramas arp
        int numT = -1;
        String macOrigen;
        String ipDestino;
        
        try{
            if(!txtNumTramas.getText().equals("")){
                numT = Integer.parseInt(txtNumTramas.getText());
            }
        }
        catch(Exception e){
            numT = -1;
        }
        
        macOrigen = txtMacOrigen.getText();
        ipDestino = txtIpDestino.getText();
        
        System.out.println(ipDestino);
        
        Arp arp = new Arp(numT, macOrigen, ipDestino, s);
        arp.start();
        
    }//GEN-LAST:event_generarActionPerformed

    private void pararActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_pararActionPerformed
        // Parar de generar tramas arp
        s.cambiar();
        
    }//GEN-LAST:event_pararActionPerformed
    
    
    class Arp extends Thread{
        
        private int numTramas;
        private long tiempo;
        private String macOrigen;
        private String ipDestino;
        private Sincronizador sinc;
        
        public Arp(int numTramas, String macOrigen, String ipDestino, Sincronizador sinc){
            this.numTramas = numTramas;
            this.macOrigen = macOrigen;
            this.ipDestino = ipDestino;
            this.tiempo = 100;
            this.sinc = sinc;
        }
        
        @Override
        public void run(){
            Generar genera = new Generar(consola, macOrigen);
            generar.setEnabled(false);
            parar.setEnabled(true);
            try {
                byte trama[] = genera.generarARP(ipDestino);
                sinc.ocupado = true;
                sinc.contando = true;
                if(numTramas > 0){
                    for(int i = 0; i < numTramas; i++){
                        genera.enviarTrama(trama);
                        sinc.ocupado = false;
                        sleep(tiempo);
                        sinc.ocupado = true;
                        if(!sinc.contando){
                            sinc.ocupado = false;
                            sinc.contando = false;
                            break;
                        }
                    }
                }
                else{
                    while(true){
                        genera.enviarTrama(trama);
                        System.out.println("Envie una trama");
                        sinc.ocupado = false;
                        sleep(tiempo);
                        sinc.ocupado = true;
                        if(!sinc.contando){
                            break;
                        }
                    }
                }
            } catch (IOException ex) {
                Logger.getLogger(ArpVentana.class.getName()).log(Level.SEVERE, null, ex);
            } catch (InterruptedException ex) {
                Logger.getLogger(ArpVentana.class.getName()).log(Level.SEVERE, null, ex);
            }
            finally{
                generar.setEnabled(true);
                parar.setEnabled(false);
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
    
    
    public void imprimir(String texto){
        consola.setText(consola.getText() + "\n" + texto);
    }
    
    
    
    
    
    /**
     * @param args the command line arguments
     */
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
            java.util.logging.Logger.getLogger(ArpVentana.class.getName()).log(java.util.logging.Level.SEVERE, null, ex);
        } catch (InstantiationException ex) {
            java.util.logging.Logger.getLogger(ArpVentana.class.getName()).log(java.util.logging.Level.SEVERE, null, ex);
        } catch (IllegalAccessException ex) {
            java.util.logging.Logger.getLogger(ArpVentana.class.getName()).log(java.util.logging.Level.SEVERE, null, ex);
        } catch (javax.swing.UnsupportedLookAndFeelException ex) {
            java.util.logging.Logger.getLogger(ArpVentana.class.getName()).log(java.util.logging.Level.SEVERE, null, ex);
        }
        //</editor-fold>

        /* Create and display the form */
        java.awt.EventQueue.invokeLater(new Runnable() {
            public void run() {
                new ArpVentana().setVisible(true);
            }
        });
    }

    // Variables declaration - do not modify//GEN-BEGIN:variables
    private javax.swing.JButton generar;
    private javax.swing.JLabel jLabel1;
    private javax.swing.JLabel jLabel2;
    private javax.swing.JLabel jLabel3;
    private javax.swing.JLabel jLabel4;
    private javax.swing.JButton parar;
    private javax.swing.JTextField txtIpDestino;
    private javax.swing.JTextField txtMacOrigen;
    private javax.swing.JTextField txtNumTramas;
    // End of variables declaration//GEN-END:variables
}
