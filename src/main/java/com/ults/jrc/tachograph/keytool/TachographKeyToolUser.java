package com.ults.jrc.tachograph.keytool;

import java.io.PrintStream;

/**
 * Representation of the Generation-2 Smart Tachograph Key Tool user.
 * 
 * @author Klaas Mateboer
 */
public class TachographKeyToolUser {

    private final PrintStream out;

    public TachographKeyToolUser(PrintStream out) {
        this.out = out;
    }

    public void inform(String info) {
        out.println(info);
    }

    public void show(TachographCertificate certificate) {
       certificate.show(out);
    }

    public void warn(String warning) {
        out.println("Warning: " + warning);
    }
}
