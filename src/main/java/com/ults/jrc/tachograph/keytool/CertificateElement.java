package com.ults.jrc.tachograph.keytool;

import java.io.IOException;
import java.io.PrintStream;
import org.bouncycastle.asn1.ASN1Encodable;

/**
 * Abstract certificate element that can be encoded and shown to the user.
 *
 * @author Klaas Mateboer
 */
public abstract class CertificateElement implements ASN1Encodable {

    final int tag;
    final String name;

    public CertificateElement(String name, int tag) {
        this.tag = tag;
        this.name = name;
    }

    byte[] getEncoded() throws IOException {
        return toASN1Primitive().getEncoded();
    }

    void show(PrintStream out) {
        show("", out);
    }

    abstract void show(String prefix, PrintStream out);
}
