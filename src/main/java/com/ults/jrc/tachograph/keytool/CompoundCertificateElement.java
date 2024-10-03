package com.ults.jrc.tachograph.keytool;

import java.io.PrintStream;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.DERApplicationSpecific;

/**
 * Abstract base class for certificate elements constructed from other elements.
 *
 * @author Klaas Mateboer
 */
public abstract class CompoundCertificateElement extends CertificateElement {

    public CompoundCertificateElement(String name, int tag) {
        super(name, tag);
    }

    @Override
    public ASN1Primitive toASN1Primitive() {
        ASN1EncodableVector vector = new ASN1EncodableVector();
        for (CertificateElement e : getElements())
            vector.add(e.toASN1Primitive());
        return new DERApplicationSpecific(tag, vector);
    }

    @Override
    void show(String prefix, PrintStream out) {
        out.println(prefix + name);
        for (CertificateElement e : getElements()) {
            e.show(prefix + "    ", out);
        }
    }

    abstract Iterable<CertificateElement> getElements();
}
