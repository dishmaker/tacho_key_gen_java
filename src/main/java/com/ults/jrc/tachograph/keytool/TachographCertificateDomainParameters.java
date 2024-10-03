package com.ults.jrc.tachograph.keytool;

import java.io.PrintStream;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Primitive;

/**
 * Immutable representation of a tachograph certificate domain parameters.
 *
 * @author Klaas Mateboer
 */
public class TachographCertificateDomainParameters extends CertificateElement {

    private static final String NAME = "DomainParameters";
    private static final int TAG = 6;

    final ASN1ObjectIdentifier oid;

    static TachographCertificateDomainParameters getInstance(ASN1Encodable o) {
        return new TachographCertificateDomainParameters(ASN1ObjectIdentifier.getInstance(o));
    }

    TachographCertificateDomainParameters(ASN1ObjectIdentifier oid) {
        super(NAME, TAG);
        this.oid = oid;
    }

    @Override
    public ASN1Primitive toASN1Primitive() {
        return oid;
    }

    @Override
    void show(String prefix, PrintStream out) {
        out.println(prefix + name + " " + oid);
    }
}