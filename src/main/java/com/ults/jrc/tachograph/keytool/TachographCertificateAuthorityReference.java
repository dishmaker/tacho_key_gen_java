package com.ults.jrc.tachograph.keytool;

import org.bouncycastle.asn1.ASN1Encodable;

/**
 * Immutable representation of a tachograph certificate authority reference.
 *
 * @author Klaas Mateboer
 */
public class TachographCertificateAuthorityReference extends SimpleCertificateElement {

    private static final String NAME = "AuthorityReference";
    private static final int TAG = 2;
    private static final int LENGTH = 8;

    private final byte[] contents;

    static TachographCertificateAuthorityReference getInstance(ASN1Encodable o) {
        return new TachographCertificateAuthorityReference(getContents(o, TAG, NAME));
    }

    TachographCertificateAuthorityReference(byte[] contents) {
        super(NAME, TAG);
        if (contents.length != LENGTH)
            throw new TachographKeyToolException("Invalid length for certificate authority reference");
        this.contents = contents;
    }

    @Override
    byte[] getContents() {
        return contents.clone();
    }
}