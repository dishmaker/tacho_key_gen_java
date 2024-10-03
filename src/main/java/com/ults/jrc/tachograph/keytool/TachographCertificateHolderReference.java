package com.ults.jrc.tachograph.keytool;

import java.util.Arrays;
import org.bouncycastle.asn1.ASN1Encodable;

/**
 * Immutable representation of a tachograph certificate holder reference.
 *
 * @author Klaas Mateboer
 */
public class TachographCertificateHolderReference extends SimpleCertificateElement {

    private static final String NAME = "HolderReference";
    private static final int TAG = 32;

    private final byte[] contents;

    static TachographCertificateHolderReference getInstance(ASN1Encodable o) {
        return new TachographCertificateHolderReference(getContents(o, TAG, NAME));
    }

    TachographCertificateHolderReference(byte[] contents) {
        super(NAME, TAG);
        if (contents.length != 8)
            throw new TachographKeyToolException("Invalid length for certificate holder reference");
        this.contents = contents;
    }

    TachographCertificateAuthorityReference toAuthorityReference() {
        return new TachographCertificateAuthorityReference(getContents());
    }

    boolean matches(TachographCertificateAuthorityReference authority) {
        return Arrays.equals(contents, authority.getContents());
    }

    @Override
    byte[] getContents() {
        return contents.clone();
    }
}