package com.ults.jrc.tachograph.keytool;

import org.bouncycastle.asn1.ASN1Encodable;

/**
 * Immutable representation of a tachograph certificate profile identifier.
 *
 * @author Klaas Mateboer
 */
public class TachographCertificateProfileIdentifier extends SimpleCertificateElement {

    private static final String NAME = "ProfileIdentifier";
    private static final int TAG = 41;

    private final byte value;

    static TachographCertificateProfileIdentifier getInstance(ASN1Encodable o) {
        return new TachographCertificateProfileIdentifier(getContents(o, TAG, NAME)[0]);
    }

    TachographCertificateProfileIdentifier() {
        this((byte) 0);
    }

    TachographCertificateProfileIdentifier(byte value) {
        super(NAME, TAG);
        this.value = value;
    }

    public byte getValue() {
        return value;
    }

    @Override
    byte[] getContents() {
        return new byte[] {value};
    }
}