package com.ults.jrc.tachograph.keytool;

import java.time.LocalDateTime;
import org.bouncycastle.asn1.ASN1Encodable;

/**
 * Immutable representation of a tachograph certificate expiration date.
 *
 * @author Klaas Mateboer
 */
public class TachographCertificateExpirationDate extends TachographCertificateDate {

    private static final String NAME = "ExpirationDate";
    private static final int TAG = 36;

    static TachographCertificateExpirationDate getInstance(ASN1Encodable o) {
        return new TachographCertificateExpirationDate(getContents(o, TAG, NAME));
    }

    TachographCertificateExpirationDate(LocalDateTime dt) {
        super(NAME, TAG, dt);
    }

    TachographCertificateExpirationDate(long seconds) {
        super(NAME, TAG, seconds);
    }

    TachographCertificateExpirationDate(byte[] contents) {
        super(NAME, TAG, contents);
    }
}