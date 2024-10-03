package com.ults.jrc.tachograph.keytool;

import java.time.LocalDateTime;
import org.bouncycastle.asn1.ASN1Encodable;

/**
 * Immutable representation of a tachograph certificate effective date.
 *
 * @author Klaas Mateboer
 */
public class TachographCertificateEffectiveDate extends TachographCertificateDate {

    private static final String NAME = "EffectiveDate";
    private static final int TAG = 37;

    static TachographCertificateEffectiveDate getInstance(ASN1Encodable o) {
        return new TachographCertificateEffectiveDate(getContents(o, TAG, NAME));
    }

    TachographCertificateEffectiveDate(LocalDateTime dt) {
        super(NAME, TAG, dt);
    }

    TachographCertificateEffectiveDate(long seconds) {
        super(NAME, TAG, seconds);
    }

    TachographCertificateEffectiveDate(byte[] contents) {
        super(NAME, TAG, contents);
    }
}