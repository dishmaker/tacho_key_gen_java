package com.ults.jrc.tachograph.keytool;

import java.util.Arrays;
import org.bouncycastle.asn1.ASN1Encodable;

/**
 * Immutable representation of a tachograph certificate holder authorisation.
 *
 * @author Klaas Mateboer
 */
public class TachographCertificateHolderAuthorisation extends SimpleCertificateElement {

    private static final String NAME = "HolderAuthorisation";
    private static final int TAG = 76;

    private static final byte[] AID_TACHOGRAPH_CARD_APPLICATION_2
            = new byte[]{(byte) 0xFF, (byte) 0x53, (byte) 0x4D, (byte) 0x52, (byte) 0x44, (byte) 0x54};

    private final byte[] contents;

    static TachographCertificateHolderAuthorisation getInstance(ASN1Encodable o) {
        return new TachographCertificateHolderAuthorisation(getContents(o, TAG, NAME));
    }

    static byte[] getContents(byte equipmentType) {
        byte[] result = Arrays.copyOf(AID_TACHOGRAPH_CARD_APPLICATION_2, AID_TACHOGRAPH_CARD_APPLICATION_2.length + 1);
        result[AID_TACHOGRAPH_CARD_APPLICATION_2.length] = equipmentType;
        return result;
    }

    TachographCertificateHolderAuthorisation(byte equipmentType) {
        this(getContents(equipmentType));
    }

    TachographCertificateHolderAuthorisation(byte[] contents) {
        super(NAME, TAG);
        this.contents = contents;
    }

    int getType() {
        return contents[AID_TACHOGRAPH_CARD_APPLICATION_2.length];
    }

    @Override
    byte[] getContents() {
        return contents.clone();
    }
}