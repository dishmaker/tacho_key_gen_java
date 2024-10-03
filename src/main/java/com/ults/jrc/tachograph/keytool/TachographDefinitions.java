package com.ults.jrc.tachograph.keytool;

import java.util.Arrays;
import java.util.List;

/**
 * Tachograph specific constants and definitions.
 *
 * @author Klaas Mateboer
 */
public final class TachographDefinitions {

    static final List<String> CURVE_NAMES = Arrays.asList(
        "secp256r1",
        "secp384r1",
        "secp521r1",
        "brainpoolp256r1",
        "brainpoolp384r1",
        "brainpoolp512r1");

    static final int[] AES_KEY_SIZES = new int[]{
        128,
        192,
        256,};

    static final int KEY_USAGE_PERIOD_ERCA = (17*12);

    static final int CERTIFICATE_VALIDITY_ERCA = (34 * 12) + 3;
    static final int CERTIFICATE_VALIDITY_ERCA_LINK = (17 * 12) + 3;
    static final int CERTIFICATE_VALIDITY_MSCA_VU_EGF = (17 * 12) + 3;
    static final int CERTIFICATE_VALIDITY_MSCA_CARD = (7 * 12) + 1;
    static final int CERTIFICATE_VALIDITY_DRIVER_CARD_MA = (5 * 12);
    static final int CERTIFICATE_VALIDITY_DRIVER_CARD_SIGN = (5 * 12) + 1;
    static final int CERTIFICATE_VALIDITY_WORKSHOP_CARD_MA = (1 * 12);
    static final int CERTIFICATE_VALIDITY_WORKSHOP_CARD_SIGN = (1 * 12) + 1;
    static final int CERTIFICATE_VALIDITY_CONTROL_CARD_MA = (2 * 12);
    static final int CERTIFICATE_VALIDITY_COMPANY_CARD_MA = (5 * 12);
    static final int CERTIFICATE_VALIDITY_VU_MA = (15 * 12) + 3;
    static final int CERTIFICATE_VALIDITY_VU_SIGN = (15 * 12) + 3;
    static final int CERTIFICATE_VALIDITY_EGF_MA = (15 * 12);

    static final byte EQUIPMENT_TYPE_DRIVER_CARD = 1;
    static final byte EQUIPMENT_TYPE_WORKSHOP_CARD = 2;
    static final byte EQUIPMENT_TYPE_CONTROL_CARD = 3;
    static final byte EQUIPMENT_TYPE_COMPANY_CARD = 4;
    static final byte EQUIPMENT_TYPE_VU = 6;
    static final byte EQUIPMENT_TYPE_MS = 7;
    static final byte EQUIPMENT_TYPE_EGF = 8;
    static final byte EQUIPMENT_TYPE_ERCA = 13;
    static final byte EQUIPMENT_TYPE_MSCA = 14;

    static final byte AUTHORISATION_TYPE_DRIVER_CARD_MA = 1;
    static final byte AUTHORISATION_TYPE_WORKSHOP_CARD_MA = 2;
    static final byte AUTHORISATION_TYPE_CONTROL_CARD_MA = 3;
    static final byte AUTHORISATION_TYPE_COMPANY_CARD_MA = 4;
    static final byte AUTHORISATION_TYPE_VU_MA = 6;
    static final byte AUTHORISATION_TYPE_EGF_MA = 8;
    static final byte AUTHORISATION_TYPE_ERCA = 13;
    static final byte AUTHORISATION_TYPE_MSCA = 14;
    static final byte AUTHORISATION_TYPE_DRIVER_CARD_SIGN = 17;
    static final byte AUTHORISATION_TYPE_WORKSHOP_CARD_SIGN = 18;
    static final byte AUTHORISATION_TYPE_VU_SIGN = 19;

    static byte[] CV_128 = new byte[]{
        (byte) 0xB6, (byte) 0x44, (byte) 0x2C, (byte) 0x45, (byte) 0x0E, (byte) 0xF8, (byte) 0xD3, (byte) 0x62,
        (byte) 0x0B, (byte) 0x7A, (byte) 0x8A, (byte) 0x97, (byte) 0x91, (byte) 0xE4, (byte) 0x5D, (byte) 0x83};
    static byte[] CV_192 = new byte[]{
        (byte) 0x72, (byte) 0xAD, (byte) 0xEA, (byte) 0xFA, (byte) 0x00, (byte) 0xBB, (byte) 0xF4, (byte) 0xEE,
        (byte) 0xF4, (byte) 0x99, (byte) 0x15, (byte) 0x70, (byte) 0x5B, (byte) 0x7E, (byte) 0xEE, (byte) 0xBB,
        (byte) 0x1C, (byte) 0x54, (byte) 0xED, (byte) 0x46, (byte) 0x8B, (byte) 0x0E, (byte) 0xF8, (byte) 0x25};
    static byte[] CV_256 = new byte[]{
        (byte) 0x1D, (byte) 0x74, (byte) 0xDB, (byte) 0xF0, (byte) 0x34, (byte) 0xC7, (byte) 0x37, (byte) 0x2F,
        (byte) 0x65, (byte) 0x55, (byte) 0xDE, (byte) 0xD5, (byte) 0xDC, (byte) 0xD1, (byte) 0x9A, (byte) 0xC3,
        (byte) 0x23, (byte) 0xD6, (byte) 0xA6, (byte) 0x25, (byte) 0x64, (byte) 0xCD, (byte) 0xBE, (byte) 0x2D,
        (byte) 0x42, (byte) 0x0D, (byte) 0x85, (byte) 0xD2, (byte) 0x32, (byte) 0x63, (byte) 0xAD, (byte) 0x60};

    static byte[] getCV(int keyLengthInBytes) {
        switch (keyLengthInBytes) {
            case 16:
                return CV_128;
            case 24:
                return CV_192;
            case 32:
                return CV_256;
            default:
                throw new NoCvDefined(keyLengthInBytes);
        }
    }

    static String getSignatureAlgorithmName(int keyLengthInBits) {
        switch (keyLengthInBits) {
            case 256:
                return "SHA256withECDSA";
            case 384:
                return "SHA384withECDSA";
            case 512:
            case 521:
                return "SHA512withECDSA";
            default:
                throw new NoSignatureAlgorithmDefined(keyLengthInBits);
        }
    }

    static String hmacHashAlgorithm(int keyLengthInBytes) {
        switch (keyLengthInBytes) {
            case 16:
                return "HmacSHA256";
            case 24:
                return "HmacSHA384";
            case 32:
                return "HmacSHA512";
            default:
                throw new NoHmacHashAlgorithmDefined(keyLengthInBytes);
        }
    }

    static class NoCvDefined extends TachographKeyToolException {
        NoCvDefined(int keyLengthInBytes) {
            super("No CV defined for key length of " + keyLengthInBytes + " bytes");
        }
    }

    static class NoSignatureAlgorithmDefined extends TachographKeyToolException {
        NoSignatureAlgorithmDefined(int keyLengthInBits) {
            super("No signature algorithm defined for key length of " + keyLengthInBits + " bits");
        }
    }

    static class NoHmacHashAlgorithmDefined extends TachographKeyToolException {
        NoHmacHashAlgorithmDefined(int keyLengthInBytes) {
            super("No HMAC hash algorithm defined for key length of " + keyLengthInBytes + " bytes");
        }
    }
}
