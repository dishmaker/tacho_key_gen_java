package com.ults.jrc.tachograph.keytool;

/**
 * Immutable Tachograph Certification Authority KID.
 *
 * @author Klaas Mateboer
 */
public class TachographCertificationAuthorityKID extends TachographEntityReference {

    final byte nationNumeric;
    final String nationAlpha;
    final byte keySerialNumber;
    final short additionalInfo;
    final byte caIdentifier;
    
    public TachographCertificationAuthorityKID(byte[] bytes) {
        int offset = 0;
        this.nationNumeric = bytes[offset++];
        this.nationAlpha = new String(new char[] {(char)bytes[offset++], (char)bytes[offset++], (char)bytes[offset++]});
        this.keySerialNumber = bytes[offset++];
        this.additionalInfo = (short) ((bytes[offset++] & 0xff) * 256 + (bytes[offset++] & 0xff));
        this.caIdentifier = bytes[offset++];
    }
    
    public TachographCertificationAuthorityKID(byte nn, String na, byte ksn, short ai, byte caid) {
        this.nationNumeric = nn;
        this.nationAlpha = na;
        this.keySerialNumber = ksn;
        this.additionalInfo = ai;
        this.caIdentifier = caid;
    }
    
    @Override
    byte[] toByteArray() {
        byte[] result = new byte[8];
        int offset = 0;
        result[offset++] = nationNumeric;
        result[offset++] = (byte) nationAlpha.charAt(0);
        result[offset++] = (byte) nationAlpha.charAt(1);
        result[offset++] = (byte) nationAlpha.charAt(2);
        result[offset++] = keySerialNumber;
        result[offset++] = (byte) ((additionalInfo >>> 8) & 0xff);
        result[offset++] = (byte) (additionalInfo & 0xff);
        result[offset++] = caIdentifier;
        return result;
    }
}
