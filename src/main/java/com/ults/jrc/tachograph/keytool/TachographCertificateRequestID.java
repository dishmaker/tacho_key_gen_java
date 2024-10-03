package com.ults.jrc.tachograph.keytool;

/**
 * Immutable Tachograph Certificate Request ID.
 *
 * @author Klaas Mateboer
 */
public class TachographCertificateRequestID extends TachographEntityReference {

    final int serialNumber;
    final int month;
    final int year;
    final byte manufacturerCode;
    
    public TachographCertificateRequestID(int sn, int m, int y, byte mc) {
        if (y < 0)
            throw new IllegalArgumentException("Year cannot be negative: " + y);
        if (m < 0)
            throw new IllegalArgumentException("Month cannot be negative: " + m);
        this.serialNumber = sn;
        this.month = m;
        this.year = y % 100;
        this.manufacturerCode = mc;
    }

    @Override
    byte[] toByteArray() {
        byte[] result = new byte[8];
        int offset = 7;
        result[offset--] = manufacturerCode;
        result[offset--] = (byte) 0xff;
        result[offset--] = encodeBcd(year);
        result[offset--] = encodeBcd(month);
        int sn = serialNumber;
        while (offset >= 0) {
            result[offset--] = (byte) (sn & 0xff);
            sn >>= 8;
        }
        return result;
    }
}
