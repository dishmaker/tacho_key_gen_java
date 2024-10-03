package com.ults.jrc.tachograph.keytool;

/**
 * Immutable Tachograph Extended Serial Number.
 *
 * @author Klaas Mateboer
 */
public class TachographExtendedSerialNumber extends TachographEntityReference {

    final int serialNumber;
    final int month;
    final int year;
    final byte type;
    final byte manufacturerCode;
    
    public TachographExtendedSerialNumber(byte[] bytes) {
        int offset = 0;
        int sn = 0;
        while (offset < 4)
            sn = sn * 256 + (bytes[offset++] & 0xff);
        this.serialNumber = sn;
        this.month = decodeBcd(bytes[offset++]);
        this.year = decodeBcd(bytes[offset++]);
        this.type = bytes[offset++];
        this.manufacturerCode = bytes[offset++];
    }
    
    public TachographExtendedSerialNumber(int sn, int m, int y, byte t, byte mc) {
        if (y < 0)
            throw new IllegalArgumentException("Year cannot be negative: " + y);
        if (m < 0)
            throw new IllegalArgumentException("Month cannot be negative: " + m);
        this.serialNumber = sn;
        this.month = m;
        this.year = y % 100;
        this.type = t;
        this.manufacturerCode = mc;
    }

    @Override
    byte[] toByteArray() {
        byte[] result = new byte[8];
        int offset = 7;
        result[offset--] = manufacturerCode;
        result[offset--] = type;
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
