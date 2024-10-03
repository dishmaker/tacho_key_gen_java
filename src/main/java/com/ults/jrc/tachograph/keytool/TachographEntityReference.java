package com.ults.jrc.tachograph.keytool;

/**
 * Abstract base class for entity references used in tachograph certificates.
 * 
 * @author Klaas Mateboer
 */
public abstract class TachographEntityReference {

    /**
     * Serialize the reference to a byte array.
     * 
     * @return the bytes
     */
    abstract byte[] toByteArray();
    
    final byte encodeBcd(int value) {
        if (value < 0 || value > 99)
            throw new IllegalArgumentException("Value cannot be encoded to a single byte BCD: " + value);
        return (byte) ((value % 10) + (((value / 10) % 10) * 16));
    }
    
    final byte decodeBcd(byte bcd) {
        int result = (byte) (bcd & 0x0f);
        if (result > 9)
            throw new IllegalArgumentException("Improper value for binary coded decimal: " + bcd);
        result += (((bcd / 16) & 0x0f) * 10);
        if (result > 99)
            throw new IllegalArgumentException("Improper value for binary coded decimal: " + bcd);
        return (byte) result; 
    }
}
