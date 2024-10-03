package com.ults.jrc.tachograph.keytool;

import java.math.BigInteger;

/**
 * Tachograph utilities.
 *
 * @author Klaas Mateboer
 */
final class TachographUtils {

    /**
     * Copy the value bytes of a big integer to a fixed size location in a byte array.
     * 
     * @param integer the integer
     * @param size the number of bytes to be set in the destination
     * @param dst the destination byte array
     * @param dstOffset the destination offset
     * @return dstOffset + size
     */
    static int copyIntegerBytes(BigInteger bi, int size, byte[] dst, int dstOffset) {
        return copyIntegerBytes(bi.toByteArray(), size, dst, dstOffset);
    }

    private static int copyIntegerBytes(byte[] integer, int size, byte[] dst, int dstOffset) {
        int srcOffset = 0;
        if (integer.length > size)
            srcOffset = integer.length - size;
        if (integer.length < size)
            dstOffset += (size - integer.length);
        int length = Math.min(integer.length, size);
        System.arraycopy(integer, srcOffset, dst, dstOffset, length);
        return dstOffset + length;
    }
}
