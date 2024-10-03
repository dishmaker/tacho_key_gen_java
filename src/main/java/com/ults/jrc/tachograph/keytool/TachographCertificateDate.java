package com.ults.jrc.tachograph.keytool;

import java.time.LocalDateTime;
import java.time.ZoneOffset;

/**
 * Immutable representation of a tachograph certificate date.
 *
 * @author Klaas Mateboer
 */
public abstract class TachographCertificateDate extends SimpleCertificateElement {

    private final long seconds;

    TachographCertificateDate(String name, int tag, LocalDateTime dt) {
        this(name, tag, dt.toEpochSecond(ZoneOffset.UTC));
    }

    TachographCertificateDate(String name, int tag, long seconds) {
        this(name, tag, toByteArray(seconds));
    }

    TachographCertificateDate(String name, int tag, byte[] contents) {
        super(name, tag);
        this.seconds = toLong(contents);
    }

    LocalDateTime getLocalDateTime() {
        return LocalDateTime.ofEpochSecond(seconds, 0, ZoneOffset.UTC);
    }

    long getSeconds() {
        return seconds;
    }

    @Override
    byte[] getContents() {
        return toByteArray(seconds);
    }

    private static byte[] toByteArray(long seconds) {
        if (seconds < 0 || seconds > 0x0ffffffffL)
            throw new TachographKeyToolException("Date out of range: " + seconds);
        byte[] result = new byte[4];
        for (int i = 3; i >= 0; i--) {
            result[i] = (byte) (seconds & 0xff);
            seconds >>= 8;
        }
        return result;
    }

    private static long toLong(byte[] bytes) {
        if (bytes.length != 4)
            throw new TachographKeyToolException("Certificate date should consist of four bytes");
        long result = 0;
        for (int i = 0; i < bytes.length; i++)
            result = (result << 8) + (bytes[i] & 0xff);
        return result;
    }
}