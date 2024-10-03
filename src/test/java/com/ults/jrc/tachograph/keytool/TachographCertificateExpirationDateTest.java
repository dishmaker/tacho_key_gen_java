package com.ults.jrc.tachograph.keytool;

import java.time.LocalDateTime;
import java.time.ZoneOffset;
import org.junit.Test;

public class TachographCertificateExpirationDateTest {

    @Test
    public void testConstructionFromDateTime0() {
        LocalDateTime dt = LocalDateTime.ofEpochSecond(0, 0, ZoneOffset.UTC);
        TachographCertificateExpirationDate exd = new TachographCertificateExpirationDate(dt);
        assert(dt.equals(exd.getLocalDateTime()));
    }

    @Test
    public void testConstructionFromDateTime1() {
        LocalDateTime dt = LocalDateTime.ofEpochSecond(10000, 0, ZoneOffset.UTC);
        TachographCertificateExpirationDate exd = new TachographCertificateExpirationDate(dt);
        assert(dt.equals(exd.getLocalDateTime()));
    }

    @Test
    public void testConstructionFromDateTime2() {
        LocalDateTime dt = LocalDateTime.ofEpochSecond(0x0ffffffffL, 0, ZoneOffset.UTC);
        TachographCertificateExpirationDate exd = new TachographCertificateExpirationDate(dt);
        assert(dt.equals(exd.getLocalDateTime()));
    }

    @Test
    public void testConstructionFromLong0() {
        assert(new TachographCertificateExpirationDate(0).getSeconds() == 0);
    }

    @Test
    public void testConstructionFromLong1() {
        assert(new TachographCertificateExpirationDate(50000).getSeconds() == 50000);
    }

    @Test
    public void testConstructionFromLong2() {
        assert(new TachographCertificateExpirationDate(0x01234567L).getSeconds() == 0x01234567L);
    }

    @Test
    public void testConstructionFromLong3() {
        assert(new TachographCertificateExpirationDate(0x0ffffffffL).getSeconds() == 0x0ffffffffL);
    }

    @Test
    public void testConstructionFromBytes0() {
        assert(new TachographCertificateExpirationDate(new byte[4]).getSeconds() == 0);
    }

    @Test
    public void testConstructionFromBytes1() {
        byte[] bytes = new byte[] {(byte) 0x98, (byte) 0x5b, (byte) 0xa9, (byte) 0x7f};
        assert(new TachographCertificateExpirationDate(bytes).getSeconds() == 2556143999L);
    }

    @Test
    public void testMinDateTime() {
        LocalDateTime dt = LocalDateTime.ofEpochSecond(0, 0, ZoneOffset.UTC);
        TachographCertificateExpirationDate exd = new TachographCertificateExpirationDate(dt);
        assert(dt.equals(exd.getLocalDateTime()));
    }

    @Test
    public void testMaxDateTime() {
        LocalDateTime dt = LocalDateTime.ofEpochSecond(0x0ffffffffL, 0, ZoneOffset.UTC);
        TachographCertificateExpirationDate exd = new TachographCertificateExpirationDate(dt);
        assert(dt.equals(exd.getLocalDateTime()));
    }

    @Test(expected = TachographKeyToolException.class)
    public void testDateTimeBeforeEpoch() {
        LocalDateTime dt = LocalDateTime.ofEpochSecond(-1, 0, ZoneOffset.UTC);
        new TachographCertificateExpirationDate(dt);
    }

    @Test(expected = TachographKeyToolException.class)
    public void testDateTimeAfterEnd() {
        LocalDateTime dt = LocalDateTime.ofEpochSecond(0x100000000L, 0, ZoneOffset.UTC);
        new TachographCertificateExpirationDate(dt);
    }
}
