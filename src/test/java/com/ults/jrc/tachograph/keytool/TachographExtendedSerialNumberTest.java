package com.ults.jrc.tachograph.keytool;

import org.junit.Assert;
import org.junit.Test;

public class TachographExtendedSerialNumberTest {

    @Test
    public void testConstructionFromBytes() {
        byte[] bytes = new byte[] {(byte)0x00, (byte)0x00, (byte)0x00, (byte)0x0a, (byte)0x05, (byte)0x18, (byte)0x01, (byte)0x45};
        Assert.assertArrayEquals(bytes, new TachographExtendedSerialNumber(bytes).toByteArray());
    }

    @Test
    public void testConstructionFromBytesWithLargeSerialNumber() {
        byte[] bytes = new byte[] {(byte)0xff, (byte)0xff, (byte)0xff, (byte)0xff, (byte)0x00, (byte)0x18, (byte)0x01, (byte)0x45};
        Assert.assertArrayEquals(bytes, new TachographExtendedSerialNumber(bytes).toByteArray());
    }

    @Test(expected = IllegalArgumentException.class)
    public void testConstructionFromBytesWithInvalidMonthBcd() {
        byte[] bytes = new byte[] {(byte)0x00, (byte)0x00, (byte)0x00, (byte)0x0a, (byte)0xff, (byte)0x18, (byte)0x01, (byte)0x45};
        Assert.assertArrayEquals(bytes, new TachographExtendedSerialNumber(bytes).toByteArray());
    }

    @Test(expected = IllegalArgumentException.class)
    public void testConstructionFromBytesWithInvalidYearBcd() {
        byte[] bytes = new byte[] {(byte)0x00, (byte)0x00, (byte)0x00, (byte)0x0a, (byte)0x12, (byte)0xa0, (byte)0x01, (byte)0x45};
        Assert.assertArrayEquals(bytes, new TachographExtendedSerialNumber(bytes).toByteArray());
    }

    @Test
    public void testConstructionFromFields() {
        byte[] bytes = new byte[] {(byte)0x00, (byte)0x00, (byte)0x01, (byte)0x00, (byte)0x11, (byte)0x50, (byte)0x03, (byte)0xff};
        Assert.assertArrayEquals(bytes, new TachographExtendedSerialNumber(256, 11, 2050, (byte)3, (byte)-1).toByteArray());
    }

    @Test(expected = IllegalArgumentException.class)
    public void testConstructionFromFieldsWithInvalidMonth() {
        new TachographExtendedSerialNumber(256, -1, 2050, (byte)3, (byte)-1).toByteArray();
    }

    @Test(expected = IllegalArgumentException.class)
    public void testConstructionFromFieldsWithInvalidYear() {
        new TachographExtendedSerialNumber(256, 1, -1, (byte)3, (byte)-1).toByteArray();
    }
}
