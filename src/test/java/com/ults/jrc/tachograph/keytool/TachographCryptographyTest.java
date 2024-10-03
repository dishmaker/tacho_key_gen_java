package com.ults.jrc.tachograph.keytool;

import com.ults.jrc.tachograph.keytool.TachographCryptography.KeyPairGenerationFailure;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.Arrays;
import org.junit.Before;
import org.junit.Test;

public class TachographCryptographyTest {

    private TachographCryptography crypto;

    @Before
    public void setUp() {
        crypto = new TachographCryptography(new TachographKeyToolUser(System.out));
    }

    @Test
    public void generateKeyPair() {
        crypto.generateKeyPair("secp256r1");
    }

    @Test(expected = KeyPairGenerationFailure.class)
    public void generateKeyPairWithInvalidCurveName_throwsException() {
        crypto.generateKeyPair("invalidCurveName");
    }

    @Test
    public void deriveVuKeys1() {
        TachographExtendedSerialNumber esn = new TachographExtendedSerialNumber(1, 1, 2017, (byte) 6, (byte) -1);
        byte[] dsrcmk = readAesKey("DSRC keys/ERCA-MSCA/DSRCMK-1.bin");
        byte[] dsrck_enc = readAesKey("DSRC keys/ERCA-MSCA/UTO/Equipment/UTO_VU (1-1)_DSRCK_ENC.bin");
        byte[] dsrck_mac = readAesKey("DSRC keys/ERCA-MSCA/UTO/Equipment/UTO_VU (1-1)_DSRCK_MAC.bin");
        byte[] okm = crypto.kdf(dsrcmk, esn.toByteArray());
        assert(Arrays.equals(dsrck_enc, crypto.firstHalf(okm)));
        assert(Arrays.equals(dsrck_mac, crypto.lastHalf(okm)));
    }

    @Test
    public void deriveVuKeys2() {
        TachographExtendedSerialNumber esn = new TachographExtendedSerialNumber(5, 1, 2034, (byte) 6, (byte) -1);
        byte[] dsrcmk = readAesKey("DSRC keys/ERCA-MSCA/DSRCMK-2.bin");
        byte[] dsrck_enc = readAesKey("DSRC keys/ERCA-MSCA/UTO/Equipment/UTO_VU (2-1)_DSRCK_ENC.bin");
        byte[] dsrck_mac = readAesKey("DSRC keys/ERCA-MSCA/UTO/Equipment/UTO_VU (2-1)_DSRCK_MAC.bin");
        byte[] okm = crypto.kdf(dsrcmk, esn.toByteArray());
        assert(Arrays.equals(dsrck_enc, crypto.firstHalf(okm)));
        assert(Arrays.equals(dsrck_mac, crypto.lastHalf(okm)));
    }

    @Test
    public void deriveVuKeys3() {
        TachographExtendedSerialNumber esn = new TachographExtendedSerialNumber(9, 1, 2051, (byte) 6, (byte) -1);
        byte[] dsrcmk = readAesKey("DSRC keys/ERCA-MSCA/DSRCMK-3.bin");
        byte[] dsrck_enc = readAesKey("DSRC keys/ERCA-MSCA/UTO/Equipment/UTO_VU (3-1)_DSRCK_ENC.bin");
        byte[] dsrck_mac = readAesKey("DSRC keys/ERCA-MSCA/UTO/Equipment/UTO_VU (3-1)_DSRCK_MAC.bin");
        byte[] okm = crypto.kdf(dsrcmk, esn.toByteArray());
        assert(Arrays.equals(dsrck_enc, crypto.firstHalf(okm)));
        assert(Arrays.equals(dsrck_mac, crypto.lastHalf(okm)));
    }

    @Test
    public void encryptMsEsn1() {
        TachographExtendedSerialNumber esn = new TachographExtendedSerialNumber(1, 1, 2017, (byte) 7, (byte) -1);
        byte[] msmk = readAesKey("Motion sensor keys and encrypted data/ERCA-MSCA/MSMK-1.bin");
        byte[] expected = readAesKey("Motion sensor keys and encrypted data/ERCA-MSCA/Equipment/MS-1-SN-ENC-1.bin");
        assert(Arrays.equals(expected, crypto.encryptMsExtendedSerialNumber(msmk, esn)));
    }

    @Test
    public void encryptMsEsn2() {
        TachographExtendedSerialNumber esn = new TachographExtendedSerialNumber(2, 1, 2034, (byte) 7, (byte) -1);
        byte[] msmk = readAesKey("Motion sensor keys and encrypted data/ERCA-MSCA/MSMK-2.bin");
        byte[] expected = readAesKey("Motion sensor keys and encrypted data/ERCA-MSCA/Equipment/MS-2-SN-ENC-2.bin");
        assert(Arrays.equals(expected, crypto.encryptMsExtendedSerialNumber(msmk, esn)));
    }

    @Test
    public void encryptMsEsn3() {
        TachographExtendedSerialNumber esn = new TachographExtendedSerialNumber(3, 12, 2050, (byte) 7, (byte) -1);
        byte[] msmk = readAesKey("Motion sensor keys and encrypted data/ERCA-MSCA/MSMK-3.bin");
        byte[] expected = readAesKey("Motion sensor keys and encrypted data/ERCA-MSCA/Equipment/MS-3-SN-ENC-3.bin");
        assert(Arrays.equals(expected, crypto.encryptMsExtendedSerialNumber(msmk, esn)));
    }

    @Test
    public void encryptPairingKey1() {
        byte[] msmk = readAesKey("Motion sensor keys and encrypted data/ERCA-MSCA/MSMK-1.bin");
        byte[] pk = readAesKey("Motion sensor keys and encrypted data/ERCA-MSCA/Equipment/MS-1-PK-1.bin");
        byte[] epk = readAesKey("Motion sensor keys and encrypted data/ERCA-MSCA/Equipment/MS-1-PK-ENC-1.bin");
        assert(Arrays.equals(epk, crypto.encryptPairingKey(msmk, pk)));
    }

    @Test
    public void encryptPairingKey2() {
        byte[] msmk = readAesKey("Motion sensor keys and encrypted data/ERCA-MSCA/MSMK-2.bin");
        byte[] pk = readAesKey("Motion sensor keys and encrypted data/ERCA-MSCA/Equipment/MS-2-PK-2.bin");
        byte[] epk = readAesKey("Motion sensor keys and encrypted data/ERCA-MSCA/Equipment/MS-2-PK-ENC-2.bin");
        assert(Arrays.equals(epk, crypto.encryptPairingKey(msmk, pk)));
    }

    @Test
    public void encryptPairingKey3() {
        byte[] msmk = readAesKey("Motion sensor keys and encrypted data/ERCA-MSCA/MSMK-3.bin");
        byte[] pk = readAesKey("Motion sensor keys and encrypted data/ERCA-MSCA/Equipment/MS-3-PK-3.bin");
        byte[] epk = readAesKey("Motion sensor keys and encrypted data/ERCA-MSCA/Equipment/MS-3-PK-ENC-3.bin");
        assert(Arrays.equals(epk, crypto.encryptPairingKey(msmk, pk)));
    }

    @Test
    public void deriveMsmk128() {
        byte[] k1 = getBytes(16, (byte)0x5a);
        byte[] k2 = getBytes(16, (byte)0x96);
        byte[] kr = getBytes(16, (byte)0xcc);
        assert(Arrays.equals(kr, crypto.deriveMsmk(k1, k2)));
    }

    @Test
    public void deriveMsmk192() {
        byte[] k1 = getBytes(24, (byte)0x5a);
        byte[] k2 = getBytes(24, (byte)0x69);
        byte[] kr = getBytes(24, (byte)0x33);
        assert(Arrays.equals(kr, crypto.deriveMsmk(k1, k2)));
    }

    @Test
    public void deriveMsmk256() {
        byte[] k1 = getBytes(32, (byte)0x00);
        byte[] k2 = getBytes(32, (byte)0xff);
        byte[] kr = getBytes(32, (byte)0xff);
        assert(Arrays.equals(kr, crypto.deriveMsmk(k1, k2)));
    }

    @Test
    public void deriveMsik128() {
        byte[] msmk = readAesKey("Motion sensor keys and encrypted data/ERCA-MSCA/MSMK-1.bin");
        byte[] expected = readAesKey("Motion sensor keys and encrypted data/ERCA-MSCA/MSIK-1.bin");
        assert(Arrays.equals(expected, crypto.deriveMsik(msmk)));
    }

    @Test
    public void deriveMsik192() {
        byte[] msmk = readAesKey("Motion sensor keys and encrypted data/ERCA-MSCA/MSMK-2.bin");
        byte[] expected = readAesKey("Motion sensor keys and encrypted data/ERCA-MSCA/MSIK-2.bin");
        assert(Arrays.equals(expected, crypto.deriveMsik(msmk)));
    }

    @Test
    public void deriveMsik256() {
        byte[] msmk = readAesKey("Motion sensor keys and encrypted data/ERCA-MSCA/MSMK-3.bin");
        byte[] expected = readAesKey("Motion sensor keys and encrypted data/ERCA-MSCA/MSIK-3.bin");
        assert(Arrays.equals(expected, crypto.deriveMsik(msmk)));
    }

    private byte[] getBytes(int length, byte value) {
        byte[] result = new byte[length];
        Arrays.fill(result, value);
        return result;
    }

    private byte[] readAesKey(String fileName) {
        try {
            return Files.readAllBytes(Paths.get("src/test/resources/samples/AES keys", fileName));
        } catch (IOException ex) {
            throw new RuntimeException("Unable to read file; " + ex.getMessage(), ex);
        }
    }
}
