package com.ults.jrc.tachograph.keytool;

import static com.ults.jrc.tachograph.keytool.TachographDefinitions.KEY_USAGE_PERIOD_ERCA;
import java.time.LocalDateTime;

import org.junit.Test;

public class TachographKeyToolCliHappyFlowTest {

    @Test
    public void makeKeysAndCertificates() {
        LocalDateTime erca1EffectiveDate = LocalDateTime.now().minusMonths(KEY_USAGE_PERIOD_ERCA + 1);
        LocalDateTime erca2EffectiveDate = erca1EffectiveDate.plusMonths(KEY_USAGE_PERIOD_ERCA);
        processWithoutWarning(
            "generate",
            "ec",
            "target/test-output/erca1",
            "brainpoolp256r1"
        );
        processWithoutWarning(
            "generate",
            "ec",
            "target/test-output/erca2",
            "brainpoolp384r1"
        );
        processWithoutWarning(
            "generate",
            "ec",
            "target/test-output/msca_card2-1",
            "secp384r1"
        );
        processWithoutWarning(
            "generate",
            "ec",
            "target/test-output/driver_card_ma2-1",
            "secp384r1"
        );
        processWithoutWarning(
            "create",
            "ca",
            "erca",
            "target/test-output/erca1",
            "target/test-output/erca1.pkcs8",
            "0xFD",
            "EC",
            "1",
            "0xFFFF",
            "1",
            erca1EffectiveDate.toString()
        );
        processWithoutWarning(
            "verify", 
            "target/test-output/erca1.cert", 
            "target/test-output/erca1.cert"
        );
        processWithoutWarning(
            "create",
            "ca",
            "erca",
            "target/test-output/erca2",
            "target/test-output/erca2.pkcs8",
            "0xFD",
            "EC",
            "2",
            "0xFFFF",
            "1",
            erca2EffectiveDate.toString()
        );
        processWithoutWarning(
            "verify", 
            "target/test-output/erca2.cert", 
            "target/test-output/erca2.cert"
        );
        processWithoutWarning(
            "link",
            "target/test-output/erca1.pkcs8",
            "target/test-output/erca1.cert",
            "target/test-output/erca2.cert",
            "target/test-output/link1-2"
        );
        processWithoutWarning(
            "verify", 
            "target/test-output/link1-2.cert", 
            "target/test-output/erca1.cert"
        );
         processWithoutWarning(
            "create",
            "ca",
            "msca_card",
            "target/test-output/msca_card2-1",
            "target/test-output/msca_card2-1.pkcs8",
            "0xFC",
            "ARC",
            "1",
            "0xFFFF",
            "1"
        );
        processWithoutWarning(
            "sign",
            "target/test-output/msca_card2-1.cert",
            "target/test-output/erca2.pkcs8",
            "target/test-output/erca2.cert",
            "target/test-output/msca_card2-1"
        );
        processWithoutWarning(
            "verify", 
            "target/test-output/msca_card2-1.cert", 
            "target/test-output/erca2.cert"
        );
        processWithoutWarning(
            "create",
            "equipment",
            "driver_card_ma",
            "target/test-output/driver_card_ma2-1",
            "target/test-output/driver_card_ma2-1.pkcs8",
            "1",
            "1",
            "2018",
            "1"
        );
        processWithoutWarning(
            "sign",
            "target/test-output/driver_card_ma2-1.cert",
            "target/test-output/msca_card2-1.pkcs8",
            "target/test-output/msca_card2-1.cert",
            "target/test-output/driver_card_ma2-1"
        );
        processWithoutWarning(
            "verify", 
            "target/test-output/driver_card_ma2-1.cert", 
            "target/test-output/msca_card2-1.cert"
        );
    }

    @Test
    public void generateMsmkEncryptMs128() {
        processWithoutWarning(
            "generate",
            "aes",
            "target/test-output/aes128",
            "128"
        );
        processWithoutWarning(
            "encrypt",
            "ms",
            "target/test-output/ms128",
            "target/test-output/aes128.bin",
            "0x000000000A",
            "5",
            "2018",
            "0x45"
        );
    }

    @Test
    public void generateMsmkEncryptMs192() {
        processWithoutWarning(
            "generate",
            "aes",
            "target/test-output/aes192",
            "192"
        );
        processWithoutWarning(
            "encrypt",
            "ms",
            "target/test-output/ms192",
            "target/test-output/aes192.bin",
            "0x000000000A",
            "5",
            "2018",
            "0x45"
        );
    }

    @Test
    public void generateMsmkEncryptMs256() {
        processWithoutWarning(
            "generate",
            "aes",
            "target/test-output/aes256",
            "256"
        );
        processWithoutWarning(
            "encrypt",
            "ms",
            "target/test-output/ms256",
            "target/test-output/aes256.bin",
            "0x000000000A",
            "5",
            "2018",
            "0x45"
        );
    }

    @Test
    public void generateMsmkEncryptMs128Hex() {
        processWithoutWarning(
            "generate",
            "aes",
            "target/test-output/aes128",
            "128"
        );
        processWithoutWarning(
            "encrypt",
            "ms",
            "target/test-output/ms128",
            "target/test-output/aes128.bin",
            "0000000A0518FF45"
        );
    }

    @Test
    public void generateMsmkEncryptMs192Hex() {
        processWithoutWarning(
            "generate",
            "aes",
            "target/test-output/aes192",
            "192"
        );
        processWithoutWarning(
            "encrypt",
            "ms",
            "target/test-output/ms192",
            "target/test-output/aes192.bin",
            "0000000A0518FF45"
        );
    }

    @Test
    public void generateMsmkEncryptMs256Hex() {
        processWithoutWarning(
            "generate",
            "aes",
            "target/test-output/aes256",
            "256"
        );
        processWithoutWarning(
            "encrypt",
            "ms",
            "target/test-output/ms256",
            "target/test-output/aes256.bin",
            "0000000A0518FF45"
        );
    }

    @Test
    public void deriveMsmk128() {
        processWithoutWarning(
            "generate",
            "aes",
            "target/test-output/msmk_vu_128",
            "128"
        );
        processWithoutWarning(
            "generate",
            "aes",
            "target/test-output/msmk_wc_128",
            "128"
        );
        processWithoutWarning(
            "derive", 
            "msmk", 
            "target/test-output/msmk_128",
            "target/test-output/msmk_vu_128.bin",
            "target/test-output/msmk_wc_128.bin"
        );
    }

    @Test
    public void deriveMsmk192() {
        processWithoutWarning(
            "generate",
            "aes",
            "target/test-output/msmk_vu_192",
            "192"
        );
        processWithoutWarning(
            "generate",
            "aes",
            "target/test-output/msmk_wc_192",
            "192"
        );
        processWithoutWarning(
            "derive", 
            "msmk", 
            "target/test-output/msmk_192",
            "target/test-output/msmk_vu_192.bin",
            "target/test-output/msmk_wc_192.bin"
        );
    }

    @Test
    public void deriveMsmk256() {
        processWithoutWarning(
            "generate",
            "aes",
            "target/test-output/msmk_vu_256",
            "256"
        );
        processWithoutWarning(
            "generate",
            "aes",
            "target/test-output/msmk_wc_256",
            "256"
        );
        processWithoutWarning(
            "derive", 
            "msmk", 
            "target/test-output/msmk_256",
            "target/test-output/msmk_vu_256.bin",
            "target/test-output/msmk_wc_256.bin"
        );
    }

    private void processWithoutWarning(String... args) {
        TachographKeyToolUser happyFlowTester = new TachographKeyToolUser(System.out) {

            @Override
            public void warn(String warning) {
                throw new AssertionError("Unexpected warning: " + warning);
            }
        };
        new TachographKeyToolCli(happyFlowTester).processCommandLine(args);
    }
}
