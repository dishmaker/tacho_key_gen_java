package com.ults.jrc.tachograph.keytool;

import static com.ults.jrc.tachograph.keytool.TachographKeyToolCli.process;

import org.junit.Test;

public class TachographKeyToolCliTest {

    @Test
    public void main() {
        TachographKeyToolCli.main(new String[0]);
    }

    @Test
    public void usage() {
        process();
    }

    @Test
    public void generateHelp() {
        process(
            "generate"
        );
    }

    @Test
    public void generateTruncated() {
        process(
            "g",
            "e",
            "target/test-output/erca1",
            "brainpoolp256r1"
        );
    }

    @Test
    public void generateBrainpoolp256r1() {
        process(
            "generate",
            "ec",
            "target/test-output/erca1",
            "brainpoolp256r1"
        );
    }

    @Test
    public void generateBrainpoolp384r1() {
        process(
            "generate",
            "ec",
            "target/test-output/erca1",
            "brainpoolp384r1"
        );
    }

    @Test
    public void generateBrainpoolp512r1() {
        process(
            "generate",
            "ec",
            "target/test-output/erca1",
            "brainpoolp512r1"
        );
    }

    @Test
    public void generateSecp256r1() {
        process(
            "generate",
            "ec",
            "target/test-output/erca1",
            "secp256r1"
        );
    }

    @Test
    public void generateSecp384r1() {
        process(
            "generate",
            "ec",
            "target/test-output/erca1",
            "secp384r1"
        );
    }

    @Test
    public void generateSecp521r1() {
        process(
            "generate",
            "ec",
            "target/test-output/erca1",
            "secp521r1"
        );
    }

    @Test
    public void generateSecp521r1a() {
        process(
            "generate",
            "ec",
            "target/test-output/ercaa",
            "secp521r1"
        );
    }

    @Test
    public void generateSecp521r1b() {
        process(
            "generate",
            "ec",
            "target/test-output/ercab",
            "secp521r1"
        );
    }

    @Test
    public void generateSecp521r1c() {
        process(
            "generate",
            "ec",
            "target/test-output/ercac",
            "secp521r1"
        );
    }

    @Test
    public void generateSecp521r1d() {
        process(
            "generate",
            "ec",
            "target/test-output/ercad",
            "secp521r1"
        );
    }

    @Test
    public void generateSecp521r1e() {
        process(
            "generate",
            "ec",
            "target/test-output/ercae",
            "secp521r1"
        );
    }

    @Test
    public void generateAes128() {
        process(
            "generate",
            "aes",
            "target/test-output/aes128",
            "128"
        );
    }

    @Test
    public void generateAes192() {
        process(
            "generate",
            "aes",
            "target/test-output/aes192",
            "192"
        );
    }

    @Test
    public void generateAes256() {
        process(
            "generate",
            "aes",
            "target/test-output/aes256",
            "256"
        );
    }

    @Test
    public void create() {
        process(
            "create"
        );
    }

    @Test
    public void createErca() {
        process(
            "create",
            "ca",
            "erca",
            "target/test-output/erca1",
            "src/test/resources/samples/ECC keys and certificates/ERCA/ERCA (1).pkcs8",
            "0xFD",
            "EC",
            "1",
            "0xFFFF",
            "1",
            "2018-01-01T12:00:00"
        );
    }

    @Test
    public void createMscaVuEgf() {
        process(
            "create",
            "ca",
            "msca_vu_egf",
            "target/test-output/msca_vu_egf1",
            "src/test/resources/samples/ECC keys and certificates/ERCA/MSCA/ARC/ARC_MSCA_VU-EGF (1-1).pkcs8",
            "0xFC",
            "ARC",
            "1",
            "0xFFFF",
            "1",
            "2018-01-01T12:00:00"
        );
    }

    @Test
    public void createMscaCard() {
        process(
            "create",
            "ca",
            "msca_card",
            "target/test-output/msca_card1",
            "src/test/resources/samples/ECC keys and certificates/ERCA/MSCA/ARC/ARC_MSCA_Card (1-1).pkcs8",
            "0xFC",
            "ARC",
            "1",
            "0xFFFF",
            "1",
            "2018-01-01T12:00:00"
        );
    }

    @Test
    public void createDriverCardMa() {
        process(
            "create",
            "equipment",
            "driver_card_ma",
            "target/test-output/driver_card_ma1",
            "src/test/resources/samples/ECC keys and certificates/ERCA/MSCA/ARC/Equipment/TC/ARC_Driver_Card_MA (1-1).pkcs8",
            "0x00000001",
            "1",
            "2018",
            "0x01",
            "2018-01-01T12:00:00"
        );
    }

    @Test
    public void createDriverCardSign() {
        process(
            "create",
            "equipment",
            "driver_card_sign",
            "target/test-output/driver_card_sign1234",
            "src/test/resources/samples/ECC keys and certificates/ERCA/MSCA/ARC/Equipment/TC/ARC_Driver_Card_Sign (1-1).pkcs8",
            "1234",
            "1",
            "2018",
            "1",
            "2018-01-01T12:00:00"
        );
    }

    @Test
    public void createWorkshopCardMa() {
        process(
            "create",
            "equipment",
            "workshop_card_ma",
            "target/test-output/workshop_card_ma1",
            "src/test/resources/samples/ECC keys and certificates/ERCA/MSCA/ARC/Equipment/TC/ARC_Workshop_Card_MA (1-1).pkcs8",
            "0000000000000000000000001",
            "1",
            "2018",
            "0000000000000000000000001",
            "2018-01-01T12:00:00"
        );
    }

    @Test
    public void createWorkshopCardSign() {
        process(
            "create",
            "equipment",
            "workshop_card_sign",
            "target/test-output/workshop_card_sign1",
            "src/test/resources/samples/ECC keys and certificates/ERCA/MSCA/ARC/Equipment/TC/ARC_Workshop_Card_Sign (1-1).pkcs8",
            "-1",
            "1",
            "2018",
            "-1",
            "2018-01-01T12:00:00"
        );
    }

    @Test
    public void createControlCardMa() {
        process(
            "create",
            "equipment",
            "control_card_ma",
            "target/test-output/control_card_ma1",
            "src/test/resources/samples/ECC keys and certificates/ERCA/MSCA/ARC/Equipment/TC/ARC_Control_Card_MA (1-1).pkcs8",
            "1625346123",
            "1",
            "2018",
            "-1625346123",
            "2018-01-01T12:00:00"
        );
    }

    @Test
    public void createCompanyCardMa() {
        process(
            "create",
            "equipment",
            "company_card_ma",
            "target/test-output/company_card_ma1",
            "src/test/resources/samples/ECC keys and certificates/ERCA/MSCA/ARC/Equipment/TC/ARC_Company_Card_MA (1-1).pkcs8",
            "1",
            "1",
            "2018",
            "1",
            "2018-01-01T12:00:00"
        );
    }

    @Test
    public void createVuMa() {
        process(
            "create",
            "equipment",
            "vu_ma",
            "target/test-output/vu_ma1",
            "src/test/resources/samples/ECC keys and certificates/ERCA/MSCA/ARC/Equipment/VU/ARC_VU_MA (1-1).pkcs8",
            "1",
            "1",
            "2018",
            "1",
            "2018-01-01T12:00:00"
        );
    }

    @Test
    public void createVuSign() {
        process(
            "create",
            "equipment",
            "vu_sign",
            "target/test-output/vu_sign1",
            "src/test/resources/samples/ECC keys and certificates/ERCA/MSCA/ARC/Equipment/VU/ARC_VU_Sign (1-1).pkcs8",
            "1",
            "1",
            "2018",
            "1",
            "2018-01-01T12:00:00"
        );
    }

    @Test
    public void createRequestVuMa() {
        process(
            "create",
            "request",
            "vu_ma",
            "target/test-output/request_vu_ma1",
            "src/test/resources/samples/ECC keys and certificates/ERCA/MSCA/ARC/Equipment/VU/ARC_VU_MA (1-1).pkcs8",
            "1",
            "1",
            "2018",
            "1",
            "2018-01-01T12:00:00"
        );
    }

    @Test
    public void createRequestVuSign() {
        process(
            "create",
            "request",
            "vu_sign",
            "target/test-output/request_vu_sign1",
            "src/test/resources/samples/ECC keys and certificates/ERCA/MSCA/ARC/Equipment/VU/ARC_VU_Sign (1-1).pkcs8",
            "1",
            "1",
            "2018",
            "1",
            "2018-01-01T12:00:00"
        );
    }

    @Test
    public void createEgfMa() {
        process(
            "create",
            "equipment",
            "egf_ma",
            "target/test-output/egf_ma1",
            "src/test/resources/samples/ECC keys and certificates/ERCA/MSCA/ARC/Equipment/EGF/ARC_EGF_MA (1-1).pkcs8",
            "1",
            "1",
            "2018",
            "1",
            "2018-01-01T12:00:00"
        );
    }

    @Test
    public void createTruncated() {
        process(
            "c",
            "c",
            "e",
            "target/test-output/erca1",
            "src/test/resources/samples/ECC keys and certificates/ERCA/ERCA (1).pkcs8",
            "0xFD",
            "EC ",
            "1",
            "0xFFFF",
            "1"
        );
    }

    @Test
    public void createShortNationAlpha() {
        process(
            "create",
            "ca",
            "erca",
            "target/test-output/erca1",
            "src/test/resources/samples/ECC keys and certificates/ERCA/ERCA (1).pkcs8",
            "0xFD",
            "EC",
            "1",
            "0xFFFF",
            "1"
        );
    }

    @Test
    public void createWithExpirationDate() {
        process(
            "create",
            "ca",
            "erca",
            "target/test-output/erca1",
            "src/test/resources/samples/ECC keys and certificates/ERCA/ERCA (1).pkcs8",
            "0xFD",
            "EC",
            "1",
            "0xFFFF",
            "1",
            "2018-01-01T12:00:00",
            "2018-03-01T12:00:00"
        );
    }

    @Test
    public void link() {
        process(
            "link"
        );
    }

    @Test
    public void linkErca() {
        process(
            "link",
            "src/test/resources/samples/ECC keys and certificates/ERCA/ERCA (1).pkcs8",
            "src/test/resources/samples/ECC keys and certificates/ERCA/ERCA (1).cert",
            "src/test/resources/samples/ECC keys and certificates/ERCA/ERCA (2).cert",
            "target/test-output/link"
        );
        process(
            "verify", 
            "target/test-output/link.cert", 
            "src/test/resources/samples/ECC keys and certificates/ERCA/ERCA (1).cert"
        );
    }

    @Test
    public void sign() {
        process(
            "sign"
        );
    }

    @Test
    public void signErca() {
        process(
            "sign",
            "src/test/resources/samples/ECC keys and certificates/ERCA/ERCA (1).cert",
            "src/test/resources/samples/ECC keys and certificates/ERCA/ERCA (1).pkcs8",
            "src/test/resources/samples/ECC keys and certificates/ERCA/ERCA (1).cert",
            "target/test-output/signed"
        );
        process(
            "verify", 
            "target/test-output/signed.cert", 
            "src/test/resources/samples/ECC keys and certificates/ERCA/ERCA (1).cert"
        );
    }

    @Test
    public void verify() {
        process(
            "verify"
        );
    }
    
    @Test
    public void verifyErca1() {
        process(
            "verify",
            "src/test/resources/samples/ECC keys and certificates/ERCA/ERCA (1).cert",
            "src/test/resources/samples/ECC keys and certificates/ERCA/ERCA (1).cert"
        );
    }
    
    @Test
    public void derive() {
        process(
            "derive"
       );
    }

    @Test
    public void deriveDsrcKeys1() {
        process(
            "derive", 
            "dsrc", 
            "target/test-output/dsrc1",
            "src/test/resources/samples/AES keys/DSRC keys/ERCA-MSCA/DSRCMK-1.bin",
            "1",
            "1",
            "2017",
            "-1"
        );
    }

    @Test
    public void deriveDsrcKeys2() {
        process(
            "derive", 
            "dsrc", 
            "target/test-output/dsrc2",
            "src/test/resources/samples/AES keys/DSRC keys/ERCA-MSCA/DSRCMK-2.bin",
            "5",
            "1",
            "2034",
            "-1"
        );
    }

    @Test
    public void deriveDsrcKeys3() {
        process(
            "derive", 
            "dsrc", 
            "target/test-output/dsrc3",
            "src/test/resources/samples/AES keys/DSRC keys/ERCA-MSCA/DSRCMK-3.bin",
            "10",
            "1",
            "2051",
            "-1"
        );
    }

    @Test
    public void deriveMsmk1() {
        process(
            "derive", 
            "msmk", 
            "target/test-output/msmk1",
            "src/test/resources/samples/AES keys/Motion sensor keys and encrypted data/ERCA-MSCA/MSMK-1-VU.bin",
            "src/test/resources/samples/AES keys/Motion sensor keys and encrypted data/ERCA-MSCA/MSMK-1-WS.bin"
        );
    }

    @Test
    public void deriveMsmk2() {
        process(
            "derive", 
            "msmk", 
            "target/test-output/msmk2",
            "src/test/resources/samples/AES keys/Motion sensor keys and encrypted data/ERCA-MSCA/MSMK-2-VU.bin",
            "src/test/resources/samples/AES keys/Motion sensor keys and encrypted data/ERCA-MSCA/MSMK-2-WS.bin"
        );
    }

    @Test
    public void deriveMsmk3() {
        process(
            "derive", 
            "msmk", 
            "target/test-output/msmk3",
            "src/test/resources/samples/AES keys/Motion sensor keys and encrypted data/ERCA-MSCA/MSMK-3-VU.bin",
            "src/test/resources/samples/AES keys/Motion sensor keys and encrypted data/ERCA-MSCA/MSMK-3-WS.bin"
        );
    }

    @Test
    public void deriveMsik1() {
        process(
            "derive", 
            "msik", 
            "target/test-output/msik1",
            "src/test/resources/samples/AES keys/Motion sensor keys and encrypted data/ERCA-MSCA/MSMK-1.bin"
        );
    }

    @Test
    public void deriveMsik2() {
        process(
            "derive", 
            "msik", 
            "target/test-output/msik2",
            "src/test/resources/samples/AES keys/Motion sensor keys and encrypted data/ERCA-MSCA/MSMK-2.bin"
        );
    }

    @Test
    public void deriveMsik3() {
        process(
            "derive", 
            "msik", 
            "target/test-output/msik3",
            "src/test/resources/samples/AES keys/Motion sensor keys and encrypted data/ERCA-MSCA/MSMK-3.bin"
        );
    }

    @Test
    public void encrypt() {
        process(
            "encrypt"
        );
    }

    @Test
    public void encryptMsEsn1() {
        process(
            "encrypt", 
            "ms", 
            "target/test-output/ms1",
            "src/test/resources/samples/AES keys/Motion sensor keys and encrypted data/ERCA-MSCA/MSMK-1.bin",
            "0",
            "1",
            "2017",
            "-1"
        );
    }

    @Test
    public void encryptMsEsn2() {
        process(
            "encrypt", 
            "ms", 
            "target/test-output/ms2",
            "src/test/resources/samples/AES keys/Motion sensor keys and encrypted data/ERCA-MSCA/MSMK-2.bin",
            "0",
            "1",
            "2017",
            "-1"
        );
    }

    @Test
    public void encryptMsEsn3() {
        process(
            "encrypt", 
            "ms", 
            "target/test-output/ms3",
            "src/test/resources/samples/AES keys/Motion sensor keys and encrypted data/ERCA-MSCA/MSMK-3.bin",
            "0",
            "1",
            "2017",
            "-1"
        );
    }

    @Test
    public void encryptPairingKey1() {
        process(
            "encrypt", 
            "pk", 
            "target/test-output/pk1",
            "src/test/resources/samples/AES keys/Motion sensor keys and encrypted data/ERCA-MSCA/MSMK-1.bin",
            "src/test/resources/samples/AES keys/Motion sensor keys and encrypted data/ERCA-MSCA/Equipment/MS-1-PK-1.bin"
        );
    }

    @Test
    public void encryptPairingKey2() {
        process(
            "encrypt", 
            "pk", 
            "target/test-output/pk2",
            "src/test/resources/samples/AES keys/Motion sensor keys and encrypted data/ERCA-MSCA/MSMK-2.bin",
            "src/test/resources/samples/AES keys/Motion sensor keys and encrypted data/ERCA-MSCA/Equipment/MS-2-PK-2.bin"
        );
    }

    @Test
    public void encryptPairingKey3() {
        process(
            "encrypt", 
            "pk", 
            "target/test-output/pk3",
            "src/test/resources/samples/AES keys/Motion sensor keys and encrypted data/ERCA-MSCA/MSMK-3.bin",
            "src/test/resources/samples/AES keys/Motion sensor keys and encrypted data/ERCA-MSCA/Equipment/MS-3-PK-3.bin"
        );
    }
}
