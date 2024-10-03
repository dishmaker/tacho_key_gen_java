package com.ults.jrc.tachograph.keytool;

import com.ults.jrc.tachograph.keytool.TachographCryptography.InvalidSignature;
import java.io.ByteArrayOutputStream;
import java.io.PrintStream;

import org.junit.Test;

public class TachographKeyToolCliWarningTest {

    @Test
    public void noArgumentsShowUsage() {
        checkWarning(
            "Usage"
        );
    }

    @Test
    public void unknownCommand() {
        checkWarning(
            "Unknown command \"unknownCommand\"",
            "unknownCommand"
        );
    }

    @Test
    public void nationNumericTooLarge() {
        checkWarning(
            "loss of data due to type conversion",
            "create",
            "ca",
            "msca_vu_egf",
            "target/test-output/msca_vu_egf1",
            "src/test/resources/samples/ECC keys and certificates/ERCA/MSCA/ARC/ARC_MSCA_VU-EGF (1-1).pkcs8",
            "256",
            "ARC",
            "1",
            "0xFFFF",
            "1",
            "2018-01-01T12:00:00"
        );
    }

    @Test
    public void nationNumericNotCompliant() {
        checkWarning(
            "nation numeric of ERCA certificate holder reference is not equal to 0xFD",
            "create",
            "ca",
            "erca",
            "target/test-output/erca1",
            "src/test/resources/samples/ECC keys and certificates/ERCA/ERCA (1).pkcs8",
            "0x00",
            "EC",
            "1",
            "0xFFFF",
            "1",
            "2018-01-01T12:00:00"
        );
    }

    @Test
    public void nationAlphaNotCompliant() {
        checkWarning(
            "nation alpha of ERCA certificate holder reference is not equal to EC: ec ",
            "create",
            "ca",
            "erca",
            "target/test-output/erca1",
            "src/test/resources/samples/ECC keys and certificates/ERCA/ERCA (1).pkcs8",
            "0xFD",
            "ec",
            "1",
            "0xFFFF",
            "1",
            "2018-01-01T12:00:00"
        );
    }

    @Test
    public void keySerialNumberTooLarge() {
        checkWarning(
            "loss of data due to type conversion",
            "create",
            "ca",
            "msca_card",
            "target/test-output/msca_card1",
            "src/test/resources/samples/ECC keys and certificates/ERCA/MSCA/ARC/ARC_MSCA_Card (1-1).pkcs8",
            "0xFC",
            "ARC",
            "256",
            "0xFFFF",
            "1",
            "2018-01-01T12:00:00"
        );
    }

    @Test
    public void additionalInfoTooLarge() {
        checkWarning(
            "loss of data due to type conversion",
            "create",
            "ca",
            "erca",
            "target/test-output/erca1",
            "src/test/resources/samples/ECC keys and certificates/ERCA/ERCA (1).pkcs8",
            "0xFD",
            "EC",
            "1",
            "0x010000",
            "1",
            "2018-01-01T12:00:00"
        );
    }

    @Test
    public void additionalInfoTooSmall() {
        checkWarning(
            "loss of data due to type conversion",
            "create",
            "ca",
            "erca",
            "target/test-output/erca1",
            "src/test/resources/samples/ECC keys and certificates/ERCA/ERCA (1).pkcs8",
            "0xFD",
            "EC",
            "1",
            "-65537",
            "1",
            "2018-01-01T12:00:00"
        );
    }

    @Test
    public void caIdentifierTooLarge() {
        checkWarning(
            "loss of data due to type conversion",
            "create",
            "ca",
            "erca",
            "target/test-output/erca1",
            "src/test/resources/samples/ECC keys and certificates/ERCA/ERCA (1).pkcs8",
            "0xFD",
            "EC",
            "1",
            "0xFFFF",
            "256",
            "2018-01-01T12:00:00"
        );
    }

    @Test
    public void certificateExpired() {
        checkWarning(
            "certificate is expired",
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
            "1970-01-01T12:00:00"
        );
    }

    @Test
    public void certificateNotYetValid() {
        checkWarning(
            "certificate is not yet valid",
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
            "2070-01-01T12:00:00"
        );
    }

    @Test
    public void equipmentSerialNumberTooLarge() {
        checkWarning(
            "loss of data due to type conversion",
            "create",
            "equipment",
            "control_card_ma",
            "target/test-output/control_card_ma1",
            "src/test/resources/samples/ECC keys and certificates/ERCA/MSCA/ARC/Equipment/TC/ARC_Control_Card_MA (1-1).pkcs8",
            "0x1234567890",
            "1",
            "2018",
            "1",
            "2018-01-01T12:00:00"
        );
    }

    @Test
    public void equipmentSerialNumberTooSmall() {
        checkWarning(
            "loss of data due to type conversion",
            "create",
            "equipment",
            "control_card_ma",
            "target/test-output/control_card_ma1",
            "src/test/resources/samples/ECC keys and certificates/ERCA/MSCA/ARC/Equipment/TC/ARC_Control_Card_MA (1-1).pkcs8",
            "-4294967297",
            "1",
            "2018",
            "1",
            "2018-01-01T12:00:00"
        );
    }

    @Test
    public void manufacturerCodeTooLarge() {
        checkWarning(
            "loss of data due to type conversion",
            "create",
            "equipment",
            "control_card_ma",
            "target/test-output/control_card_ma1",
            "src/test/resources/samples/ECC keys and certificates/ERCA/MSCA/ARC/Equipment/TC/ARC_Control_Card_MA (1-1).pkcs8",
            "1",
            "1",
            "2018",
            "1625346123",
            "2018-01-01T12:00:00"
        );
    }

    @Test
    public void manufacturerCodeTooSmall() {
        checkWarning(
            "loss of data due to type conversion",
            "create",
            "equipment",
            "control_card_ma",
            "target/test-output/control_card_ma1",
            "src/test/resources/samples/ECC keys and certificates/ERCA/MSCA/ARC/Equipment/TC/ARC_Control_Card_MA (1-1).pkcs8",
            "1",
            "1",
            "2018",
            "-257",
            "2018-01-01T12:00:00"
        );
    }

    @Test
    public void expirationDateBeforeEffectiveDate() {
        checkWarning(
            "certificate expiration date is before its effective date",
            "create",
            "equipment",
            "control_card_ma",
            "target/test-output/control_card_ma1",
            "src/test/resources/samples/ECC keys and certificates/ERCA/MSCA/ARC/Equipment/TC/ARC_Control_Card_MA (1-1).pkcs8",
            "1",
            "1",
            "2018",
            "1",
            "2018-02-01T12:00:00",
            "2018-01-01T12:00:00"
        );
    }

    @Test
    public void expirationDateEqualsEffectiveDate() {
        checkWarning(
            "certificate expiration date is equal to its effective date",
            "create",
            "equipment",
            "control_card_ma",
            "target/test-output/control_card_ma1",
            "src/test/resources/samples/ECC keys and certificates/ERCA/MSCA/ARC/Equipment/TC/ARC_Control_Card_MA (1-1).pkcs8",
            "1",
            "1",
            "2018",
            "1",
            "2018-01-01T12:00:00",
            "2018-01-01T12:00:00"
        );
    }

    @Test
    public void linkPreceedingValidityPeriod() {
        checkWarning(
            "certificate validity period preceeds the CA certificate validity period",
            "link",
            "src/test/resources/samples/ECC keys and certificates/ERCA/ERCA (3).pkcs8",
            "src/test/resources/samples/ECC keys and certificates/ERCA/ERCA (3).cert",
            "src/test/resources/samples/ECC keys and certificates/ERCA/ERCA (1).cert",
            "target/test-output/signed"
        );
    }

    @Test
    public void signExceedingValidityPeriod() {
        checkWarning(
            "certificate validity period exceeds the CA certificate validity period",
            "sign",
            "src/test/resources/samples/ECC keys and certificates/ERCA/ERCA (3).cert",
            "src/test/resources/samples/ECC keys and certificates/ERCA/ERCA (1).pkcs8",
            "src/test/resources/samples/ECC keys and certificates/ERCA/ERCA (1).cert",
            "target/test-output/signed"
        );
    }

    @Test
    public void signPreceedingValidityPeriod() {
        checkWarning(
            "certificate validity period preceeds the CA certificate validity period",
            "sign",
            "src/test/resources/samples/ECC keys and certificates/ERCA/ERCA (1).cert",
            "src/test/resources/samples/ECC keys and certificates/ERCA/ERCA (3).pkcs8",
            "src/test/resources/samples/ECC keys and certificates/ERCA/ERCA (3).cert",
            "target/test-output/signed"
        );
    }

    @Test
    public void signWithAuthorisationMismatch() {
        checkWarning(
            "signer authorisation does not match the certificate authorisation",
            "sign",
            "src/test/resources/samples/ECC keys and certificates/ERCA/ERCA (1).cert",
            "src/test/resources/samples/ECC keys and certificates/ERCA/MSCA/ARC/ARC_MSCA_Card (1-1).pkcs8",
            "src/test/resources/samples/ECC keys and certificates/ERCA/MSCA/ARC/ARC_MSCA_Card (1-1).cert",
            "target/test-output/signed"
        );
    }

    @Test
    public void signRequestNotSelfSigned() {
        checkWarning(
            "certificate holder and authority references should be equal",
            "sign",
            "src/test/resources/samples/ECC keys and certificates/ERCA/ERCA (1) - ERCA (2).cert",
            "src/test/resources/samples/ECC keys and certificates/ERCA/ERCA (2).pkcs8",
            "src/test/resources/samples/ECC keys and certificates/ERCA/ERCA (2).cert",
            "target/test-output/signed"
        );
    }

    @Test
    public void signWithWeakerKey() {
        checkWarning(
            "certificate is signed with a weaker key",
            "sign",
            "src/test/resources/samples/ECC keys and certificates/ERCA/MSCA/ARC/ARC_MSCA_Card (2-1).cert",
            "src/test/resources/samples/ECC keys and certificates/ERCA/ERCA (1).pkcs8",
            "src/test/resources/samples/ECC keys and certificates/ERCA/ERCA (1).cert",
            "target/test-output/signed"
        );
    }

    @Test(expected = InvalidSignature.class)
    public void signWithLinkCertificate() {
        checkWarning(
            "certificate validity period preceeds the CA certificate validity period",
            "sign",
            "src/test/resources/samples/ECC keys and certificates/ERCA/MSCA/ARC/ARC_MSCA_Card (1-1).cert",
            "src/test/resources/samples/ECC keys and certificates/ERCA/ERCA (1).pkcs8",
            "src/test/resources/samples/ECC keys and certificates/ERCA/ERCA (2).cert",
            "target/test-output/signed"
        );
    }

    @Test(expected = InvalidSignature.class)
    public void verifyWithWrongCaCertificate_warnsAboutReferenceMismatch() {
        checkWarning(
            "certificate authority reference does not equal CA certificate holder reference",
            "verify",
            "src/test/resources/samples/ECC keys and certificates/ERCA/MSCA/ARC/ARC_MSCA_Card (1-1).cert",
            "src/test/resources/samples/ECC keys and certificates/ERCA/ERCA (2).cert"
         );
    }

    @Test(expected = InvalidSignature.class)
    public void verifyWithWrongCaCertificate_warnsAboutValidityPeriodMismatch() {
        checkWarning(
            "certificate validity period preceeds the CA certificate validity period",
            "verify",
            "src/test/resources/samples/ECC keys and certificates/ERCA/MSCA/ARC/ARC_MSCA_Card (1-1).cert",
            "src/test/resources/samples/ECC keys and certificates/ERCA/ERCA (2).cert"
         );
    }

    @Test(expected = InvalidSignature.class)
    public void verifyCertificateWithWrongProfileIdentifier() {
        checkWarning(
            "certificate profile identifier should be zero",
            "verify",
            "src/test/resources/testfiles/wrong_profile_identifier_value.cert",
            "src/test/resources/samples/ECC keys and certificates/ERCA/ERCA (1).cert"
         );
    }

    @Test
    public void deriveMonthLessThanOne() {
        checkWarning(
            "month should be a number in the range [1,12]",
            "derive",
            "dsrc",
            "target/test-output/dsrc1",
            "src/test/resources/samples/AES keys/DSRC keys/ERCA-MSCA/DSRCMK-1.bin",
            "1",
            "0",
            "2017",
            "-1"
        );
    }

    @Test
    public void deriveMonthGreaterThanTwelve() {
        checkWarning(
            "month should be a number in the range [1,12]",
            "derive",
            "dsrc",
            "target/test-output/dsrc1",
            "src/test/resources/samples/AES keys/DSRC keys/ERCA-MSCA/DSRCMK-1.bin",
            "1",
            "13",
            "2017",
            "-1"
        );
    }

    @Test
    public void deriveEquipmentSerialNumberTooLarge() {
        checkWarning(
            "loss of data due to type conversion",
            "derive",
            "dsrc",
            "target/test-output/dsrc2",
            "src/test/resources/samples/AES keys/DSRC keys/ERCA-MSCA/DSRCMK-2.bin",
            "51234125234143",
            "1",
            "2034",
            "-1"
        );
    }

    @Test
    public void deriveManufacturerCodeTooLarge() {
        checkWarning(
            "loss of data due to type conversion",
            "derive",
            "dsrc",
            "target/test-output/dsrc3",
            "src/test/resources/samples/AES keys/DSRC keys/ERCA-MSCA/DSRCMK-3.bin",
            "10",
            "1",
            "2051",
            "256"
        );
    }

    @Test
    public void deriveMsmkIncorrectAesKeySize() {
        checkWarning(
            "incorrect key size",
            "derive",
            "msmk",
            "target/test-output/msmk2",
            "src/test/resources/samples/ECC keys and certificates/ERCA/ERCA (1).cert",
            "src/test/resources/samples/ECC keys and certificates/ERCA/ERCA (1).cert"
        );
    }

    @Test
    public void encryptMonthLessThanOne() {
        checkWarning(
            "month should be a number in the range [1,12]",
            "encrypt",
            "ms",
            "target/test-output/ms1",
            "src/test/resources/samples/AES keys/Motion sensor keys and encrypted data/ERCA-MSCA/MSMK-1.bin",
            "0",
            "0",
            "2017",
            "-1"
        );
    }

    @Test
    public void encryptMonthGreaterThanTwelve() {
        checkWarning(
            "month should be a number in the range [1,12]",
            "encrypt",
            "ms",
            "target/test-output/ms1",
            "src/test/resources/samples/AES keys/Motion sensor keys and encrypted data/ERCA-MSCA/MSMK-1.bin",
            "1",
            "13",
            "2017",
            "-1"
        );
    }

    @Test
    public void encryptEquipmentSerialNumberTooLarge() {
        checkWarning(
            "loss of data due to type conversion",
            "encrypt",
            "ms",
            "target/test-output/ms1",
            "src/test/resources/samples/AES keys/Motion sensor keys and encrypted data/ERCA-MSCA/MSMK-1.bin",
            "51234125234143",
            "1",
            "2034",
            "-1"
        );
    }

    @Test
    public void encryptManufacturerCodeTooLarge() {
        checkWarning(
            "loss of data due to type conversion",
            "encrypt",
            "ms",
            "target/test-output/ms1",
            "src/test/resources/samples/AES keys/Motion sensor keys and encrypted data/ERCA-MSCA/MSMK-1.bin",
            "10",
            "1",
            "2051",
            "256"
        );
    }

    private void checkWarning(String warning, String... args) {
        ByteArrayOutputStream output = new ByteArrayOutputStream();
        try {
            new TachographKeyToolCli(new TachographKeyToolUser(new PrintStream(output))).processCommandLine(args);
        } finally {
            System.out.println(output.toString());
            assert(output.toString().contains(warning));
        }
    }
}
