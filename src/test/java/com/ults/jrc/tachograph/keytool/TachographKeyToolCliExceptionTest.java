package com.ults.jrc.tachograph.keytool;

import static com.ults.jrc.tachograph.keytool.TachographKeyToolCli.process;

import com.ults.jrc.tachograph.keytool.TachographKeyToolCli.CertificateTypeNotAllowed;
import com.ults.jrc.tachograph.keytool.TachographKeyToolCli.IncorrectDateTimeFormat;
import com.ults.jrc.tachograph.keytool.TachographKeyToolCli.IncorrectExtendedSerialNumberFormat;
import com.ults.jrc.tachograph.keytool.TachographKeyToolCli.IncorrectExtendedSerialNumberSize;
import com.ults.jrc.tachograph.keytool.TachographKeyToolCli.IncorrectNumberFormat;
import com.ults.jrc.tachograph.keytool.TachographKeyToolCli.InvalidNumberOfArguments;
import com.ults.jrc.tachograph.keytool.TachographKeyToolCli.UnkownSubcommand;
import com.ults.jrc.tachograph.keytool.TachographKeyToolCli.UnsupportedAesKeySize;
import com.ults.jrc.tachograph.keytool.TachographKeyToolCli.UnknownCertificateType;
import com.ults.jrc.tachograph.keytool.TachographKeyToolCli.UnsupportedCurveName;

import com.ults.jrc.tachograph.keytool.TachographKeyTool.CertificateDecodingFailed;
import com.ults.jrc.tachograph.keytool.TachographKeyTool.InvalidFileName;
import com.ults.jrc.tachograph.keytool.TachographKeyTool.UnableToReadFile;
import com.ults.jrc.tachograph.keytool.TachographKeyTool.UnableToCreateDirectory;

import com.ults.jrc.tachograph.keytool.TachographCryptography.AesKeySizeMismatch;
import com.ults.jrc.tachograph.keytool.TachographCryptography.InvalidSignature;
import com.ults.jrc.tachograph.keytool.TachographCryptography.UnableToRetrievePrivateKey;

import com.ults.jrc.tachograph.keytool.TachographDefinitions.NoHmacHashAlgorithmDefined;

import org.junit.Test;

public class TachographKeyToolCliExceptionTest {

    @Test(expected = InvalidNumberOfArguments.class)
    public void generateTooFewArguments() {
        process(
            "generate",
            "ec"
        );
    }

    @Test(expected = InvalidNumberOfArguments.class)
    public void generateTooManyArguments() {
        process(
            "generate",
            "ec",
            "target/test-output/x",
            "100",
            "superfluous"
        );
    }

    @Test(expected = UnkownSubcommand.class)
    public void generateUnknownSubcommand() {
        process(
            "generate",
            "unknownSubCommand",
            "target/test-output/erca1",
            "???"
        );
    }

    @Test(expected = UnsupportedAesKeySize.class)
    public void invalidAesKeySize() {
        process(
            "generate",
            "aes",
            "target/test-output/aesx",
            "100"
        );
    }

    @Test(expected = UnsupportedCurveName.class)
    public void unknownCurveName() {
        process(
            "generate",
            "ec",
            "target/test-output/erca1",
            "unknownCurveName"
        );
    }

    @Test(expected = UnsupportedCurveName.class)
    public void unsupportedCurve() {
        process(
            "generate",
            "ec",
            "target/test-output/ercae",
            "secp128r1"
        );
    }

    @Test(expected = InvalidFileName.class)
    public void invalidFileName() {
        process(
            "generate",
            "ec",
            "target/test-output/*\u0000",
            "brainpoolp384r1"
        );
    }

    @Test(expected = InvalidNumberOfArguments.class)
    public void createTooFewArguments() {
        process(
            "create",
            "ca",
            "erca",
            "target/test-output/erca1",
            "src/test/resources/samples/ECC keys and certificates/ERCA/ERCA (1).pkcs8",
            "0xFD",
            "EC",
            "1",
            "0xFFFF"
        );
    }

    @Test(expected = InvalidNumberOfArguments.class)
    public void createTooManyArguments() {
        process(
            "create",
            "ca",
            "unknownCertificateType",
            "target/test-output/erca1",
            "src/test/resources/samples/ECC keys and certificates/ERCA/ERCA (1).pkcs8",
            "0xFD",
            "EC",
            "1",
            "0xFFFF",
            "1",
            "2018-01-01T12:00:00",
            "2019-01-01T12:00:00",
            "superfluous"
        );
    }

    @Test(expected = UnkownSubcommand.class)
    public void createUnknownSubcommand() {
        process(
            "create",
            "unknownSubcommand",
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

    @Test(expected = UnknownCertificateType.class)
    public void unknownCertificateType() {
        process(
            "create",
            "ca",
            "unknownCertificateType",
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

    @Test(expected = CertificateTypeNotAllowed.class)
    public void createCaCertificateWithWrongCertificateType() {
        process(
            "create",
            "ca",
            "vu_ma",
            "target/test-output/vu_ma1",
            "src/test/resources/samples/ECC keys and certificates/ERCA/MSCA/ARC/Equipment/VU/ARC_VU_MA (1-1).pkcs8",
            "0xFD",
            "EC",
            "1",
            "0xFFFF",
            "1",
            "2018-01-01T12:00:00"
        );
    }

    @Test(expected = CertificateTypeNotAllowed.class)
    public void createEquipmentCertificateWithWrongCertificateType() {
        process(
            "create",
            "equipment",
            "erca",
            "target/test-output/erca1",
            "src/test/resources/samples/ECC keys and certificates/ERCA/ERCA (1).pkcs8",
            "0x00000001",
            "1",
            "2018",
            "0x01",
            "2018-01-01T12:00:00"
        );
    }

    @Test(expected = CertificateTypeNotAllowed.class)
    public void createRequestCertificateWithWrongCertificateType() {
        process(
            "create",
            "request",
            "driver_card_ma",
            "target/test-output/driver_card_ma1",
            "src/test/resources/samples/ECC keys and certificates/ERCA/MSCA/ARC/Equipment/TC/ARC_Driver_Card_MA (1-1).pkcs8",
            "1",
            "1",
            "2018",
            "1",
            "2018-01-01T12:00:00"
        );
    }

    @Test(expected = UnableToReadFile.class)
    public void nonExistentKeyFile() {
        process(
            "create",
            "ca",
            "erca",
            "target/test-output/erca1",
            "nonExistentKeyFile.pkcs8",
            "0xFD",
            "EC ",
            "1",
            "0xFFFF",
            "1",
            "2018-01-01T12:00:00"
        );
    }

    @Test(expected = InvalidFileName.class)
    public void invalidDirectoryName() {
        process(
            "create",
            "ca",
            "erca",
            "target/test-output/*\u0000/erca1",
            "src/test/resources/samples/ECC keys and certificates/ERCA/ERCA (1).pkcs8",
            "0xFD",
            "EC ",
            "1",
            "0xFFFF",
            "1",
            "2018-01-01T12:00:00"
        );
    }

    @Test(expected = UnableToCreateDirectory.class)
    public void unableToCreateDirectory() {
        process(
            "create",
            "ca",
            "erca",
            "target/test-output/x",
            "src/test/resources/samples/ECC keys and certificates/ERCA/ERCA (1).pkcs8",
            "0xFD",
            "EC ",
            "1",
            "0xFFFF",
            "1",
            "2018-01-01T12:00:00"
        );
        process(
            "create",
            "ca",
            "erca",
            "target/test-output/x.cert/erca1",
            "src/test/resources/samples/ECC keys and certificates/ERCA/ERCA (1).pkcs8",
            "0xFD",
            "EC ",
            "1",
            "0xFFFF",
            "1",
            "2018-01-01T12:00:00"
        );
    }

    @Test(expected = UnableToRetrievePrivateKey.class)
    public void invalidKeyFileType() {
        process(
            "create",
            "ca",
            "erca",
            "target/test-output/erca1",
            "src/test/resources/samples/ECC keys and certificates/ERCA/ERCA (1).cert",
            "0xFD",
            "EC ",
            "1",
            "0xFFFF",
            "1",
            "2018-01-01T12:00:00"
        );
    }

    @Test(expected = IncorrectNumberFormat.class)
    public void nonNumericNationNumeric() {
        process(
            "create",
            "ca",
            "msca_vu_egf",
            "target/test-output/msca_vu_egf1",
            "src/test/resources/samples/ECC keys and certificates/ERCA/MSCA/ARC/ARC_MSCA_VU-EGF (1-1).pkcs8",
            "nonNumericNationNumeric",
            "ARC",
            "1",
            "0xFFFF",
            "1",
            "2018-01-01T12:00:00"
        );
    }

    @Test(expected = IncorrectNumberFormat.class)
    public void nonNumericKeySerialNumber() {
        process(
            "create",
            "ca",
            "msca_card",
            "target/test-output/msca_card1",
            "src/test/resources/samples/ECC keys and certificates/ERCA/MSCA/ARC/ARC_MSCA_Card (1-1).pkcs8",
            "0xFC",
            "ARC",
            "nonNumericKeySerialNumber",
            "0xFFFF",
            "1",
            "2018-01-01T12:00:00"
        );
    }

    @Test(expected = IncorrectNumberFormat.class)
    public void nonNumericAdditionalInfo() {
        process(
            "create",
            "ca",
            "erca",
            "target/test-output/erca1",
            "src/test/resources/samples/ECC keys and certificates/ERCA/ERCA (1).pkcs8",
            "0xFD",
            "EC",
            "1",
            "nonNumericAdditionalInfo",
            "1",
            "2018-01-01T12:00:00"
        );
    }

    @Test(expected = IncorrectNumberFormat.class)
    public void nonNumericCaIdentifier() {
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
            "nonNumericCaIdentifier",
            "2018-01-01T12:00:00"
        );
    }

    @Test(expected = IncorrectDateTimeFormat.class)
    public void invalidDateTimeFormat() {
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
            "invalidDateTimeFormat"
        );
    }

    @Test(expected = IncorrectNumberFormat.class)
    public void nonNumericEquipmentSerialNumber() {
        process(
            "create",
            "equipment",
            "driver_card_ma",
            "target/test-output/driver_card_ma1",
            "src/test/resources/samples/ECC keys and certificates/ERCA/MSCA/ARC/Equipment/TC/ARC_Driver_Card_MA (1-1).pkcs8",
            "nonNumericEquipmentSerialNumber",
            "1",
            "2018",
            "0x01",
            "2018-01-01T12:00:00"
        );
    }

    @Test(expected = IncorrectNumberFormat.class)
    public void nonNumericManufacturerCode() {
        process(
            "create",
            "equipment",
            "driver_card_sign",
            "target/test-output/driver_card_sign1234",
            "src/test/resources/samples/ECC keys and certificates/ERCA/MSCA/ARC/Equipment/TC/ARC_Driver_Card_Sign (1-1).pkcs8",
            "1234",
            "1",
            "2018",
            "nonNumericManufacturerCode",
            "2018-01-01T12:00:00"
        );
    }

    @Test(expected = InvalidNumberOfArguments.class)
    public void signTooFewArguments() {
        process(
            "sign",
            "src/test/resources/samples/ECC keys and certificates/ERCA/ERCA (1).pkcs8",
            "src/test/resources/samples/ECC keys and certificates/ERCA/ERCA (1).pkcs8",
            "src/test/resources/samples/ECC keys and certificates/ERCA/ERCA (1).cert"
        );
    }

    @Test(expected = InvalidNumberOfArguments.class)
    public void signTooManyArguments() {
        process(
            "sign",
            "src/test/resources/samples/ECC keys and certificates/ERCA/ERCA (1).pkcs8",
            "src/test/resources/samples/ECC keys and certificates/ERCA/ERCA (1).pkcs8",
            "src/test/resources/samples/ECC keys and certificates/ERCA/ERCA (1).cert",
            "target/test-output/signed",
            "superfluous"
        );
    }

    @Test(expected = TachographKeyToolException.class)
    public void signInvalidCertificateFile() {
        process(
            "sign",
            "src/test/resources/samples/ECC keys and certificates/ERCA/ERCA (1).pkcs8",
            "src/test/resources/samples/ECC keys and certificates/ERCA/ERCA (1).pkcs8",
            "src/test/resources/samples/ECC keys and certificates/ERCA/ERCA (1).cert",
            "target/test-output/signed"
        );
    }

    @Test(expected = TachographKeyToolException.class)
    public void signCertificateFileEmpty() {
        process(
            "sign",
            "src/test/resources/testfiles/empty",
            "src/test/resources/samples/ECC keys and certificates/ERCA/ERCA (1).pkcs8",
            "src/test/resources/samples/ECC keys and certificates/ERCA/ERCA (1).cert",
            "target/test-output/signed"
        );
    }

    @Test(expected = CertificateDecodingFailed.class)
    public void signCertificateFileNotDerEncoded() {
        process(
            "sign",
            "src/test/resources/testfiles/invalid_der",
            "src/test/resources/samples/ECC keys and certificates/ERCA/ERCA (1).pkcs8",
            "src/test/resources/samples/ECC keys and certificates/ERCA/ERCA (1).cert",
            "target/test-output/signed"
        );
    }

    @Test(expected = TachographKeyToolException.class)
    public void signCertificateFileWithWrongTag() {
        process(
            "sign",
            "src/test/resources/testfiles/wrong_certificate_tag.cert",
            "src/test/resources/samples/ECC keys and certificates/ERCA/ERCA (1).pkcs8",
            "src/test/resources/samples/ECC keys and certificates/ERCA/ERCA (1).cert",
            "target/test-output/signed"
        );
    }

    @Test(expected = UnableToRetrievePrivateKey.class)
    public void signInvalidKeyFileType() {
        process(
            "sign",
            "src/test/resources/samples/ECC keys and certificates/ERCA/ERCA (1).cert",
            "src/test/resources/samples/ECC keys and certificates/ERCA/ERCA (1).cert",
            "src/test/resources/samples/ECC keys and certificates/ERCA/ERCA (1).cert",
            "target/test-output/signed"
        );
    }

    @Test(expected = UnableToRetrievePrivateKey.class)
    public void signWithRsaKey() {
        process(
            "sign",
            "src/test/resources/samples/ECC keys and certificates/ERCA/ERCA (1).cert",
            "src/test/resources/testfiles/rsa_key.pkcs8",
            "src/test/resources/samples/ECC keys and certificates/ERCA/ERCA (1).cert",
            "target/test-output/signed"
        );
    }

    @Test(expected = UnableToRetrievePrivateKey.class)
    public void signKeyFileEmpty() {
        process(
            "sign",
            "src/test/resources/samples/ECC keys and certificates/ERCA/ERCA (1).cert",
            "src/test/resources/testfiles/empty",
            "src/test/resources/samples/ECC keys and certificates/ERCA/ERCA (1).cert",
            "target/test-output/signed"
        );
    }

    @Test(expected = UnableToRetrievePrivateKey.class)
    public void signKeyFileNotDerEncoded() {
        process(
            "sign",
            "src/test/resources/samples/ECC keys and certificates/ERCA/ERCA (1).cert",
            "src/test/resources/testfiles/invalid_der",
            "src/test/resources/samples/ECC keys and certificates/ERCA/ERCA (1).cert",
            "target/test-output/signed"
        );
    }

    @Test(expected = InvalidNumberOfArguments.class)
    public void verifyTooFewArguments() {
        process(
            "verify",
            "src/test/resources/samples/ECC keys and certificates/ERCA/ERCA (1).pkcs8"
        );
    }

    @Test(expected = InvalidNumberOfArguments.class)
    public void verifyTooManyArguments() {
        process(
            "verify",
            "src/test/resources/samples/ECC keys and certificates/ERCA/ERCA (1).pkcs8",
            "src/test/resources/samples/ECC keys and certificates/ERCA/ERCA (1).cert",
            "superfluous"
        );
    }

    @Test(expected = TachographKeyToolException.class)
    public void verifyInvalidCertificateFile() {
        process(
            "verify",
            "src/test/resources/samples/ECC keys and certificates/ERCA/ERCA (1).pkcs8",
            "src/test/resources/samples/ECC keys and certificates/ERCA/ERCA (1).cert"
        );
    }

    @Test(expected = InvalidSignature.class)
    public void verifyWithInvalidSignature() {
        process(
            "verify",
            "src/test/resources/samples/ECC keys and certificates/ERCA/MSCA/ARC/ARC_MSCA_Card (1-1).cert",
            "src/test/resources/samples/ECC keys and certificates/ERCA/ERCA (2).cert"
         );
    }

    @Test(expected = InvalidSignature.class)
    public void verifyWithInvalidSignature2() {
        process(
            "verify",
            "src/test/resources/samples/ECC keys and certificates/ERCA/MSCA/ARC/ARC_MSCA_Card (1-1).cert",
            "src/test/resources/samples/ECC keys and certificates/ERCA/ERCA (2).cert"
         );
    }

    @Test(expected = UnkownSubcommand.class)
    public void deriveUnknownSubcommand() {
        process(
            "derive",
            "unknownSubcommand",
            "target/test-output/vu1",
            "src/test/resources/samples/AES keys/DSRC keys/ERCA-MSCA/DSRCMK-1.bin",
            "1",
            "1",
            "2017",
            "-1"
        );
    }

    @Test(expected = InvalidNumberOfArguments.class)
    public void deriveTooFewArguments() {
        process(
            "derive",
            "dsrc",
            "target/test-output/dsrc1",
            "src/test/resources/samples/AES keys/DSRC keys/ERCA-MSCA/DSRCMK-1.bin",
            "1",
            "1",
            "2017"
        );
    }

    @Test(expected = InvalidNumberOfArguments.class)
    public void deriveTooManyArguments() {
        process(
            "derive",
            "dsrc",
            "target/test-output/dsrc1",
            "src/test/resources/samples/AES keys/DSRC keys/ERCA-MSCA/DSRCMK-1.bin",
            "1",
            "1",
            "2017",
            "-1",
            "superfluous"
        );
    }

    @Test(expected = UnableToReadFile.class)
    public void deriveNonExistentMsmk() {
        process(
            "derive",
            "dsrc",
            "target/test-output/dsrc1",
            "nonexistentfile",
            "1",
            "1",
            "2017",
            "-1"
        );
    }

    @Test(expected = NoHmacHashAlgorithmDefined.class)
    public void deriveIncorrectAesKeySize() {
        process(
            "derive",
            "dsrc",
            "target/test-output/dsrc3",
            "src/test/resources/samples/ECC keys and certificates/ERCA/ERCA (1).cert",
            "10",
            "1",
            "2051",
            "256"
        );
    }

    @Test(expected = InvalidNumberOfArguments.class)
    public void deriveMsmkTooFewArguments() {
        process(
            "derive",
            "msmk",
            "target/test-output/msmk1",
            "src/test/resources/samples/AES keys/Motion sensor keys and encrypted data/ERCA-MSCA/MSMK-1-VU.bin"
        );
    }

    @Test(expected = InvalidNumberOfArguments.class)
    public void deriveMsmkTooManyArguments() {
        process(
            "derive",
            "msmk",
            "target/test-output/msmk2",
            "src/test/resources/samples/AES keys/Motion sensor keys and encrypted data/ERCA-MSCA/MSMK-2-VU.bin",
            "src/test/resources/samples/AES keys/Motion sensor keys and encrypted data/ERCA-MSCA/MSMK-2-WS.bin",
            "superfluous"
        );
    }

    @Test(expected = InvalidNumberOfArguments.class)
    public void deriveMsikTooFewArguments() {
        process(
            "derive",
            "msik",
            "target/test-output/msik1"
        );
    }

    @Test(expected = InvalidNumberOfArguments.class)
    public void deriveMsikTooManyArguments() {
        process(
            "derive",
            "msik",
            "target/test-output/msik2",
            "src/test/resources/samples/AES keys/Motion sensor keys and encrypted data/ERCA-MSCA/MSMK-2.bin",
            "superfluous"
        );
    }

    @Test(expected = UnkownSubcommand.class)
    public void encryptUnknownSubcommand() {
        process(
            "encrypt",
            "unknownSubcommand",
            "target/test-output/ms1",
            "src/test/resources/samples/AES keys/Motion sensor keys and encrypted data/ERCA-MSCA/MSMK-1.bin",
            "0",
            "1",
            "2017",
            "-1"
        );
    }

    @Test(expected = InvalidNumberOfArguments.class)
    public void encryptMsTooFewArguments() {
        process(
            "encrypt",
            "ms",
            "target/test-output/ms1",
            "src/test/resources/samples/AES keys/Motion sensor keys and encrypted data/ERCA-MSCA/MSMK-1.bin",
            "0",
            "1",
            "2017"
        );
    }

    @Test(expected = InvalidNumberOfArguments.class)
    public void encryptMsTooManyArguments() {
        process(
            "encrypt",
            "ms",
            "target/test-output/ms1",
            "src/test/resources/samples/AES keys/Motion sensor keys and encrypted data/ERCA-MSCA/MSMK-1.bin",
            "0",
            "1",
            "2017",
            "-1",
            "superfluous"
        );
    }

    @Test(expected = UnableToReadFile.class)
    public void encryptMsNonExistentMsmk() {
        process(
            "encrypt",
            "ms",
            "target/test-output/ms1",
            "nonexistentfile",
            "0",
            "1",
            "2017",
            "-1"
        );
    }

    @Test(expected = IncorrectExtendedSerialNumberSize.class)
    public void encryptMsIncorrectSize() {
        process(
            "encrypt",
            "ms",
            "target/test-output/ms1",
            "src/test/resources/samples/AES keys/Motion sensor keys and encrypted data/ERCA-MSCA/MSMK-1.bin",
            "0"
        );
    }

    @Test(expected = IncorrectNumberFormat.class)
    public void encryptMsNonHexadecimal() {
        process(
            "encrypt",
            "ms",
            "target/test-output/ms1",
            "src/test/resources/samples/AES keys/Motion sensor keys and encrypted data/ERCA-MSCA/MSMK-1.bin",
            "000000000000000g"
        );
    }

    @Test(expected = IncorrectExtendedSerialNumberFormat.class) // toco define proper exception
    public void encryptMsInvalidBcd() {
        process(
            "encrypt",
            "ms",
            "target/test-output/ms1",
            "src/test/resources/samples/AES keys/Motion sensor keys and encrypted data/ERCA-MSCA/MSMK-1.bin",
            "ffffffffffffffff"
        );
    }

    @Test(expected = InvalidNumberOfArguments.class)
    public void encryptPkTooFewArguments() {
        process(
            "encrypt",
            "pk",
            "target/test-output/pk1",
            "src/test/resources/samples/AES keys/Motion sensor keys and encrypted data/ERCA-MSCA/MSMK-1.bin"
        );
    }

    @Test(expected = InvalidNumberOfArguments.class)
    public void encryptPkTooManyArguments() {
        process(
            "encrypt",
            "pk",
            "target/test-output/pk1",
            "src/test/resources/samples/AES keys/Motion sensor keys and encrypted data/ERCA-MSCA/MSMK-1.bin",
            "src/test/resources/samples/AES keys/Motion sensor keys and encrypted data/ERCA-MSCA/Equipment/MS-2-PK-2.bin",
            "superfluous"
        );
    }

    @Test(expected = UnableToReadFile.class)
    public void encryptPkNonExistentMsmk() {
        process(
            "encrypt",
            "pk",
            "target/test-output/pk1",
            "nonexistentfile",
            "src/test/resources/samples/AES keys/Motion sensor keys and encrypted data/ERCA-MSCA/Equipment/MS-2-PK-2.bin"
        );
    }

    @Test(expected = UnableToReadFile.class)
    public void encryptPkNonExistentPk() {
        process(
            "encrypt",
            "pk",
            "target/test-output/pk1",
            "src/test/resources/samples/AES keys/Motion sensor keys and encrypted data/ERCA-MSCA/MSMK-1.bin",
            "nonexistentfile"
        );
    }

    @Test(expected = AesKeySizeMismatch.class)
    public void encryptPairingKeyInvalidKeySize() {
        process(
            "encrypt",
            "pk",
            "target/test-output/pk1",
            "src/test/resources/samples/AES keys/Motion sensor keys and encrypted data/ERCA-MSCA/MSMK-1.bin",
            "src/test/resources/samples/AES keys/Motion sensor keys and encrypted data/ERCA-MSCA/Equipment/MS-2-PK-2.bin"
        );
    }
}
