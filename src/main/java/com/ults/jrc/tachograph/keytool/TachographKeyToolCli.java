package com.ults.jrc.tachograph.keytool;

import static com.ults.jrc.tachograph.keytool.TachographDefinitions.*;

import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.time.format.DateTimeParseException;
import java.util.List;

/**
 * Command line interface for Generation-2 Smart Tachograph Key Tool.
 *
 * @author Klaas Mateboer
 */
public class TachographKeyToolCli {

    private static final String COPYRIGHTS
            = "Generation-2 Smart Tachograph Key Tool - Copyright 2017 Joint Research Centre\r\n";

    private static final String USAGE_GENERATE
            = "generate aes <name> <size>\r\n"
            + "       To generate an AES secret key, and store it in a binary file.\r\n"
            + "generate ec <name> <curve>\r\n"
            + "       To generate an EC key pair, and store the private key in a PKCS#8 file.\r\n"
            + "  name - the name of the file to be created\r\n"
            + "  size - the size in bits of the secret key to be generated (128, 192, or 256)\r\n"
            + "  curve - the standard name of the elliptic curve parameters to be used:\r\n"
            + listOptions(CURVE_NAMES);

    private static final String USAGE_CREATE
            = "create ca <catype> <name> <keyname> <nationnumeric> <nationalpha> <serialnumber> <additionalinfo> <caidentifier> [<effectivedate> [<expirationdate>]]\r\n"
            + "       To create a self-signed certificate with a certification authority KID.\r\n"
            + "create equipment <equipmenttype> <name> <keyname> <serialnumber> <month> <year> <manufacturercode> [<effectivedate> [<expirationdate>]]\r\n"
            + "       To create a self-signed certificate with an equipment extended serial number.\r\n"
            + "create request <requesttype> <name> <keyname> <serialnumber> <month> <year> <manufacturercode> [<effectivedate> [<expirationdate>]]\r\n"
            + "       To create a self-signed certificate with a certificate request ID.\r\n"
            + "  catype - one of the following options:\r\n"
            + listOptions(TachographCertificateType.CA_TYPES)
            + "  equipmenttype - one of the following options:\r\n"
            + listOptions(TachographCertificateType.EQUIPMENT_TYPES)
            + "  requesttype - one of the following options:\r\n"
            + listOptions(TachographCertificateType.REQUEST_TYPES)
            + "  name - the name of the certificate file to be created\r\n"
            + "  keyname - the name of the PKCS#8 file containing the key to be certified\r\n"
            + "  nationnumeric - a numerical identifier of the nation\r\n"
            + "  nationalpha - a country code of up to three characters\r\n"
            + "  serialnumber - the key or equipment serial number\r\n"
            + "  month - the month to be encoded in the extended serial number or request ID\r\n"
            + "  year - the year to be encoded in the extended serial number or request ID\r\n"
            + "  additionalinfo - the additional info field\r\n"
            + "  caidentifier - the CA identifier\r\n"
            + "  manufacturercode - the manufacturer code\r\n"
            + "  effectivedate - the certificate effective date and time in ISO 8601 format (e.g. 2018-01-01T12:00:00)\r\n"
            + "  expirationdate - the certificate expiration date and time in ISO 8601 format (e.g. 2018-01-01T12:00:00)\r\n";

    private static final String USAGE_LINK
            = "link <key> <currentcertificate> <nextcertificate> <name>\r\n"
            + "       To create and sign an ERCA link certificate.\r\n"
            + "  key - the name of the file containing the current ERCA private key\r\n"
            + "  currentcertificate - the name of the file containing the current ERCA certificate\r\n"
            + "  nextcertificate - the name of the file containing the next ERCA certificate\r\n"
            + "  name - the file name of the link certificate to be created.\r\n";

    private static final String USAGE_SIGN
            = "sign <selfsignedcertificate> <caprivatekey> <cacertificate> <name>\r\n"
            + "       To sign a previously generated certificate.\r\n"
            + "  selfsignedcertificate - the name of the file containing the self-signed certificate to be signed\r\n"
            + "  caprivatekey - the name of the file containing the CA private key\r\n"
            + "  cacertificate - the name of the file containing the CA certificate\r\n"
            + "  name - the name of the certificate file to be created.\r\n";

    private static final String USAGE_VERIFY
            = "verify <certificate> <cacertificate>\r\n"
            + "       To verify a previously generated certificate.\r\n"
            + "  certificate - the name of the file containing the certificate to be verified\r\n"
            + "  cacertificate - the name of the file containing the CA certificate.\r\n";

    private static final String USAGE_DERIVE
            = "derive dsrc <name> <dsrcmk> <serialnumber> <month> <year> <manufacturercode>\r\n"
            + "derive dsrc <name> <dsrcmk> <extendedserialnumber>\r\n"
            + "       To derive vehicle unit specific DSRC encryption and authentication keys.\r\n"
            + "       The encryption key will be stored in a file named <name>-enc.bin\r\n"
            + "       The authentication key will be stored in a file named <name>-mac.bin\r\n"
            + "derive msmk <name> <msmkvu> <msmkwc>\r\n"
            + "       To derive the Motion Sensor Master Key from the vehicle unit and workshop card parts.\r\n"
            + "       The MSMK key will be stored in a file named <name>.bin\r\n"
            + "derive msik <name> <msmk>\r\n"
            + "       To derive the Identification Key from a Motion Sensor Master Key.\r\n"
            + "       The MSIK key will be stored in a file named <name>.bin\r\n"
            + "  name - the base name for the output files\r\n"
            + "  dsrcmk - the name of the file containing the DSRC master key\r\n"
            + "  msmkvu - the name of the file containing the VU part of the MSMK\r\n"
            + "  msmkwc - the name of the file containing the WC part of the MSMK\r\n"
            + "  msmk - the name of the file containing the MSMK\r\n"
            + "  serialnumber - the serial number of the vehicle unit\r\n"
            + "  month - the month\r\n"
            + "  year - the year\r\n"
            + "  manufacturercode - the manufacturer code\r\n"
            + "  extendedserialnumber - the extended serial number of the vehicle unit (16 hexadecimal digits)\r\n";

    private static final String USAGE_ENCRYPT
            = "encrypt ms <name> <msmk> <serialnumber> <month> <year> <manufacturercode>\r\n"
            + "encrypt ms <name> <msmk> <extendedserialnumber>\r\n"
            + "       To encrypt a motion sensor extended serial number with an identification key.\r\n"
            + "       The identification key wil be derived from the  motion sensor master key.\r\n"
            + "       The result will be stored in a file named <name>-esn-enc.bin\r\n"
            + "encrypt pk <name> <msmk> <pk>\r\n"
            + "       To encrypt a pairing key.\r\n"
            + "       The encrypted pairing key will be stored in a file named <name>-pk-enc.bin\r\n"
            + "  name - the base name for the output file\r\n"
            + "  msmk - the name of the file containing the motion sensor master key\r\n"
            + "  serialnumber - the serial number of the motion sensor\r\n"
            + "  month - the month\r\n"
            + "  year - the year\r\n"
            + "  manufacturercode - the manufacturer code\r\n"
            + "  extendedserialnumber - the extended serial number of the motion sensor (16 hexadecimal digits)\r\n"
            + "  pk - the name of the file containing the pairing key\r\n";

    private final TachographKeyTool keyTool;
    private final TachographKeyToolUser user;

    public static void main(String[] args) {
        try {
            process(args);
        } catch (TachographKeyToolException ex) {
            System.out.println("Error: " + ex.getMessage());
        }
    }

    public static void process(String... args) {
        new TachographKeyToolCli(new TachographKeyToolUser(System.out)).processCommandLine(args);
    }

    TachographKeyToolCli(TachographKeyToolUser user) {
        this.user = user;
        user.inform(COPYRIGHTS);
        keyTool = new TachographKeyTool(user);
    }

    void processCommandLine(String... args) {
        echo(args);
        if (args.length < 1)
            showUsage();
        else if ("generate".startsWith(args[0]))
            processGenerateCommand(args);
        else if ("create".startsWith(args[0]))
            processCreateCommand(args);
        else if ("link".startsWith(args[0]))
            processLinkCommand(args);
        else if ("sign".startsWith(args[0]))
            processSignCommand(args);
        else if ("verify".startsWith(args[0]))
            processVerifyCommand(args);
        else if ("derive".startsWith(args[0]))
            processDeriveCommand(args);
        else if ("encrypt".startsWith(args[0]))
            processEncryptCommand(args);
        else
            showUsage(args[0]);
    }

    private void echo(String[] args) {
        user.inform(getCommandLine(args));
    }

    private String getCommandLine(String[] args) {
        String commandLine = "";
        for (String arg : args)
            commandLine += ((arg.isEmpty() ? "\"\"" : arg) + " ");
        return commandLine;
    }

    private void showUsage() {
        user.inform("Usage:");
        user.inform(USAGE_GENERATE);
        user.inform(USAGE_CREATE);
        user.inform(USAGE_LINK);
        user.inform(USAGE_SIGN);
        user.inform(USAGE_VERIFY);
        user.inform(USAGE_DERIVE);
        user.inform(USAGE_ENCRYPT);
    }

    private void showUsage(String arg) {
        user.inform("Unknown command \"" + arg + "\".");
        showUsage();
    }

    private void processGenerateCommand(String... args) {
        if (args.length < 2)
            user.inform(USAGE_GENERATE);
        else if ("aes".startsWith(args[1]))
            processGenerateSecret(args);
        else if ("ec".startsWith(args[1]))
            processGenerateKeyPair(args);
        else
            throw new UnkownSubcommand(args[1]);
    }

    private void processGenerateSecret(String... args) {
        if (args.length == 4)
            keyTool.generateSecretKey(args[2], getAesKeySize(getInt(args[3])));
        else
            throw new InvalidNumberOfArguments();
    }

    private void processGenerateKeyPair(String... args) {
        if (args.length == 4)
            keyTool.generateKeyPair(args[2], getCurve(args[3]));
        else
            throw new InvalidNumberOfArguments();
    }

    private void processCreateCommand(String... args) {
        if (args.length < 2)
            user.inform(USAGE_CREATE);
        else if ("ca".startsWith(args[1]))
            processCreateCommandCa(args);
        else if ("equipment".startsWith(args[1]))
            processCreateCommandEquipment(args);
        else if ("request".startsWith(args[1]))
            processCreateCommandRequest(args);
        else
            throw new UnkownSubcommand(args[1]);
    }

    private void processCreateCommandCa(String... args) {
        if (args.length >= 10 && args.length <= 12) {
            TachographCertificateType type = getType(args[2]);
            checkType(type, TachographCertificateType.CA_TYPES);
            keyTool.create(type, args[3], args[4], getAuthority(args, 5), getValidityPeriod(args, 10, type));
        } else
            throw new InvalidNumberOfArguments();
    }

    private void processCreateCommandEquipment(String... args) {
        if (args.length >= 9 && args.length <= 11) {
            TachographCertificateType type = getType(args[2]);
            checkType(type, TachographCertificateType.EQUIPMENT_TYPES);
            keyTool.create(type, args[3], args[4], getExtendedSerialNumber(args, 5, type.equipmentType), getValidityPeriod(args, 9, type));
        } else
            throw new InvalidNumberOfArguments();
    }

    private void processCreateCommandRequest(String... args) {
        if (args.length >= 9 && args.length <= 11) {
            TachographCertificateType type = getType(args[2]);
            checkType(type, TachographCertificateType.REQUEST_TYPES);
            keyTool.create(type, args[3], args[4], getRequestID(args, 5), getValidityPeriod(args, 9, type));
        } else
            throw new InvalidNumberOfArguments();
    }

    private void processLinkCommand(String... args) {
        if (args.length < 2)
            user.inform(USAGE_LINK);
        else if (args.length == 5)
            keyTool.link(args[1], args[2], args[3], args[4]);
        else
            throw new InvalidNumberOfArguments();
    }

    private void processSignCommand(String... args) {
        if (args.length < 2)
            user.inform(USAGE_SIGN);
        else if (args.length == 5)
            keyTool.sign(args[1], args[2], args[3], args[4]);
        else
            throw new InvalidNumberOfArguments();
    }

    private void processVerifyCommand(String... args) {
        if (args.length < 2)
            user.inform(USAGE_VERIFY);
        else if (args.length == 3)
            keyTool.verify(args[1], args[2]);
        else
            throw new InvalidNumberOfArguments();
    }

    private void processDeriveCommand(String... args) {
        if (args.length < 2)
            user.inform(USAGE_DERIVE);
        else if ("dsrc".startsWith(args[1]))
            processDeriveVuDsrcKeys(args);
        else if ("msmk".startsWith(args[1]))
            processDeriveMsmk(args);
        else if ("msik".startsWith(args[1]))
            processDeriveMsik(args);
        else
            throw new UnkownSubcommand(args[1]);
    }

    private void processDeriveVuDsrcKeys(String... args) {
        if (args.length == 8)
            keyTool.deriveVuDsrcKeys(args[3], getExtendedSerialNumber(args, 4, EQUIPMENT_TYPE_VU), args[2]);
        else if (args.length == 5)
            keyTool.deriveVuDsrcKeys(args[3], getExtendedSerialNumber(args[4]), args[2]);
        else
            throw new InvalidNumberOfArguments();
    }

    private void processDeriveMsmk(String... args) {
        if (args.length == 5)
            keyTool.deriveMsmk(args[3], args[4], args[2]);
        else
            throw new InvalidNumberOfArguments();
    }

    private void processDeriveMsik(String... args) {
        if (args.length == 4)
            keyTool.deriveMsik(args[3], args[2]);
        else
            throw new InvalidNumberOfArguments();
    }

    private void processEncryptCommand(String... args) {
        if (args.length < 2)
            user.inform(USAGE_ENCRYPT);
        else if ("ms".startsWith(args[1]))
            processEncryptMsExtendedSerialNumber(args);
        else if ("pk".startsWith(args[1]))
            processEncryptPairingKey(args);
        else
            throw new UnkownSubcommand(args[1]);
    }

    private void processEncryptMsExtendedSerialNumber(String... args) {
        if (args.length == 8)
            keyTool.encryptMsExtendedSerialNumber(args[3], getExtendedSerialNumber(args, 4, EQUIPMENT_TYPE_MS), args[2]);
        else if (args.length == 5)
            keyTool.encryptMsExtendedSerialNumber(args[3], getExtendedSerialNumber(args[4]), args[2]);
        else
            throw new InvalidNumberOfArguments();
    }

    private void processEncryptPairingKey(String... args) {
        if (args.length == 5)
            keyTool.encryptPairingKey(args[3], args[4], args[2]);
        else
            throw new InvalidNumberOfArguments();
    }

    private int getAesKeySize(int size) {
        for (int s : AES_KEY_SIZES)
            if (s == size)
                return size / 8;
        throw new UnsupportedAesKeySize(size);
    }

    private String getCurve(String name) {
        for (String s : CURVE_NAMES)
            if (s.equals(name))
                return s;
        throw new UnsupportedCurveName(name);
    }

    private TachographCertificateType getType(String type) {
        for (TachographCertificateType t : TachographCertificateType.values())
            if (t.getName().startsWith(type))
                return t;
        throw new UnknownCertificateType(type);
    }

    private void checkType(TachographCertificateType type, List<TachographCertificateType> allowed) {
        if (!allowed.contains(type))
            throw new CertificateTypeNotAllowed(type);
    }

    private TachographCertificateValidity getValidityPeriod(String[] args, int offset, TachographCertificateType type) {
        LocalDateTime effectiveDate = getOptionalDateTime(args, offset++);
        if (args.length > offset)
            return TachographCertificateValidity.getInstance(effectiveDate, getDateTime(args[offset]));
        else
            return TachographCertificateValidity.getInstance(effectiveDate, type);
    }

    private LocalDateTime getOptionalDateTime(String[] args, int offset) {
        if (args.length > offset)
            return getDateTime(args[offset]);
        else
            return LocalDateTime.now();
    }

    private LocalDateTime getDateTime(String arg) {
        try {
            return LocalDateTime.parse(arg, DateTimeFormatter.ISO_LOCAL_DATE_TIME);
        } catch (DateTimeParseException ex) {
            throw new IncorrectDateTimeFormat(arg, ex);
        }
    }

    private TachographCertificationAuthorityKID getAuthority(String[] args, int offset) {
        return new TachographCertificationAuthorityKID(
                getNationNumeric(args[offset++]),
                getNationAlpha(args[offset++]),
                getKeySerialNumber(args[offset++]),
                getAdditionalInfo(args[offset++]),
                getCaIdentifier(args[offset++]));
    }

    private TachographExtendedSerialNumber getExtendedSerialNumber(String[] args, int offset, byte type) {
        try {
            return new TachographExtendedSerialNumber(
                    getSerialNumber(args[offset++]),
                    getMonth(args[offset++]),
                    getYear(args[offset++]),
                    type,
                    getManufacturerCode(args[offset++]));
        } catch (IllegalArgumentException ex) {
            throw new IncorrectExtendedSerialNumberFormat(args[offset], ex);
        }
    }

    private TachographExtendedSerialNumber getExtendedSerialNumber(String arg) {
        if (arg.length() != 16)
            throw new IncorrectExtendedSerialNumberSize(arg);
        try {
            return new TachographExtendedSerialNumber(getBytes(arg));
        } catch (IllegalArgumentException ex) {
            throw new IncorrectExtendedSerialNumberFormat(arg, ex);
        }
    }

    private TachographCertificateRequestID getRequestID(String[] args, int offset) {
        return new TachographCertificateRequestID(
                getSerialNumber(args[offset++]),
                getMonth(args[offset++]),
                getYear(args[offset++]),
                getManufacturerCode(args[offset++]));
    }

    byte getNationNumeric(String arg) {
        return getByte(arg);
    }

    String getNationAlpha(String arg) {
        return (arg + "   ").substring(0, 3);
    }

    int getSerialNumber(String arg) {
        return getInt(arg);
    }

    byte getKeySerialNumber(String arg) {
        return getByte(arg);
    }

    short getAdditionalInfo(String arg) {
        return getShort(arg);
    }

    byte getCaIdentifier(String arg) {
        return getByte(arg);
    }

    byte getMonth(String arg) {
        byte month = getByte(arg);
        if (month > 12 || month < 1)
            warn("month should be a number in the range [1,12]: " + arg);
        return month;
    }

    int getYear(String arg) {
        return getInt(arg);
    }

    byte getManufacturerCode(String arg) {
        return getByte(arg);
    }

    private byte[] getBytes(String arg) {
        byte[] result = new byte[arg.length() / 2];
        for (int i = 7; i >= 0; i--) {
            result[i] = getByte("0x" + arg.substring(arg.length() - 2));
            arg = arg.substring(0, arg.length() - 2);
        }
        return result;
    }

    byte getByte(String arg) {
        long value = getLong(arg);
        if (value > 255 || value < -256)
            warn("loss of data due to type conversion: " + arg);
        return (byte) value;
    }

    short getShort(String arg) {
        long value = getLong(arg);
        if (value > 65535 || value < -65536)
            warn("loss of data due to type conversion: " + arg);
        return (short) value;
    }

    int getInt(String arg) {
        long value = getLong(arg);
        if (value > 4294967295L || value < -4294967296L)
            warn("loss of data due to type conversion: " + arg);
        return (int) value;
    }

    long getLong(String arg) {
        try {
            return Long.decode(arg);
        } catch (NumberFormatException ex) {
            throw new IncorrectNumberFormat(arg, ex);
        }
    }

    private static String listOptions(List options) {
        String result = "";
        for (Object s : options)
            result += "\t" + s + "\r\n";
        return result;
    }

    private void warn(String message) {
        user.warn(message);
    }

    class UnkownSubcommand extends TachographKeyToolException {
        UnkownSubcommand(String s) {
            super("Unknown subcommand: " + s);
        }
    }

    class InvalidNumberOfArguments extends TachographKeyToolException {
        InvalidNumberOfArguments() {
            super("Invalid number of arguments");
        }
    }

    class UnsupportedAesKeySize extends TachographKeyToolException {
        UnsupportedAesKeySize(int size) {
            super("Unsupported AES key size: " + size);
        }
    }

    class UnsupportedCurveName extends TachographKeyToolException {
        UnsupportedCurveName(String name) {
            super("Unsupported curve name: " + name);
        }
    }

    class UnknownCertificateType extends TachographKeyToolException {
        UnknownCertificateType(String type) {
            super("Unknown certificate type: " + type);
        }
    }

    class CertificateTypeNotAllowed extends TachographKeyToolException {
        CertificateTypeNotAllowed(TachographCertificateType type) {
            super("Certificate type not allowed: " + type);
        }
    }

    class IncorrectDateTimeFormat extends TachographKeyToolException {
        IncorrectDateTimeFormat(String arg, DateTimeParseException ex) {
            super("Incorrect format for date/time: " + arg, ex);
        }
    }

    class IncorrectNumberFormat extends TachographKeyToolException {
        IncorrectNumberFormat(String arg, NumberFormatException ex) {
            super("Incorrect format for numeric input: " + arg, ex);
        }
    }

    class IncorrectExtendedSerialNumberSize extends TachographKeyToolException {
        IncorrectExtendedSerialNumberSize(String arg) {
            super("Extended serial number should consist of 16 hexadecimal digits: " + arg);
        }
    }

    class IncorrectExtendedSerialNumberFormat extends TachographKeyToolException {
        IncorrectExtendedSerialNumberFormat(String arg, Exception cause) {
            super("Incorrect format for extended serial number format: " + cause.getMessage(), cause);
        }
    }
}
