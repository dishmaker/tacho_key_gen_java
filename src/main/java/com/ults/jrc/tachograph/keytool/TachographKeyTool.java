package com.ults.jrc.tachograph.keytool;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.InvalidPathException;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.PrivateKey;
import java.security.interfaces.ECPrivateKey;

/**
 * Generation-2 Smart Tachograph Key Tool.
 *
 * Generates key and certificate files for Tachograph related certificate authorities and equipment.
 *
 * @author Klaas Mateboer
 */
public class TachographKeyTool {

    private final TachographKeyToolUser user;
    private final TachographCryptography crypto;

    public TachographKeyTool(TachographKeyToolUser user) {
        this.crypto = new TachographCryptography(user);
        this.user = user;
    }

    /**
     * Generate an EC key pair and store the private key in a PKCS#8 formatted file.
     *
     * @param name the name of the PKCS#8 file to be created
     * @param curve the standard name of the elliptic curve parameters to be used
     */
    public void generateKeyPair(String name, String curve) {
        writePkcs8(name, crypto.generateKeyPair(curve).getPrivate());
    }

    /**
     * Generate a random secret AES key and store it in a binary file.
     *
     * @param name the name of the binary file to be created
     * @param size the size in bytes of the key to be generated
     */
    public void generateSecretKey(String name, int size) {
        writeBinary(name, crypto.getRandom(size));
    }

    /**
     * Create a self-signed certificate.
     *
     * For certificate type and holder reference type should be a valid combination.
     *
     * @param type the certificate type
     * @param name the name of the certificate file to be created
     * @param pkcs8Name the name of the PKCS#8 file containing the key to be certified
     * @param holder the holder reference
     * @param validityPeriod the validity period
     */
    public void create(TachographCertificateType type, String name, String pkcs8Name,
            TachographEntityReference holder, TachographCertificateValidity validityPeriod) {
        TachographKeyPair keyPair = crypto.getTachographKeyPair(readPrivateKey(pkcs8Name));
        writeCertificate(name, crypto.createCertificate(type, keyPair, holder, validityPeriod));
        crypto.checkSelfSignedCertificate(readCertificate(name + ".cert"));
    }

    /**
     * Sign a certificate.
     *
     * @param requestName the file name of the request certificate
     * @param caPrivateKeyName the file name of the CA private key
     * @param caCertificateName the file name of the CA certificate
     * @param certificateName the output file name for the signed certificate
     */
    public void sign(String requestName, String caPrivateKeyName, String caCertificateName, String certificateName) {
        TachographCertificate request = readCertificate(requestName);
        crypto.checkSelfSignedCertificate(request);
        TachographCertificate caCertificate = readCertificate(caCertificateName);
        crypto.checkCertificate(caCertificate);
        writeCertificate(certificateName, crypto.sign(request, readPrivateKey(caPrivateKeyName), caCertificate));
        crypto.verify(readCertificate(certificateName + ".cert"), caCertificate);
    }

    /**
     * Create and sign a link certificate.
     * A link certificate has the same expiration date as the CA certificate.
     *
     * @param caPkcs8Name the file name of the CA private key
     * @param caCertificateName the file name of the CA certificate
     * @param requestName the file name of the request certificate
     * @param certificateName the output file name for the signed certificate
     */
    public void link(String caPkcs8Name, String caCertificateName, String requestName, String certificateName) {
        TachographCertificate request = readCertificate(requestName);
        crypto.checkSelfSignedCertificate(request);
        TachographCertificate caCertificate = readCertificate(caCertificateName);
        crypto.checkCertificate(caCertificate);
        writeCertificate(certificateName, crypto.link(request, readPrivateKey(caPkcs8Name), caCertificate));
        crypto.verify(readCertificate(certificateName + ".cert"), caCertificate);
    }

    /**
     * Verify the signature of a certificate.
     *
     * @param certificateName the file name of the certificate to be verified
     * @param caCertificateName the file name of the CA certificate
     */
    public void verify(String certificateName, String caCertificateName) {
        crypto.verify(readCertificate(certificateName), readCertificate(caCertificateName));
        user.inform("Verified " + certificateName);
    }

    /**
     * Encrypt a pairing key, and store the result in a binary file.
     *
     * @param msmkName the name of the file containing the MSMK
     * @param pkName the name of the file containing the pairing key
     * @param baseName the base name for the output file
     */
    public void encryptPairingKey(String msmkName, String pkName, String baseName) {
        writeBinary(baseName + "-pk-enc", crypto.encryptPairingKey(readFile(msmkName), readFile(pkName)));
    }

    /**
     * Encrypt a Motion Sensor Extended Serial Number, and store the result in a binary file.
     *
     * @param msmkName the name of the file containing the MSMK
     * @param sn the extended serial number
     * @param baseName the base name for the output file
     */
    public void encryptMsExtendedSerialNumber(String msmkName, TachographExtendedSerialNumber sn, String baseName) {
        writeBinary(baseName + "-esn-enc", crypto.encryptMsExtendedSerialNumber(readFile(msmkName), sn));
    }

    /**
     * Derive DSRC keys from a Vehicle Unit Extended Serial Number, and store the keys in binary files.
     *
     * @param dsrcmkName the name of the file containing the DSRCMK
     * @param esn the extended serial number
     * @param baseName the base name for the output files
     */
    public void deriveVuDsrcKeys(String dsrcmkName, TachographExtendedSerialNumber esn, String baseName) {
        byte[] okm = crypto.kdf(readFile(dsrcmkName), esn.toByteArray());
        writeBinary(baseName + "-enc", crypto.firstHalf(okm));
        writeBinary(baseName + "-mac", crypto.lastHalf(okm));
    }

    /**
     * Derive the Motion Sensor Master Key from the Vehicle Unit and Workshop Card parts.
     *
     * @param msmkVuName the name of the file containing the VU part of the MSMK
     * @param msmkWcName the name of the file containing the WC part of the MSMK
     * @param baseName the base name for the output file
     */
    public void deriveMsmk(String msmkVuName, String msmkWcName, String baseName) {
        writeBinary(baseName, crypto.deriveMsmk(readFile(msmkVuName), readFile(msmkWcName)));
    }

    /**
     * Derive the Identification Key from the Motion Sensor Master Key.
     *
     * @param msmkName the name of the file containing the MSMK
     * @param baseName the base name for the output file
     */
    public void deriveMsik(String msmkName, String baseName) {
        writeBinary(baseName, crypto.deriveMsik(readFile(msmkName)));
    }

    private ECPrivateKey readPrivateKey(String fileName) {
        return crypto.getPrivateKey(readFile(fileName));
    }

    private TachographCertificate readCertificate(String fileName) {
        try {
            TachographCertificate certificate = TachographCertificate.getInstance(readFile(fileName));
            user.show(certificate);
            return certificate;
        } catch (IOException ex) {
            throw new CertificateDecodingFailed(fileName, ex);
        }
    }

    private byte[] readFile(String fileName) {
        try {
            user.inform("Reading " + fileName);
            return Files.readAllBytes(getPath(fileName));
        } catch (IOException ex) {
            throw new UnableToReadFile(fileName, ex);
        }
    }

    private Path getPath(String fileName) {
        try {
            return Paths.get(fileName);
        } catch (InvalidPathException ex) {
            throw new InvalidFileName(fileName, ex);
        }
    }

    private void writeBinary(String name, byte[] bytes) {
        writeFile(name + ".bin", bytes);
    }

    private void writeCertificate(String name, TachographCertificate certificate) {
        try {
            writeFile(name + ".cert", certificate.getEncoded());
            user.show(certificate);
        } catch (IOException ex) {
            throw new CertificateEncodingFailed(name, ex);
        }
    }

    private void writePkcs8(String name, PrivateKey key) {
        writeFile(name + ".pkcs8", key.getEncoded());
    }

    private void writeFile(String fileName, byte[] bytes) {
        try {
            user.inform("Writing " + fileName);
            Files.write(createPath(fileName), bytes);
        } catch (IOException ex) {
            throw new UnableToWriteFile(fileName, ex);
        }
    }

    private Path createPath(String fileName) {
        Path path = getPath(fileName);
        ensureDirectoryExists(path.getParent());
        return path;
    }

    private void ensureDirectoryExists(Path path) {
        try {
            if (path != null)
                Files.createDirectories(path);
        } catch (IOException ex) {
            throw new UnableToCreateDirectory(path.toString(), ex);
        }
    }

    class CertificateDecodingFailed extends TachographKeyToolException {
        CertificateDecodingFailed(String name, Exception cause) {
            super("Decoding certificate failed: " + name, cause);
        }
    }

    class CertificateEncodingFailed extends TachographKeyToolException {
        CertificateEncodingFailed(String name, Exception cause) {
            super("Encoding certificate failed: " + name, cause);
        }
    }

    class InvalidFileName extends TachographKeyToolException {
        InvalidFileName(String name, Exception cause) {
            super("Invalid file name: " + name, cause);
        }
    }

    class UnableToReadFile extends TachographKeyToolException {
        UnableToReadFile(String name, Exception cause) {
            super("Unable to read file: " + name, cause);
        }
    }

    class UnableToWriteFile extends TachographKeyToolException {
        UnableToWriteFile(String name, Exception cause) {
            super("Unable to write file: " + name, cause);
        }
    }

    class UnableToCreateDirectory extends TachographKeyToolException {
        UnableToCreateDirectory(String name, Exception cause) {
            super("Unable to create directory: " + name, cause);
        }
    }
}
