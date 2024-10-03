package com.ults.jrc.tachograph.keytool;

import static com.ults.jrc.tachograph.keytool.TachographDefinitions.*;

import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.SignatureException;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPublicKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.time.LocalDateTime;
import java.util.Arrays;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.Mac;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * Cryptographic methods for Generation-2 Smart Tachograph.
 *
 * Provides methods for both symmetric and asymmetric cryptographic methods as specified in
 * Commission Implementing Regulation (EU) 2016/799 of 18 March 2016.
 *
 * @author Klaas Mateboer
 */
public class TachographCryptography {

    private static final int AES_BLOCK_SIZE = 16;

    private static final IvParameterSpec AES_IV = new IvParameterSpec(new byte[AES_BLOCK_SIZE]);

    private final Provider provider;
    private final KeyPairGenerator keyPairGenerator;
    private final KeyFactory keyFactory;
    private final Cipher aesCipher;
    private final SecureRandom secureRandom;
    private final TachographKeyToolUser user;

    public TachographCryptography(TachographKeyToolUser out) {
        try {
            this.user = out;
            this.provider = new org.bouncycastle.jce.provider.BouncyCastleProvider();
            this.keyPairGenerator = KeyPairGenerator.getInstance("ECDSA", provider);
            this.keyFactory = KeyFactory.getInstance("ECDSA", provider);
            this.aesCipher = Cipher.getInstance("AES/CBC/NoPadding", provider);
            this.secureRandom = new SecureRandom();
            secureRandom.setSeed(System.currentTimeMillis());
            checkMaxAllowedAesKeySize(Cipher.getMaxAllowedKeyLength("AES"));
        } catch (NoSuchAlgorithmException | NoSuchPaddingException ex) {
            throw new InstantiationFailure(ex);
        }
    }

    private void checkMaxAllowedAesKeySize(int size) {
        if (size < 256)
            warn("maximum allowed AES key size is " + size + " bits\r\n"
                    + "install JCE unlimited strength jurisdiction policy files in order to support stronger keys");
    }

    /**
     * Generate an EC key pair based on the specified curve name.
     * Supported curves are defined in TachographDefinitions.
     *
     * @param curve the name of the curve
     * @return the generated key pair
     */
    public KeyPair generateKeyPair(String curve) {
        try {
            keyPairGenerator.initialize(new ECGenParameterSpec(curve), secureRandom);
            return keyPairGenerator.generateKeyPair();
        } catch (InvalidAlgorithmParameterException ex) {
            throw new KeyPairGenerationFailure(ex);
        }
    }

    ECPrivateKey getPrivateKey(byte[] pkcs8Bytes) {
        try {
            return (ECPrivateKey) keyFactory.generatePrivate(new PKCS8EncodedKeySpec(pkcs8Bytes));
        } catch (InvalidKeySpecException ex) {
            throw new UnableToRetrievePrivateKey(ex);
        }
    }

    /**
     * Get a Tachograph key pair from a given private key.
     * The public key is computed from the private key parameters.
     *
     * @param privateKey the EC private key
     * @return the Tachograph key pair
     */
    public TachographKeyPair getTachographKeyPair(ECPrivateKey privateKey) {
        return new TachographKeyPair(privateKey, getPublicKey(privateKey));
    }

    private ECPublicKey getPublicKey(ECPrivateKey privateKey) {
        try {
            org.bouncycastle.jce.spec.ECPrivateKeySpec privSpec = keyFactory.getKeySpec(privateKey,
                    org.bouncycastle.jce.spec.ECPrivateKeySpec.class);
            org.bouncycastle.jce.spec.ECParameterSpec params = privSpec.getParams();
            org.bouncycastle.math.ec.ECPoint q = params.getG().multiply(privSpec.getD());
            return (ECPublicKey) keyFactory.generatePublic(new org.bouncycastle.jce.spec.ECPublicKeySpec(q, params));
        } catch (InvalidKeySpecException ex) {
            throw new UnableToRetrievePublicKey(ex);
        }
    }

    /**
     * Create a self-signed certificate.
     *
     * @param type the certificate type
     * @param keyPair the key pair holding the public key to be certified, and the private key to sign the certificate
     * @param holder the certificate holder reference
     * @param validityPeriod the validity period
     * @return the self-signed certificate
     */
    public TachographCertificate createCertificate(TachographCertificateType type, TachographKeyPair keyPair,
            TachographEntityReference holder, TachographCertificateValidity validityPeriod) {
        return sign(getCertificateBody(type, keyPair, holder.toByteArray(), validityPeriod), keyPair.privateKey);
    }

    /**
     * Get a body for a self-signed certificate.
     *
     * @param type the type of the certificate
     * @param keyPair the keyPair providing the OID and public key
     * @param holder the reference to holder and authority
     * @param validityPeriod the validity period
     * @return the body
     */
    private TachographCertificateBody getCertificateBody(TachographCertificateType type, TachographKeyPair keyPair,
            byte[] holder, TachographCertificateValidity validityPeriod) {
        return new TachographCertificateBody(
                new TachographCertificateProfileIdentifier(),
                new TachographCertificateAuthorityReference(holder),
                new TachographCertificateHolderAuthorisation(type.authorisationType),
                new TachographCertificatePublicKey(keyPair.oid, keyPair.publicKey),
                new TachographCertificateHolderReference(holder),
                new TachographCertificateEffectiveDate(validityPeriod.effectiveDate),
                new TachographCertificateExpirationDate(validityPeriod.expirationDate)
        );
    }

    /**
     * Get a certificate body derived from request and authority certificate.
     *
     * The authority reference is derived from the holder reference of the signer. All other fields are taken
     * from the request certificate.
     *
     * @param request the certificate body of the request
     * @param signer the certificate body of the signer
     * @return the certificate body with updated authority reference
     */
    private TachographCertificateBody getCertificateBody(TachographCertificateBody request,
            TachographCertificateBody signer) {
        return new TachographCertificateBody(request, signer.hr.toAuthorityReference());
    }

    /**
     * Get a link certificate body derived from request and authority certificate.
     *
     * The authority reference is derived from the holder reference of the signer. The expiration date is also
     * taken from the signer. All other fields are taken from the request certificate.
     *
     * @param request the certificate body of the request
     * @param signer the certificate body of the signer
     * @return the certificate body with updated authority reference
     */
    private TachographCertificateBody getLinkCertificateBody(TachographCertificateBody request,
            TachographCertificateBody signer) {
        return new TachographCertificateBody(request, signer.hr.toAuthorityReference(), signer.exd);
    }

    /**
     * Sign a certificate.
     *
     * @param request the request certificate
     * @param caPrivateKey the signing key
     * @param caCertificate the certificate of the certificate authority
     * @return the signed certificate
     */
    public TachographCertificate sign(TachographCertificate request, ECPrivateKey caPrivateKey,
            TachographCertificate caCertificate) {
        return sign(getCertificateBody(request.body, caCertificate.body), caPrivateKey);
    }

    /**
     * Link a certificate.
     *
     * @param request the request certificate
     * @param caPrivateKey the signing key
     * @param caCertificate the certificate of the certificate authority
     * @return the signed certificate
     */
    public TachographCertificate link(TachographCertificate request, ECPrivateKey caPrivateKey,
            TachographCertificate caCertificate) {
        return sign(getLinkCertificateBody(request.body, caCertificate.body), caPrivateKey);
    }

    /**
     * Get a certificate with given body and a signature created by the given private key.
     *
     * @param body the body of the new certificate
     * @param caPrivateKey the signing key
     * @return the signed certificate
     */
    private TachographCertificate sign(TachographCertificateBody body, ECPrivateKey caPrivateKey) {
        try {
            return new TachographCertificate(body, getSignature(body.getEncoded(), caPrivateKey));
        } catch (IOException ex) {
            throw new CertificateBodyEncodingFailure(ex);
        }
    }

    private TachographCertificateSignature getSignature(byte[] body, ECPrivateKey caPrivateKey) {
        try {
            Signature signer = getSignatureAlgorithm(caPrivateKey.getParams());
            signer.initSign(caPrivateKey);
            signer.update(body);
            return new TachographCertificateSignature(signer.sign(), getBitLength(caPrivateKey.getParams()));
        } catch (InvalidKeyException | SignatureException ex) {
            throw new CertificateSigningFailure(ex);
        }
    }

    private Signature getSignatureAlgorithm(ECParameterSpec parameters) {
        try {
            return Signature.getInstance(getAlgorithmName(parameters), provider);
        } catch (NoSuchAlgorithmException ex) {
            throw new SignatureAlgorithmNotSupported(ex);
        }
    }

    private String getAlgorithmName(ECParameterSpec parameterSpec) {
        return getSignatureAlgorithmName(getBitLength(parameterSpec));
    }

    private int getBitLength(ECParameterSpec parameterSpec) {
        return parameterSpec.getOrder().bitLength();
    }

    /**
     * Verify the signature of a certificate.
     *
     * @param certificate the certificate to be verified
     * @param caCertificate the CA certificate
     */
    public void verify(TachographCertificate certificate, TachographCertificate caCertificate) {
        checkCertificate(certificate);
        checkCertificate(caCertificate);
        if (!caCertificate.body.hr.matches(certificate.body.ar))
            warn("certificate authority reference does not equal CA certificate holder reference");
        if (certificate.body.ha.getType() == AUTHORISATION_TYPE_ERCA)
            checkErca(certificate, caCertificate);
        if (certificate.getEffectiveDate().isBefore(caCertificate.getEffectiveDate()))
            warn("certificate validity period preceeds the CA certificate validity period");
        if (certificate.getExpirationDate().isAfter(caCertificate.getExpirationDate()))
            warn("certificate validity period exceeds the CA certificate validity period");
        if (isWeaker(caCertificate.getBitLength(), certificate.getBitLength()) && !certificate.isLinkCertificate())
            warn("certificate is signed with a weaker key");
        if (!authorisationMatch(certificate, caCertificate))
            warn("signer authorisation does not match the certificate authorisation");
        if (!isSignatureValid(certificate, caCertificate))
            throw new InvalidSignature();
    }

    void checkSelfSignedCertificate(TachographCertificate certificate) {
        checkCertificate(certificate);
        if (!isSignatureValid(certificate, certificate))
            warn("certificate is not properly self-signed");
        if (!certificate.isSelfSigned())
            warn("certificate holder and authority references should be equal");
        if (certificate.isAuthorisationType(AUTHORISATION_TYPE_ERCA))
            checkErca(certificate, certificate);
    }

    void checkCertificate(TachographCertificate certificate) {
        if (certificate.body.pi.getValue() != 0)
            warn("certificate profile identifier should be zero");
        checkValidityPeriod(certificate.body);
    }

    private void checkErca(TachographCertificate ercaCert, TachographCertificate signerCert) {
        if (ercaCert.isLinkCertificate())
            if (ercaCert.getEffectiveDate().isBefore(signerCert.getEffectiveDate().plusMonths(KEY_USAGE_PERIOD_ERCA)))
                warn("link certificate effective validity starts before end of signing key usage period");
        checkCertificationAuthorityKID(new TachographCertificationAuthorityKID(ercaCert.body.hr.getContents()));
    }

    private void checkCertificationAuthorityKID(TachographCertificationAuthorityKID kid) {
        if (!kid.nationAlpha.equals("EC "))
            warn("nation alpha of ERCA certificate holder reference is not equal to EC: " + kid.nationAlpha);
        if (kid.nationNumeric != (byte)0xfd)
            warn("nation numeric of ERCA certificate holder reference is not equal to 0xFD");
    }

    private void checkValidityPeriod(TachographCertificateBody body) {
        checkValidityPeriod(body.ha.getType(), body.efd.getLocalDateTime(), body.exd.getLocalDateTime());
    }

    private void checkValidityPeriod(int authorisationType, LocalDateTime effectiveDate, LocalDateTime expirationDate) {
        if (LocalDateTime.now().isBefore(effectiveDate))
            warn("certificate is not yet valid");
        if (!expirationDate.isAfter(LocalDateTime.now()))
            warn("certificate is expired");
        if (expirationDate.isBefore(effectiveDate))
            warn("certificate expiration date is before its effective date");
        if (expirationDate.equals(effectiveDate))
            warn("certificate expiration date is equal to its effective date");
        for (TachographCertificateType t : TachographCertificateType.values())
            if (t.authorisationType == authorisationType)
                if (effectiveDate.plusMonths(t.validity).equals(expirationDate))
                    return;
        warn("certificate validity period does not match with holder authorisation type " + authorisationType);
    }

    /**
     * Check whether the authorisation of the certificate and that of the CA is known as a valid combination.
     *
     * @param certificate the signed certificate
     * @param caCertificate the CA certificate
     * @return true iff the combination of the authorisations is allowed
     */
    private boolean authorisationMatch(TachographCertificate certificate, TachographCertificate caCertificate) {
        int signedAuthorisation = certificate.body.ha.getType();
        int signerAuthorisation = caCertificate.body.ha.getType();
        for (TachographCertificateType t : TachographCertificateType.values())
            if (t.authorisationType == signedAuthorisation)
                if (t.signer.authorisationType == signerAuthorisation)
                    return true;
        return false;
    }

    private boolean isSignatureValid(TachographCertificate certificate, TachographCertificate caCertificate) {
        return isSignatureValid(certificate, caCertificate.getKeySpec());
    }

    private boolean isSignatureValid(TachographCertificate certificate, ECPublicKeySpec publicKeySpec) {
        try {
            Signature verifier = getSignatureAlgorithm(publicKeySpec.getParams());
            verifier.initVerify(keyFactory.generatePublic(publicKeySpec));
            verifier.update(certificate.body.getEncoded());
            return verifier.verify(certificate.signature.getEncodedSignature());
        } catch (InvalidKeyException | InvalidKeySpecException | SignatureException | IOException ex) {
            throw new CertificateValidationFailure(ex);
        }
    }

    private boolean isWeaker(int bitLength1, int bitLength2) {
        return bitLength1 < bitLength2 && bitLength1 != 512;
    }

    /**
     * Derive an encrypted pairing key.
     *
     * @param msmk the MSMK
     * @param pk the plain pairing key
     * @return the encrypted pairing key
     */
    public byte[] encryptPairingKey(byte[] msmk, byte[] pk) {
        checkAesKeySizes(msmk, pk);
        return encrypt(msmk, getPaddedPairingKey(pk));
    }

    /**
     * Encrypt a Motion Sensor Extended Serial Number.
     *
     * @param msmk the MSMK
     * @param esn the extended serial number
     * @return the encrypted result
     */
    public byte[] encryptMsExtendedSerialNumber(byte[] msmk, TachographExtendedSerialNumber esn) {
        return encrypt(deriveMsik(msmk), pad(esn.toByteArray()));
    }

    /**
     * Derive a Motion Sensor Master Key.
     *
     * @param msmkVu the VU part of the MSMK
     * @param msmkWc the Workshop Card part of the MSMK
     * @return the MSMK
     */
    public byte[] deriveMsmk(byte[] msmkVu, byte[] msmkWc) {
        checkAesKeySizes(msmkVu, msmkWc);
        return xor(msmkVu, msmkWc);
    }

    /**
     * Derive a Motion Sensor Identification Key.
     *
     * @param msmk the Motion Sensor Master Key
     * @return the Identification Key
     */
    public byte[] deriveMsik(byte[] msmk) {
        checkAesKeySize(msmk);
        return xor(msmk, getCV(msmk.length));
    }

    private void checkAesKeySizes(byte[] key1, byte[] key2) {
        if (key1.length != key2.length)
            throw new AesKeySizeMismatch();
        checkAesKeySize(key1);
    }

    private void checkAesKeySize(byte[] key) {
        for (int s : AES_KEY_SIZES)
            if ((key.length * 8) == s)
                return;
        warn("incorrect key size of " + key.length + " bytes");
    }

    private byte[] xor(byte[] b1, byte[] b2) {
        byte[] result = Arrays.copyOf(b1, b1.length);
        for (int i = 0; i < b1.length; i++)
            result[i] ^= b2[i];
        return result;
    }

    private byte[] getPaddedPairingKey(byte[] pk) {
        return pk.length % AES_BLOCK_SIZE == 0 ? pk : pad(pk);
    }

    private byte[] pad(byte[] bytes) {
        int length = (((bytes.length + 1) / AES_BLOCK_SIZE) + 1) * AES_BLOCK_SIZE;
        byte[] result = Arrays.copyOf(bytes, length);
        result[bytes.length] = (byte) 0x80;
        return result;
    }

    public byte[] getRandom(int length) {
        byte[] bytes = new byte[length];
        secureRandom.nextBytes(bytes);
        return bytes;
    }

    private byte[] encrypt(byte[] key, byte[] data) {
        try {
            aesCipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, 0, key.length, "AES"), AES_IV);
            return aesCipher.doFinal(data);
        } catch (InvalidKeyException | IllegalBlockSizeException | BadPaddingException | InvalidAlgorithmParameterException ex) {
            throw new EncryptionFailure(ex);
        }
    }

    byte[] kdf(byte[] dsrcmk, byte[] esn) {
        String algo = hmacHashAlgorithm(dsrcmk.length);
        byte[] salt = new byte[dsrcmk.length];
        return hmac(algo, hmac(algo, salt, dsrcmk), append(esn, (byte) 1));
    }

    private byte[] hmac(String algorithm, byte[] key, byte[] data) {
        try {
            Mac hmac = Mac.getInstance(algorithm, provider);
            hmac.init(new SecretKeySpec(key, algorithm));
            return hmac.doFinal(data);
        } catch (NoSuchAlgorithmException | InvalidKeyException ex) {
            throw new HmacHashingFailure(ex);
        }
    }

    private byte[] append(byte[] bytes, byte b) {
        byte[] result = Arrays.copyOf(bytes, bytes.length + 1);
        result[bytes.length] = b;
        return result;
    }

    byte[] firstHalf(byte[] bytes) {
        return Arrays.copyOfRange(bytes, 0, bytes.length / 2);
    }

    byte[] lastHalf(byte[] bytes) {
        return Arrays.copyOfRange(bytes, bytes.length / 2, bytes.length);
    }

    private void warn(String message) {
        user.warn(message);
    }

    class InstantiationFailure extends TachographKeyToolException {
        InstantiationFailure(Exception cause) {
            super("Instantion of Tachograph cryptography failed: " + cause.getMessage(), cause);
        }
    }

    class KeyPairGenerationFailure extends TachographKeyToolException {
        KeyPairGenerationFailure(Exception cause) {
            super("Generating key pair failed", cause);
        }
    }

    class UnableToRetrievePrivateKey extends TachographKeyToolException {
        UnableToRetrievePrivateKey(Exception cause) {
            super("Unable to retrieve private key", cause);
        }
    }

    class UnableToRetrievePublicKey extends TachographKeyToolException {
        UnableToRetrievePublicKey(Exception cause) {
            super("Unable to retrieve public key", cause);
        }
    }

    class CertificateBodyEncodingFailure extends TachographKeyToolException {
        CertificateBodyEncodingFailure(Exception cause) {
            super("Encoding of the certificate body failed", cause);
        }
    }

    class CertificateSigningFailure extends TachographKeyToolException {
        CertificateSigningFailure(Exception cause) {
            super("Certificate signing failed", cause);
        }
    }

    class CertificateValidationFailure extends TachographKeyToolException {
        CertificateValidationFailure(Exception cause) {
            super("Certificate validation failed", cause);
        }
    }

    class SignatureAlgorithmNotSupported extends TachographKeyToolException {
        SignatureAlgorithmNotSupported(Exception cause) {
            super("Signature algorithm is not supported", cause);
        }
    }

    class InvalidSignature extends TachographKeyToolException {
        InvalidSignature() {
            super("Certificate signature is invalid");
        }
    }

    class EncryptionFailure extends TachographKeyToolException {
        EncryptionFailure(Exception cause) {
            super(cause.getMessage(), cause);
        }
    }

    class HmacHashingFailure extends TachographKeyToolException {
        HmacHashingFailure(Exception cause) {
            super("HMAC hashing failed", cause);
        }
    }

    class AesKeySizeMismatch extends TachographKeyToolException {
        AesKeySizeMismatch() {
            super("AES key sizes do not match");
        }
    }
}
