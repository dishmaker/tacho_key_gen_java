package com.ults.jrc.tachograph.keytool;

import static com.ults.jrc.tachograph.keytool.TachographUtils.copyIntegerBytes;

import java.io.IOException;
import java.math.BigInteger;
import java.util.Arrays;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERSequence;

/**
 * Immutable representation of a tachograph certificate signature.
 *
 * @author Klaas Mateboer
 */
public class TachographCertificateSignature extends SimpleCertificateElement {

    private static final String NAME = "Signature";
    private static final int TAG = 55;

    private final byte[] contents;

    static TachographCertificateSignature getInstance(ASN1Encodable o) {
        return new TachographCertificateSignature(getContents(o, TAG, NAME));
    }

    TachographCertificateSignature(byte[] encodedSignature, int bitLength) {
        this(getPlainSignature(encodedSignature, bitLength));
    }

    TachographCertificateSignature(byte[] contents) {
        super(NAME, TAG);
        this.contents = contents;
    }

    byte[] getEncodedSignature() throws IOException {
        byte[] r = Arrays.copyOfRange(contents, 0, contents.length / 2);
        byte[] s = Arrays.copyOfRange(contents, contents.length / 2, contents.length);
        return new DERSequence(new ASN1Encodable[]{
            new ASN1Integer(new BigInteger(1, r)),
            new ASN1Integer(new BigInteger(1, s))}).getEncoded();
    }

    private static byte[] getPlainSignature(byte[] encodedSignature, int bitLength) {
        try (ASN1InputStream inputStream = new ASN1InputStream(encodedSignature)) {
            ASN1Sequence point = (ASN1Sequence) inputStream.readObject();
            ASN1Integer r = (ASN1Integer) point.getObjectAt(0);
            ASN1Integer s = (ASN1Integer) point.getObjectAt(1);
            int integerSize = (bitLength + 7) / 8;
            byte[] plainSignature = new byte[integerSize * 2];
            copyIntegerBytes(r.getPositiveValue(), integerSize, plainSignature, 0);
            copyIntegerBytes(s.getPositiveValue(), integerSize, plainSignature, integerSize);
            return plainSignature;
        } catch (IOException ex) {
            throw new TachographKeyToolException("Failed to convert encoded signature", ex);
        }
    }

    @Override
    byte[] getContents() {
        return contents.clone();
    }
}