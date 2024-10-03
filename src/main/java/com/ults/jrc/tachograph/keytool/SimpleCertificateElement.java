package com.ults.jrc.tachograph.keytool;

import java.io.PrintStream;
import org.bouncycastle.asn1.ASN1ApplicationSpecific;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.DERApplicationSpecific;

/**
 * Abstract base class for certificate elements constructed from a byte array.
 *
 * @author Klaas Mateboer
 */
public abstract class SimpleCertificateElement extends CertificateElement {

    private static final char[] HEX_DIGITS = "0123456789ABCDEF".toCharArray();

    public SimpleCertificateElement(String name, int tag) {
        super(name, tag);
    }

    @Override
    public ASN1Primitive toASN1Primitive() {
        return new DERApplicationSpecific(tag, getContents());
    }

    @Override
    void show(String prefix, PrintStream out) {
        out.println(prefix + name + " " + bytesToHex(getContents()));
    }

    abstract byte[] getContents();

    static byte[] getContents(ASN1Encodable o, int tag, String name) {
        ASN1ApplicationSpecific as = ASN1ApplicationSpecific.getInstance(o);
        if (as.getApplicationTag() != tag)
            throw new TachographKeyToolException("Invalid tag for " + name);
        return as.getContents();
    }

    private static String bytesToHex(byte[] bytes) {
        char[] hexChars = new char[bytes.length * 2];
        for (int j = 0; j < bytes.length; j++) {
            int v = bytes[j] & 0xFF;
            hexChars[j * 2] = HEX_DIGITS[v >>> 4];
            hexChars[j * 2 + 1] = HEX_DIGITS[v & 0x0F];
        }
        return new String(hexChars);
    }
}
