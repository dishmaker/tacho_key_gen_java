package com.ults.jrc.tachograph.keytool;

import static com.ults.jrc.tachograph.keytool.TachographUtils.copyIntegerBytes;

import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERTaggedObject;

/**
 * Immutable representation of a tachograph certificate public point.
 *
 * @author Klaas Mateboer
 */
public class TachographCertificatePublicPoint extends SimpleCertificateElement {

    private static final String NAME = "PublicPoint";
    private static final int TAG = 6;
    private static final byte DER_TAG_OCTET_STRING = 4;

    private final byte[] contents;

    static TachographCertificatePublicPoint getInstance(ASN1Encodable o) {
        ASN1TaggedObject to = ASN1TaggedObject.getInstance(o);
        ASN1OctetString os = DEROctetString.getInstance(to, false);
        return new TachographCertificatePublicPoint(os.getOctets());
    }

    TachographCertificatePublicPoint(ECPoint point, ECParameterSpec params) {
        super(NAME, TAG);
        this.contents = toBytes(point, params);
    }

    TachographCertificatePublicPoint(byte[] contents) {
        super(NAME, TAG);
        this.contents = contents;
    }

    private byte[] toBytes(ECPoint point, ECParameterSpec params) {
        int integerSize = (params.getOrder().bitLength() + 7) / 8;
        byte[] result = new byte[integerSize * 2 + 1];
        int offset = 0;
        result[offset++] = DER_TAG_OCTET_STRING;
        offset = copyIntegerBytes(point.getAffineX(), integerSize, result, offset);
        copyIntegerBytes(point.getAffineY(), integerSize, result, offset);
        return result;
    }

    @Override
    public ASN1Primitive toASN1Primitive() {
        return new DERTaggedObject(false, TAG, new DEROctetString(getContents()));
    }

    @Override
    byte[] getContents() {
        return contents.clone();
    }
}