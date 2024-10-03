package com.ults.jrc.tachograph.keytool;

import static com.ults.jrc.tachograph.keytool.TachographDefinitions.AUTHORISATION_TYPE_ERCA;
import java.io.IOException;
import java.security.spec.ECPublicKeySpec;
import java.time.LocalDateTime;
import java.util.Arrays;
import org.bouncycastle.asn1.ASN1ApplicationSpecific;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.BERTags;

/**
 * Immutable representation of a tachograph certificate.
 *
 * Elements of a tachograph certificate and related DER encoded tags:
 *
 *    Certificate                                7F21
 *        CertificateBody                        7F4E
 *            CertificateProfileIdentifier       5F29
 *            CertificateAuthorityReference      42
 *            CertificateHolderAuthorisation     5F4C
 *            PublicKey                          7F49
 *                DomainParameters               06
 *                PublicPoint                    86
 *            CertificateHolderReference         5F20
 *            CertificateEffectiveDate           5F25
 *            CertificateExpirationDate          5F24
 *        CertificateSignature                   5F37
 *
 * @author Klaas Mateboer
 */
public class TachographCertificate extends CompoundCertificateElement {

    private static final String NAME = "Certificate";
    private static final int TAG = 33;

    public static TachographCertificate getInstance(byte[] bytes) throws IOException {
        try {
            return getInstance((ASN1ApplicationSpecific) ASN1ApplicationSpecific.fromByteArray(bytes));
        } catch (ClassCastException | NullPointerException ex) {
            throw new TachographKeyToolException("Invalid certificate format", ex);
        }
    }

    public static TachographCertificate getInstance(ASN1ApplicationSpecific certificate) throws IOException {
        if (certificate.getApplicationTag() != TAG)
            throw new TachographKeyToolException("Invalid tag for certificate");
        ASN1Sequence seq = ASN1Sequence.getInstance(certificate.getObject(BERTags.SEQUENCE));
        return new TachographCertificate(
                TachographCertificateBody.getInstance(seq.getObjectAt(0)),
                TachographCertificateSignature.getInstance(seq.getObjectAt(1))
        );
    }

    static ASN1EncodableVector getVector(ASN1Encodable... asn1Encodables) {
        ASN1EncodableVector vector = new ASN1EncodableVector();
        for (ASN1Encodable e : asn1Encodables)
            vector.add(e);
        return vector;
    }

    final TachographCertificateBody body;
    final TachographCertificateSignature signature;

    TachographCertificate(TachographCertificateBody body, TachographCertificateSignature signature) {
        super(NAME, TAG);
        this.body = body;
        this.signature = signature;
    }

    ECPublicKeySpec getKeySpec() {
        return body.pk.getKeySpec();
    }

    int getBitLength() {
        return getKeySpec().getParams().getOrder().bitLength();
    }

    boolean isAuthorisationType(int type) {
        return body.ha.getType() == type;
    }

    boolean isSelfSigned() {
        return Arrays.equals(body.hr.getContents(), body.ar.getContents());
    }

    boolean isLinkCertificate() {
        return isAuthorisationType(AUTHORISATION_TYPE_ERCA) && !isSelfSigned();
    }

    LocalDateTime getEffectiveDate() {
        return body.efd.getLocalDateTime();
    }

    LocalDateTime getExpirationDate() {
        return body.exd.getLocalDateTime();
    }

    @Override
    Iterable<CertificateElement> getElements() {
        return Arrays.asList(body, signature);
    }
}