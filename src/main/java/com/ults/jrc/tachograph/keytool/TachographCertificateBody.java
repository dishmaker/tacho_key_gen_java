package com.ults.jrc.tachograph.keytool;

import java.io.IOException;
import java.util.Arrays;
import org.bouncycastle.asn1.ASN1ApplicationSpecific;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.BERTags;

/**
 * Immutable representation of a tachograph certificate body.
 *
 * @author Klaas Mateboer
 */
public class TachographCertificateBody extends CompoundCertificateElement {

    private static final String NAME = "Body";
    private static final int TAG = 78;

    final TachographCertificateProfileIdentifier pi;
    final TachographCertificateAuthorityReference ar;
    final TachographCertificateHolderAuthorisation ha;
    final TachographCertificatePublicKey pk;
    final TachographCertificateHolderReference hr;
    final TachographCertificateEffectiveDate efd;
    final TachographCertificateExpirationDate exd;

    static TachographCertificateBody getInstance(ASN1Encodable o) throws IOException {
        ASN1ApplicationSpecific body = ASN1ApplicationSpecific.getInstance(o);
        if (body.getApplicationTag() != TAG)
            throw new TachographKeyToolException("Invalid tag for certificate body");
        ASN1Sequence seq = ASN1Sequence.getInstance(body.getObject(BERTags.SEQUENCE));
        return new TachographCertificateBody(
                TachographCertificateProfileIdentifier.getInstance(seq.getObjectAt(0)),
                TachographCertificateAuthorityReference.getInstance(seq.getObjectAt(1)),
                TachographCertificateHolderAuthorisation.getInstance(seq.getObjectAt(2)),
                TachographCertificatePublicKey.getInstance(seq.getObjectAt(3)),
                TachographCertificateHolderReference.getInstance(seq.getObjectAt(4)),
                TachographCertificateEffectiveDate.getInstance(seq.getObjectAt(5)),
                TachographCertificateExpirationDate.getInstance(seq.getObjectAt(6)));
    }

    TachographCertificateBody(
            TachographCertificateBody body,
            TachographCertificateAuthorityReference ar) {
        this(body.pi, ar, body.ha, body.pk, body.hr, body.efd, body.exd);
    }

    TachographCertificateBody(
            TachographCertificateBody body,
            TachographCertificateAuthorityReference ar,
            TachographCertificateExpirationDate exd) {
        this(body.pi, ar, body.ha, body.pk, body.hr, body.efd, exd);
    }

    TachographCertificateBody(
            TachographCertificateProfileIdentifier pi,
            TachographCertificateAuthorityReference ar,
            TachographCertificateHolderAuthorisation ha,
            TachographCertificatePublicKey pk,
            TachographCertificateHolderReference hr,
            TachographCertificateEffectiveDate efd,
            TachographCertificateExpirationDate exd) {
        super(NAME, TAG);
        this.pi = pi;
        this.ar = ar;
        this.ha = ha;
        this.pk = pk;
        this.hr = hr;
        this.efd = efd;
        this.exd = exd;
    }

    @Override
    Iterable<CertificateElement> getElements() {
        return Arrays.asList(pi, ar, ha, pk, hr, efd, exd);
    }
}