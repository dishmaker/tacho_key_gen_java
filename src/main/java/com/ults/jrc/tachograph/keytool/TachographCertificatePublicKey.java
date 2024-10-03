package com.ults.jrc.tachograph.keytool;

import java.io.IOException;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.ECPublicKeySpec;
import java.security.spec.EllipticCurve;
import java.util.Arrays;
import org.bouncycastle.asn1.ASN1ApplicationSpecific;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.BERTags;
import org.bouncycastle.asn1.nist.NISTNamedCurves;
import org.bouncycastle.asn1.teletrust.TeleTrusTNamedCurves;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.jcajce.provider.asymmetric.util.EC5Util;
import org.bouncycastle.jce.ECPointUtil;
import org.bouncycastle.math.ec.ECCurve;

/**
 * Immutable representation of a tachograph certificate public key.
 *
 * @author Klaas Mateboer
 */
public class TachographCertificatePublicKey extends CompoundCertificateElement {

    private static final String NAME = "PublicKey";
    private static final int TAG = 73;

    private final ECParameterSpec params;
    private final ECPoint point;

    private final TachographCertificateDomainParameters dp;
    private final TachographCertificatePublicPoint pp;

    static TachographCertificatePublicKey getInstance(ASN1Encodable o) throws IOException {
        ASN1ApplicationSpecific publicKey = ASN1ApplicationSpecific.getInstance(o);
        if (publicKey.getApplicationTag() != TAG)
            throw new TachographKeyToolException("Invalid tag for certificate public key");
        ASN1Sequence seq = ASN1Sequence.getInstance(publicKey.getObject(BERTags.SEQUENCE));
        return new TachographCertificatePublicKey(
                TachographCertificateDomainParameters.getInstance(seq.getObjectAt(0)),
                TachographCertificatePublicPoint.getInstance(seq.getObjectAt(1)));
    }

    TachographCertificatePublicKey(ASN1ObjectIdentifier oid, ECPublicKey publicKey) {
        this(oid, publicKey.getW(), publicKey.getParams());
    }

    TachographCertificatePublicKey(TachographCertificateDomainParameters dp, TachographCertificatePublicPoint pp) {
        super(NAME, TAG);
        this.dp = dp;
        this.pp = pp;

        X9ECParameters ecP = TeleTrusTNamedCurves.getByOID(dp.oid);
        if (ecP == null)
            ecP = NISTNamedCurves.getByOID(dp.oid);

        ECCurve curve = ecP.getCurve();
        org.bouncycastle.jce.spec.ECParameterSpec bcParams =
                new org.bouncycastle.jce.spec.ECParameterSpec(curve, ecP.getG(), ecP.getN(), ecP.getH());

        EllipticCurve ellipticCurve = EC5Util.convertCurve(curve, bcParams.getSeed());
        this.params = EC5Util.convertSpec(ellipticCurve, bcParams);
        this.point = ECPointUtil.decodePoint(ellipticCurve, pp.getContents());
    }

    TachographCertificatePublicKey(ASN1ObjectIdentifier oid, ECPoint point, ECParameterSpec params) {
        super(NAME, TAG);
        this.point = point;
        this.params = params;
        this.dp = new TachographCertificateDomainParameters(oid);
        this.pp = new TachographCertificatePublicPoint(point, params);
    }

    ECPublicKeySpec getKeySpec() {
        return new ECPublicKeySpec(point, params);
    }

    @Override
    Iterable<CertificateElement> getElements() {
        return Arrays.asList(dp, pp);
    }
}