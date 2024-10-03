package com.ults.jrc.tachograph.keytool;

import java.io.IOException;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;

/**
 * Immutable data structure containing an EC key pair and an OID identifying the corresponding EC domain parameters. 
 *
 * @author Klaas Mateboer
 */
public class TachographKeyPair {

    final ECPrivateKey privateKey;
    final ECPublicKey publicKey;
    final ASN1ObjectIdentifier oid;

    TachographKeyPair(ECPrivateKey privateKey, ECPublicKey publicKey) {
        this.oid = getOid(privateKey);
        this.privateKey = privateKey;
        this.publicKey = publicKey;
    }

    /**
     * Retrieve the elliptic curve OID from the EC private key.
     * 
     * The structure of the EC private key:
     * 
     * Sequence
     *     Integer(0)
     *     Sequence
     *         ObjectIdentifier(1.2.840.10045.2.1)
     *         ObjectIdentifier(1.3.36.3.3.2.8.1.1.7)
     *     DER Octet String[122]
     * 
     * @param privateKey the EC private key
     * @return the OID
     */
    private static ASN1ObjectIdentifier getOid(ECPrivateKey privateKey) {
        try {
            ASN1Sequence seq = ASN1Sequence.getInstance(ASN1Primitive.fromByteArray(privateKey.getEncoded()));
            seq = ASN1Sequence.getInstance(seq.getObjectAt(1));
            return ASN1ObjectIdentifier.getInstance(seq.getObjectAt(1));
        } catch (IOException ex) {
            throw new TachographKeyToolException("Could not retrieve curve OID from private key", ex);
        }
    }
}