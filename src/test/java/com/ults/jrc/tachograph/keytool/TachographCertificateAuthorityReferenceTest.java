package com.ults.jrc.tachograph.keytool;

import org.junit.Test;

public class TachographCertificateAuthorityReferenceTest {

    @Test(expected = TachographKeyToolException.class)
    public void testConstructionFromIncorrectDer() {
        TachographCertificateAuthorityReference.getInstance(new TachographCertificateProfileIdentifier().toASN1Primitive());
    }

    @Test(expected = TachographKeyToolException.class)
    public void testConstructionFromIncorrectContents() {
        new TachographCertificateAuthorityReference(new byte[0]);
    }
}
