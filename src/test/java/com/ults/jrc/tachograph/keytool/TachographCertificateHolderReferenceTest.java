package com.ults.jrc.tachograph.keytool;

import org.junit.Test;

public class TachographCertificateHolderReferenceTest {

    @Test(expected = TachographKeyToolException.class)
    public void testConstructionFromIncorrectDer() {
        TachographCertificateHolderReference.getInstance(new TachographCertificateProfileIdentifier().toASN1Primitive());
    }

    @Test(expected = TachographKeyToolException.class)
    public void testConstructionFromIncorrectContents() {
        new TachographCertificateHolderReference(new byte[0]);
    }
}
