package com.thorgate.app;

import static org.junit.Assert.assertTrue;
import static org.junit.Assert.assertEquals;

import org.junit.Test;

import java.security.cert.CertificateException;

/**
 * Unit test for simple App.
 */
public class AppTest
{
    @Test
    public void shouldVerifySignature() throws Exception
    {
        assertEquals( App.getSignature().getValueInBase64(), App.signatureBase64 );
        assertEquals( App.getHash().getHashInBase64(), App.digestBase64 );
        assertEquals( App.getCertificate().getPublicKey().getAlgorithm(), "EC" );

        App.getCertificate().checkValidity();
        assertTrue( App.verifySignatureMid() );
        // this also fails:
        // assertTrue( App.verifySignature( App.getCertificate(), App.getHash(), App.getSignature() ) );
    }
}
