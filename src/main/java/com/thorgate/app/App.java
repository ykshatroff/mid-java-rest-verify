package com.thorgate.app;

import ee.sk.mid.MidHashToSign;
import ee.sk.mid.MidHashType;
import ee.sk.mid.MidSignature;
import ee.sk.mid.MidSignatureVerifier;
import ee.sk.mid.MidAuthentication;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.Signature;

import org.apache.commons.codec.binary.Base64;

public class App
{
    /*
     * Using this demo data
     * DEMO_PHONE_EE_OK = "+37200000766"
     * DEMO_PIN_EE_OK = "60001019906"
     */

    // the certificate
    public static String cert = "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";
    // this is the first signature (from Authentication request) that verifies successfully
    //public static String signatureBase64 = "fUpHO7RPxYH2B4bZjqNy7N4dnAkj3HszpElmkJiT86sXNgWtjx4yc7V95lc5cUbY95ppqb5gEFNrdXX1KT261A==";
    // this is the second signature (from signing request) that fails to verify
    public static String signatureBase64 = "29Bu4BdSYRHi+gvEILd0Z/agXhd636J9iLuNtPTK5pFSb2zgWMjPHlHu5KVyiJlbZ7S15N6Z3fFmfesoJUlSJA==";
    public static String digestBase64 = "Uy6qvZV0iA2/drm4zACDLCCm7BE9aCKZVQ16bg80XiU=";

    public static void main( String[] args )
    {
        System.out.println( "Hello World!" );
    }

    public static MidSignature getSignature() {
        MidSignature sig = MidSignature.newBuilder()
                .withValueInBase64(signatureBase64)
                .build();

        return sig;
    }

    public static MidHashToSign getHash() {
        MidHashToSign hashToSign = MidHashToSign.newBuilder()
            .withHashInBase64(digestBase64)
            .withHashType( MidHashType.SHA256)
            .build();

        return hashToSign;
    }

    public static X509Certificate getCertificate() throws CertificateException {
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        byte[] cert_bin = Base64.decodeBase64(cert);
        InputStream in = new ByteArrayInputStream(cert_bin);
        X509Certificate cert_x509 = (X509Certificate)cf.generateCertificate(in);
        return cert_x509;
    }

    public static boolean verifySignature(X509Certificate cert, MidHashToSign hash, MidSignature sig) throws Exception {
        Signature dsa = Signature.getInstance("NONEwithECDSA");
        dsa.initVerify(cert.getPublicKey());
        dsa.update(hash.getHash());
        byte[] signatureInAsn1 = DsaSignature.fromCvcEncoding(sig.getValue()).encodeInAsn1();
        return dsa.verify(signatureInAsn1);
    }

    public static boolean verifySignatureMid() throws Exception {
        X509Certificate cert = getCertificate();

        MidAuthentication auth = MidAuthentication.newBuilder()
            .withSignedHashInBase64(digestBase64)
            .withAlgorithmName("SHA256WithECEncryption")
            .withSignatureValueInBase64(signatureBase64)
            .withCertificate(cert)
            .build();

        return MidSignatureVerifier.verifyWithECDSA(
            cert.getPublicKey(),
            auth
        );
    }
}
