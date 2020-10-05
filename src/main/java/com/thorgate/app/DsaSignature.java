package com.thorgate.app;

import java.math.BigInteger;
import java.io.IOException;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERSequence;

import org.apache.commons.lang3.ArrayUtils;

public class DsaSignature {
    private final BigInteger r;
    private final BigInteger s;

    public DsaSignature(BigInteger r, BigInteger s) {
        this.r = r;
        this.s = s;
    }

    public static DsaSignature fromCvcEncoding(byte[] cvcEncoding) {
        byte[][] elements = splitArrayInTheMiddle(cvcEncoding);
        BigInteger r = new BigInteger(1, elements[0]);
        BigInteger s = new BigInteger(1, elements[1]);
        return new DsaSignature(r, s);
    }

    public byte[] encodeInAsn1() {
        ASN1EncodableVector sequence = new ASN1EncodableVector();
        sequence.add(new ASN1Integer(r));
        sequence.add(new ASN1Integer(s));

        try {
            return new DERSequence(sequence).getEncoded("DER");
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    private static byte[][] splitArrayInTheMiddle(byte[] array) {
        return new byte[][] {
                ArrayUtils.subarray(array, 0, array.length / 2),
                ArrayUtils.subarray(array, array.length / 2, array.length)
        };
    }
}
