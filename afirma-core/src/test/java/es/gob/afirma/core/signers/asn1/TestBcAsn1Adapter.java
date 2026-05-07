/* Copyright (C) 2011 [Gobierno de Espana]
 * This file is part of "Cliente @Firma".
 * "Cliente @Firma" is free software; you can redistribute it and/or modify it under the terms of:
 *   - the GNU General Public License as published by the Free Software Foundation;
 *     either version 2 of the License, or (at your option) any later version.
 *   - or The European Software License; either version 1.1 or (at your option) any later version.
 * You may contact the copyright holder at: soporte.afirma@seap.minhap.es
 */

package es.gob.afirma.core.signers.asn1;

import static org.junit.jupiter.api.Assertions.assertAll;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.io.IOException;
import java.math.BigInteger;
import java.util.List;

import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Primitive;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import es.gob.afirma.core.signers.der.DerInputStream;
import es.gob.afirma.core.signers.der.DerOutputStream;
import es.gob.afirma.core.signers.der.DerValue;

/**
 * Tests del puente {@link BcAsn1Adapter}.
 *
 * <p>Cada test ejercita el adaptador contra un input fijo y verifica adem&aacute;s
 * que la codificaci&oacute;n resultante coincide byte a byte con la del fork
 * Oracle {@code DerValue}. As&iacute; documentamos formalmente la equivalencia
 * funcional que se requiere para Fase F.2 (migraci&oacute;n de consumidores)
 * y F.3 (eliminaci&oacute;n del fork).</p>
 */
class TestBcAsn1Adapter {

	@Test
	@DisplayName("encodeSequenceOfIntegers produce el mismo DER que DerValue")
	void encodeSequenceMatchesDerValue() throws Exception {
		final BigInteger r = new BigInteger("123456789012345678901234567890"); //$NON-NLS-1$
		final BigInteger s = new BigInteger("987654321098765432109876543210"); //$NON-NLS-1$

		final byte[] bcEncoded = BcAsn1Adapter.encodeSequenceOfIntegers(r, s);

		// Encoding equivalente con la API legacy
		final DerOutputStream legacy = new DerOutputStream();
		legacy.putInteger(r);
		legacy.putInteger(s);
		final DerValue wrapped = new DerValue(DerValue.tag_Sequence, legacy.toByteArray());
		final byte[] legacyEncoded = wrapped.toByteArray();

		assertArrayEquals(legacyEncoded, bcEncoded,
				"BC y DerValue deben producir el mismo DER para SEQUENCE OF INTEGER"); //$NON-NLS-1$
	}

	@Test
	@DisplayName("decodeSequenceOfIntegers devuelve los mismos enteros que DerValue")
	void decodeSequenceMatchesDerValue() throws Exception {
		final BigInteger r = new BigInteger("12345678"); //$NON-NLS-1$
		final BigInteger s = new BigInteger("87654321"); //$NON-NLS-1$
		final byte[] der = BcAsn1Adapter.encodeSequenceOfIntegers(r, s);

		final BigInteger[] bcResult = BcAsn1Adapter.decodeSequenceOfIntegers(der, 2);

		// Decodificación equivalente con la API legacy
		final DerInputStream legacyIn = new DerInputStream(der, 0, der.length, false);
		final DerValue[] legacyValues = legacyIn.getSequence(2);

		assertAll(
				() -> assertEquals(r, bcResult[0]),
				() -> assertEquals(s, bcResult[1]),
				() -> assertEquals(legacyValues[0].getBigInteger(), bcResult[0]),
				() -> assertEquals(legacyValues[1].getBigInteger(), bcResult[1]));
	}

	@Test
	@DisplayName("decodeSequenceOfIntegers rechaza tamaños incorrectos")
	void decodeSequenceWrongSizeFails() throws Exception {
		final byte[] der = BcAsn1Adapter.encodeSequenceOfIntegers(BigInteger.ONE, BigInteger.TEN);
		assertThrows(IOException.class, () -> BcAsn1Adapter.decodeSequenceOfIntegers(der, 3));
	}

	@Test
	@DisplayName("decodeSequenceOfIntegers rechaza datos no DER")
	void decodeSequenceInvalidFails() {
		final byte[] garbage = {0x00, 0x01, 0x02};
		assertThrows(IOException.class, () -> BcAsn1Adapter.decodeSequenceOfIntegers(garbage, 1));
	}

	@Test
	@DisplayName("encodeOctetString produce el mismo DER que DerValue")
	void encodeOctetStringMatchesDerValue() throws Exception {
		final byte[] payload = {(byte) 0xCA, (byte) 0xFE, (byte) 0xBA, (byte) 0xBE};
		final byte[] bcEncoded = BcAsn1Adapter.encodeOctetString(payload);

		final DerOutputStream legacy = new DerOutputStream();
		legacy.putOctetString(payload);
		final byte[] legacyEncoded = legacy.toByteArray();

		assertArrayEquals(legacyEncoded, bcEncoded);
	}

	@Test
	@DisplayName("getOctetStringContent extrae los mismos bytes que DerValue.getOctetString()")
	void octetStringRoundtrip() throws Exception {
		final byte[] payload = {0x11, 0x22, 0x33, 0x44, 0x55};
		final byte[] der = BcAsn1Adapter.encodeOctetString(payload);

		assertArrayEquals(payload, BcAsn1Adapter.getOctetStringContent(der));
		assertArrayEquals(payload, new DerValue(der).getOctetString());
	}

	@Test
	@DisplayName("encodeOid / decodeOid round-trip preserva el OID")
	void oidRoundtrip() throws Exception {
		final String oid = "1.2.840.113549.1.1.11"; // sha256WithRSA //$NON-NLS-1$
		final byte[] der = BcAsn1Adapter.encodeOid(oid);

		assertEquals(oid, BcAsn1Adapter.decodeOid(der));
		// Equivalencia con DerValue.getOID()
		assertEquals(oid, new DerValue(der).getOID().toString());
	}

	@Test
	@DisplayName("encodeOid produce el mismo DER que DerValue.putOID")
	void encodeOidMatchesDerValue() throws Exception {
		final String oid = "1.3.6.1.4.1.311.10.1"; //$NON-NLS-1$
		final byte[] bcEncoded = BcAsn1Adapter.encodeOid(oid);

		final DerOutputStream legacy = new DerOutputStream();
		legacy.putOID(new es.gob.afirma.core.signers.der.ObjectIdentifier(oid));
		final byte[] legacyEncoded = legacy.toByteArray();

		assertArrayEquals(legacyEncoded, bcEncoded);
	}

	@Test
	@DisplayName("encodeInteger / decodeInteger round-trip")
	void integerRoundtrip() throws Exception {
		final BigInteger value = new BigInteger("31415926535897932384626433"); //$NON-NLS-1$
		final byte[] der = BcAsn1Adapter.encodeInteger(value);

		assertEquals(value, BcAsn1Adapter.decodeInteger(der));
		assertEquals(value, new DerValue(der).getBigInteger());
	}

	@Test
	@DisplayName("readSequenceMembers itera primitives heterogéneos")
	void readSequenceMembersHeterogeneous() throws Exception {
		// SEQUENCE { INTEGER 5, OCTET STRING "AB" }
		final byte[] der = {0x30, 0x07,
				0x02, 0x01, 0x05,
				0x04, 0x02, 0x41, 0x42};

		final List<ASN1Primitive> members = BcAsn1Adapter.readSequenceMembers(der);

		assertAll(
				() -> assertEquals(2, members.size()),
				() -> assertEquals(BigInteger.valueOf(5),
						ASN1Integer.getInstance(members.get(0)).getValue()));
	}

	@Test
	@DisplayName("readSequenceMembers rechaza datos que no son SEQUENCE")
	void readSequenceMembersInvalid() {
		// INTEGER 5 (no SEQUENCE)
		final byte[] der = {0x02, 0x01, 0x05};
		assertThrows(Exception.class, () -> BcAsn1Adapter.readSequenceMembers(der));
	}
}
