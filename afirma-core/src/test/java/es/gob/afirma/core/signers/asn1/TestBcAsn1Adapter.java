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

/**
 * Tests del puente {@link BcAsn1Adapter}.
 *
 * <p>Verifica round-trip BC↔BC, validaci&oacute;n de inputs y patrones DER
 * conocidos byte a byte. Antes de la Fase F.3 esta clase tambi&eacute;n
 * cruzaba contra el fork Oracle {@code DerValue} para demostrar
 * equivalencia funcional; ese paquete se elimin&oacute; en F.3 una vez
 * verificada la migraci&oacute;n.</p>
 */
class TestBcAsn1Adapter {

	@Test
	@DisplayName("encodeSequenceOfIntegers produce un SEQUENCE DER bien formado")
	void encodeSequenceOfTwoIntegers() throws Exception {
		final BigInteger r = BigInteger.valueOf(5);
		final BigInteger s = BigInteger.valueOf(9);

		final byte[] der = BcAsn1Adapter.encodeSequenceOfIntegers(r, s);

		// SEQUENCE (0x30) length 6 { INTEGER 5, INTEGER 9 }
		assertArrayEquals(
				new byte[] {0x30, 0x06, 0x02, 0x01, 0x05, 0x02, 0x01, 0x09},
				der);
	}

	@Test
	@DisplayName("encodeSequenceOfIntegers + decodeSequenceOfIntegers preservan los enteros")
	void roundtripLargeIntegers() throws Exception {
		final BigInteger r = new BigInteger("123456789012345678901234567890"); //$NON-NLS-1$
		final BigInteger s = new BigInteger("987654321098765432109876543210"); //$NON-NLS-1$

		final byte[] der = BcAsn1Adapter.encodeSequenceOfIntegers(r, s);
		final BigInteger[] decoded = BcAsn1Adapter.decodeSequenceOfIntegers(der, 2);

		assertAll(
				() -> assertEquals(r, decoded[0]),
				() -> assertEquals(s, decoded[1]));
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
	@DisplayName("encodeOctetString produce TLV { tag=0x04, length, octets }")
	void encodeOctetStringFormat() throws Exception {
		final byte[] payload = {(byte) 0xCA, (byte) 0xFE, (byte) 0xBA, (byte) 0xBE};
		final byte[] der = BcAsn1Adapter.encodeOctetString(payload);

		// OCTET STRING tag 0x04, length 0x04, then payload
		assertArrayEquals(
				new byte[] {0x04, 0x04, (byte) 0xCA, (byte) 0xFE, (byte) 0xBA, (byte) 0xBE},
				der);
	}

	@Test
	@DisplayName("getOctetStringContent extrae los bytes del OCTET STRING")
	void octetStringRoundtrip() throws Exception {
		final byte[] payload = {0x11, 0x22, 0x33, 0x44, 0x55};
		final byte[] der = BcAsn1Adapter.encodeOctetString(payload);

		assertArrayEquals(payload, BcAsn1Adapter.getOctetStringContent(der));
	}

	@Test
	@DisplayName("encodeOid / decodeOid round-trip preserva el OID")
	void oidRoundtrip() throws Exception {
		final String oid = "1.2.840.113549.1.1.11"; // sha256WithRSA //$NON-NLS-1$
		final byte[] der = BcAsn1Adapter.encodeOid(oid);

		assertEquals(oid, BcAsn1Adapter.decodeOid(der));
	}

	@Test
	@DisplayName("encodeOid produce TLV { tag=0x06, length, contenido } estándar")
	void encodeOidStandardForm() throws Exception {
		// OID 1.2.840.113549.1.1.1 (rsaEncryption)
		final byte[] der = BcAsn1Adapter.encodeOid("1.2.840.113549.1.1.1"); //$NON-NLS-1$
		assertArrayEquals(
				new byte[] {0x06, 0x09,
						0x2A, (byte) 0x86, 0x48, (byte) 0x86, (byte) 0xF7,
						0x0D, 0x01, 0x01, 0x01},
				der);
	}

	@Test
	@DisplayName("encodeInteger / decodeInteger round-trip")
	void integerRoundtrip() throws Exception {
		final BigInteger value = new BigInteger("31415926535897932384626433"); //$NON-NLS-1$
		final byte[] der = BcAsn1Adapter.encodeInteger(value);

		assertEquals(value, BcAsn1Adapter.decodeInteger(der));
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
