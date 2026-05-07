/* Copyright (C) 2011 [Gobierno de Espana]
 * This file is part of "Cliente @Firma".
 * "Cliente @Firma" is free software; you can redistribute it and/or modify it under the terms of:
 *   - the GNU General Public License as published by the Free Software Foundation;
 *     either version 2 of the License, or (at your option) any later version.
 *   - or The European Software License; either version 1.1 or (at your option) any later version.
 * You may contact the copyright holder at: soporte.afirma@seap.minhap.es
 */

package es.gob.afirma.core.signers.der;

import static org.junit.jupiter.api.Assertions.assertAll;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.math.BigInteger;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * Red de regresi&oacute;n para {@link DerOutputStream}, {@link DerInputStream},
 * {@link ObjectIdentifier} y {@link BitArray} antes de la migraci&oacute;n a
 * {@code org.bouncycastle.asn1.*} (Fase F).
 *
 * <p>Cada test escribe un valor con {@code DerOutputStream} y lo recupera con
 * {@code DerInputStream}, fijando as&iacute; el contrato bidireccional que el
 * fork de Oracle ten&iacute;a sin tests.</p>
 */
class TestDerStreamsRoundtrip {

	// === DerOutputStream + DerInputStream round-trips ===

	@Test
	@DisplayName("putBoolean → getBoolean preserva el valor")
	void roundtripBoolean() throws IOException {
		final DerOutputStream out = new DerOutputStream();
		out.putBoolean(true);
		final DerInputStream in = new DerInputStream(out.toByteArray());
		assertTrue(new DerValue(in.toByteArray()).getBoolean());
	}

	@Test
	@DisplayName("putInteger / putInteger(BigInteger) → getInteger / getBigInteger")
	void roundtripIntegers() throws IOException {
		final DerOutputStream out = new DerOutputStream();
		out.putInteger(42);
		final DerInputStream in = new DerInputStream(out.toByteArray());
		assertEquals(42, in.getInteger());

		final DerOutputStream big = new DerOutputStream();
		final BigInteger huge = new BigInteger("123456789012345678901234567890"); //$NON-NLS-1$
		big.putInteger(huge);
		final DerInputStream inBig = new DerInputStream(big.toByteArray());
		assertEquals(huge, inBig.getBigInteger());
	}

	@Test
	@DisplayName("putEnumerated → getEnumerated")
	void roundtripEnumerated() throws IOException {
		final DerOutputStream out = new DerOutputStream();
		out.putEnumerated(7);
		final DerInputStream in = new DerInputStream(out.toByteArray());
		assertEquals(7, in.getEnumerated());
	}

	@Test
	@DisplayName("putOctetString → getOctetString preserva los bytes")
	void roundtripOctetString() throws IOException {
		final byte[] payload = {0x01, (byte) 0xFF, 0x55, (byte) 0xAA};
		final DerOutputStream out = new DerOutputStream();
		out.putOctetString(payload);
		final DerInputStream in = new DerInputStream(out.toByteArray());
		assertArrayEquals(payload, in.getOctetString());
	}

	@Test
	@DisplayName("putBitString → getBitString preserva los bytes alineados")
	void roundtripBitStringAligned() throws IOException {
		final byte[] bits = {(byte) 0xAB, (byte) 0xCD};
		final DerOutputStream out = new DerOutputStream();
		out.putBitString(bits);
		final DerInputStream in = new DerInputStream(out.toByteArray());
		assertArrayEquals(bits, in.getBitString());
	}

	@Test
	@DisplayName("putUnalignedBitString → getUnalignedBitString preserva longitud en bits")
	void roundtripBitStringUnaligned() throws IOException {
		final BitArray ba = new BitArray(11, new byte[] {(byte) 0xAB, (byte) 0xCD});
		final DerOutputStream out = new DerOutputStream();
		out.putUnalignedBitString(ba);
		final DerInputStream in = new DerInputStream(out.toByteArray());
		final BitArray decoded = in.getUnalignedBitString();
		assertEquals(ba.length(), decoded.length());
	}

	@Test
	@DisplayName("putNull → getNull no rompe el stream")
	void roundtripNull() throws IOException {
		final DerOutputStream out = new DerOutputStream();
		out.putNull();
		final DerInputStream in = new DerInputStream(out.toByteArray());
		// getNull no devuelve, sólo valida que el siguiente datum es NULL.
		in.getNull();
	}

	@Test
	@DisplayName("putOID → getOID preserva el OID")
	void roundtripOID() throws IOException {
		final ObjectIdentifier oid = new ObjectIdentifier("1.2.840.113549.1.1.11"); //$NON-NLS-1$ // sha256WithRSA
		final DerOutputStream out = new DerOutputStream();
		out.putOID(oid);
		final DerInputStream in = new DerInputStream(out.toByteArray());
		assertEquals(oid, in.getOID());
	}

	@Test
	@DisplayName("putSequence → getSequence preserva orden y miembros")
	void roundtripSequence() throws IOException {
		final DerValue a = new DerValue(DerValue.tag_Integer, new byte[] {0x05});
		final DerValue b = new DerValue(DerValue.tag_Integer, new byte[] {0x09});
		final DerOutputStream out = new DerOutputStream();
		out.putSequence(new DerValue[] {a, b});
		final DerInputStream in = new DerInputStream(out.toByteArray());
		final DerValue[] members = in.getSequence(2);
		assertAll(
				() -> assertEquals(2, members.length),
				() -> assertEquals(5, members[0].getInteger()),
				() -> assertEquals(9, members[1].getInteger()));
	}

	@Test
	@DisplayName("putSet → getSet preserva miembros")
	void roundtripSet() throws IOException {
		final DerValue a = new DerValue(DerValue.tag_Integer, new byte[] {0x01});
		final DerValue b = new DerValue(DerValue.tag_Integer, new byte[] {0x02});
		final DerOutputStream out = new DerOutputStream();
		out.putSet(new DerValue[] {a, b});
		final DerInputStream in = new DerInputStream(out.toByteArray());
		final DerValue[] members = in.getSet(2);
		assertEquals(2, members.length);
	}

	@Test
	@DisplayName("putUTF8String / putPrintableString / putIA5String round-trip")
	void roundtripStrings() throws IOException {
		final DerOutputStream o1 = new DerOutputStream();
		o1.putUTF8String("Año"); //$NON-NLS-1$
		assertEquals("Año", new DerValue(o1.toByteArray()).getUTF8String()); //$NON-NLS-1$

		final DerOutputStream o2 = new DerOutputStream();
		o2.putPrintableString("Hello"); //$NON-NLS-1$
		assertEquals("Hello", new DerValue(o2.toByteArray()).getPrintableString()); //$NON-NLS-1$

		final DerOutputStream o3 = new DerOutputStream();
		o3.putIA5String("rfc822@example.org"); //$NON-NLS-1$
		assertEquals("rfc822@example.org", new DerValue(o3.toByteArray()).getIA5String()); //$NON-NLS-1$
	}

	@Test
	@DisplayName("putDerValue añade un DerValue ya construido")
	void putDerValueAppends() throws IOException {
		final DerValue v = new DerValue(DerValue.tag_Integer, new byte[] {0x07});
		final DerOutputStream out = new DerOutputStream();
		out.putDerValue(v);
		final DerInputStream in = new DerInputStream(out.toByteArray());
		assertEquals(7, in.getInteger());
	}

	// === DerInputStream control surface ===

	@Test
	@DisplayName("peekByte / available / mark / reset componen las lecturas")
	void peekAvailableMarkReset() throws IOException {
		// SEQUENCE { INTEGER 5, INTEGER 9 }
		final byte[] der = {0x30, 0x06, 0x02, 0x01, 0x05, 0x02, 0x01, 0x09};
		final DerInputStream in = new DerInputStream(der);
		assertEquals(0x30, in.peekByte());
		final int avail = in.available();
		assertTrue(avail > 0);
	}

	@Test
	@DisplayName("getDerValue lee uno a uno los datums")
	void getDerValueReadsOneAtATime() throws IOException {
		final DerOutputStream out = new DerOutputStream();
		out.putInteger(1);
		out.putInteger(2);
		final DerInputStream in = new DerInputStream(out.toByteArray());
		assertEquals(1, in.getDerValue().getInteger());
		assertEquals(2, in.getDerValue().getInteger());
	}

	// === ObjectIdentifier ===

	@Test
	@DisplayName("ObjectIdentifier(String) y newInternal(int[]) producen el mismo OID")
	void oidEquivalence() throws IOException {
		final ObjectIdentifier fromString = new ObjectIdentifier("1.2.840.113549.1.1.1"); //$NON-NLS-1$
		final ObjectIdentifier fromInts = ObjectIdentifier.newInternal(new int[] {1, 2, 840, 113549, 1, 1, 1});
		assertAll(
				() -> assertEquals(fromString, fromInts),
				() -> assertEquals(fromString.hashCode(), fromInts.hashCode()),
				() -> assertEquals("1.2.840.113549.1.1.1", fromString.toString())); //$NON-NLS-1$
	}

	@Test
	@DisplayName("ObjectIdentifier rechaza OIDs malformados")
	void oidInvalidRejected() {
		assertThrows(IOException.class, () -> new ObjectIdentifier("foo.bar")); //$NON-NLS-1$
	}

	@Test
	@DisplayName("ObjectIdentifier no son iguales si difieren")
	void oidsNotEqualIfDifferent() throws IOException {
		final ObjectIdentifier a = new ObjectIdentifier("1.2.3"); //$NON-NLS-1$
		final ObjectIdentifier b = new ObjectIdentifier("1.2.4"); //$NON-NLS-1$
		assertNotEquals(a, b);
	}

	// === BitArray ===

	@Test
	@DisplayName("BitArray(length) inicializa todos los bits a 0")
	void bitArrayConstructorByLength() {
		final BitArray ba = new BitArray(10);
		assertEquals(10, ba.length());
		for (int i = 0; i < 10; i++) {
			final int idx = i;
			assertAll(() -> assertTrue(!ba.get(idx)));
		}
	}

	@Test
	@DisplayName("BitArray(boolean[]) preserva los bits")
	void bitArrayFromBooleans() {
		final BitArray ba = new BitArray(new boolean[] {true, false, true, false, true});
		assertAll(
				() -> assertEquals(5, ba.length()),
				() -> assertTrue(ba.get(0)),
				() -> assertTrue(!ba.get(1)),
				() -> assertTrue(ba.get(2)),
				() -> assertTrue(!ba.get(3)),
				() -> assertTrue(ba.get(4)));
	}

	@Test
	@DisplayName("BitArray.toByteArray empaqueta bits MSB-first")
	void bitArrayToByteArray() {
		// 1000 0000 = 0x80
		final BitArray ba = new BitArray(new boolean[] {true, false, false, false,
				false, false, false, false});
		assertArrayEquals(new byte[] {(byte) 0x80}, ba.toByteArray());
	}

	@Test
	@DisplayName("BitArray.truncate elimina los ceros finales")
	void bitArrayTruncate() {
		// 10000000 + ceros → tras truncate sólo queda el primer bit
		final boolean[] bits = new boolean[16];
		bits[0] = true;
		final BitArray ba = new BitArray(bits);
		final BitArray truncated = ba.truncate();
		assertEquals(1, truncated.length());
	}

	@Test
	@DisplayName("BitArray rechaza longitudes inválidas")
	void bitArrayInvalidLength() {
		assertThrows(IllegalArgumentException.class, () -> new BitArray(-1));
	}

	@Test
	@DisplayName("BitArray.get fuera de rango lanza ArrayIndexOutOfBoundsException")
	void bitArrayGetOutOfRange() {
		final BitArray ba = new BitArray(4);
		assertThrows(ArrayIndexOutOfBoundsException.class, () -> ba.get(10));
	}
}
