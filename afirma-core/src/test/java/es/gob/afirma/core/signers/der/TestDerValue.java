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
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.math.BigInteger;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * Red de regresi&oacute;n para {@link DerValue} antes de la migraci&oacute;n
 * a {@code org.bouncycastle.asn1.*} (Fase F del plan Clean Code).
 *
 * <p>Bloquea el comportamiento observable de los constructores y de cada
 * accesor {@code getXxx()} con datos DER conocidos. La suite de tests acaba
 * pasando contra la nueva implementaci&oacute;n basada en BouncyCastle, lo
 * que demuestra equivalencia funcional.</p>
 */
class TestDerValue {

	// === Constructores ===

	@Test
	@DisplayName("DerValue(byte tag, byte[] data) preserva tag y longitud")
	void rawConstructor() {
		final byte[] payload = {0x12, 0x34, 0x56};
		final DerValue v = new DerValue(DerValue.tag_OctetString, payload);
		assertAll(
				() -> assertEquals(DerValue.tag_OctetString, v.tag),
				() -> assertEquals(payload.length, v.length()));
	}

	@Test
	@DisplayName("DerValue(String) selecciona PrintableString para ASCII imprimible")
	void stringConstructorPrintable() throws IOException {
		final DerValue v = new DerValue("Hello"); //$NON-NLS-1$
		assertEquals(DerValue.tag_PrintableString, v.tag);
		assertEquals("Hello", v.getPrintableString()); //$NON-NLS-1$
	}

	@Test
	@DisplayName("DerValue(String) selecciona UTF8String para caracteres no imprimibles")
	void stringConstructorUtf8() throws IOException {
		final DerValue v = new DerValue("Año"); //$NON-NLS-1$
		assertEquals(DerValue.tag_UTF8String, v.tag);
		assertEquals("Año", v.getUTF8String()); //$NON-NLS-1$
	}

	@Test
	@DisplayName("DerValue(byte stringTag, String) usa el tag explícito")
	void stringConstructorWithExplicitTag() throws IOException {
		final DerValue v = new DerValue(DerValue.tag_IA5String, "test@example.com"); //$NON-NLS-1$
		assertEquals(DerValue.tag_IA5String, v.tag);
		assertEquals("test@example.com", v.getIA5String()); //$NON-NLS-1$
	}

	@Test
	@DisplayName("DerValue(byte[]) parsea un INTEGER DER")
	void byteArrayConstructorInteger() throws IOException {
		// INTEGER 42: tag=0x02 len=0x01 value=0x2A
		final byte[] der = {0x02, 0x01, 0x2A};
		final DerValue v = new DerValue(der);
		assertEquals(DerValue.tag_Integer, v.tag);
		assertEquals(42, v.getInteger());
	}

	@Test
	@DisplayName("DerValue(byte[], offset, len) lee solo el rango indicado")
	void byteArrayWithOffset() throws IOException {
		// INTEGER 7 precedido y seguido de basura
		final byte[] noise = {(byte) 0xFF, 0x02, 0x01, 0x07, (byte) 0xEE};
		final DerValue v = new DerValue(noise, 1, 3);
		assertEquals(7, v.getInteger());
	}

	@Test
	@DisplayName("DerValue(InputStream) consume un único datum y deja el resto")
	void inputStreamConstructorOne() throws IOException {
		final byte[] der = {0x02, 0x01, 0x05, 0x02, 0x01, 0x09};
		final ByteArrayInputStream is = new ByteArrayInputStream(der);
		final DerValue first = new DerValue(is);
		assertEquals(5, first.getInteger());
		assertEquals(3, is.available());
	}

	@Test
	@DisplayName("DerValue(byte[]) lanza IOException con datos malformados")
	void invalidDerThrows() {
		// Tag presente pero longitud declarada mayor que datos disponibles
		final byte[] bad = {0x02, 0x05, 0x01};
		assertThrows(IOException.class, () -> new DerValue(bad));
	}

	// === Inspección de tag ===

	@Test
	@DisplayName("isUniversal/isApplication/isContextSpecific clasifican según los bits 7-6")
	void tagClassInspection() {
		assertAll(
				() -> assertTrue(new DerValue(DerValue.tag_Integer, new byte[] {0x01}).isUniversal()),
				() -> assertTrue(new DerValue((byte) 0x80, new byte[] {0x01}).isContextSpecific()),
				() -> assertTrue(new DerValue((byte) 0x40, new byte[] {0x01}).isApplication()),
				() -> assertFalse(new DerValue(DerValue.tag_Integer, new byte[] {0x01}).isContextSpecific()));
	}

	@Test
	@DisplayName("isContextSpecific(byte) compara con el sub-tag concreto")
	void contextSpecificSubTag() {
		final DerValue v = new DerValue((byte) 0xA3, new byte[] {0x01}); // [3]
		assertTrue(v.isContextSpecific((byte) 0x03));
		assertFalse(v.isContextSpecific((byte) 0x04));
	}

	@Test
	@DisplayName("isConstructed detecta el bit 5")
	void constructedFlag() {
		assertTrue(new DerValue(DerValue.tag_Sequence, new byte[] {0x05, 0x00}).isConstructed());
		assertFalse(new DerValue(DerValue.tag_Integer, new byte[] {0x01}).isConstructed());
	}

	// === Accesores ===

	@Test
	@DisplayName("getBoolean reconoce 0xFF como TRUE y 0x00 como FALSE")
	void booleanAccessor() throws IOException {
		final DerValue tru = new DerValue(new byte[] {0x01, 0x01, (byte) 0xFF});
		final DerValue fal = new DerValue(new byte[] {0x01, 0x01, 0x00});
		assertAll(
				() -> assertTrue(tru.getBoolean()),
				() -> assertFalse(fal.getBoolean()));
	}

	@Test
	@DisplayName("getInteger / getBigInteger devuelven el valor numérico")
	void integerAccessors() throws IOException {
		final DerValue v = new DerValue(new byte[] {0x02, 0x02, 0x01, 0x00}); // 256
		assertAll(
				() -> assertEquals(256, v.getInteger()),
				() -> assertEquals(BigInteger.valueOf(256),
						new DerValue(new byte[] {0x02, 0x02, 0x01, 0x00}).getBigInteger()));
	}

	@Test
	@DisplayName("getEnumerated lee el valor de un ENUMERATED")
	void enumeratedAccessor() throws IOException {
		final DerValue v = new DerValue(new byte[] {0x0A, 0x01, 0x03});
		assertEquals(3, v.getEnumerated());
	}

	@Test
	@DisplayName("getOctetString devuelve los bytes intactos")
	void octetStringAccessor() throws IOException {
		final byte[] octets = {(byte) 0xCA, (byte) 0xFE, (byte) 0xBA, (byte) 0xBE};
		final DerValue v = new DerValue(DerValue.tag_OctetString, octets);
		assertArrayEquals(octets, v.getOctetString());
	}

	@Test
	@DisplayName("getOID devuelve un ObjectIdentifier comparable por toString()")
	void oidAccessor() throws IOException {
		// OID 1.2.840.113549.1.1.1 (rsaEncryption): tag 0x06 len 0x09
		final byte[] der = {0x06, 0x09,
				0x2A, (byte) 0x86, 0x48, (byte) 0x86, (byte) 0xF7, 0x0D, 0x01, 0x01, 0x01};
		final DerValue v = new DerValue(der);
		assertEquals("1.2.840.113549.1.1.1", v.getOID().toString()); //$NON-NLS-1$
	}

	@Test
	@DisplayName("getBitString preserva los bits no relleno")
	void bitStringAccessor() throws IOException {
		// BIT STRING con 0 bits sin usar y 2 bytes
		final byte[] der = {0x03, 0x03, 0x00, (byte) 0xCA, (byte) 0xFE};
		final byte[] bits = new DerValue(der).getBitString();
		assertArrayEquals(new byte[] {(byte) 0xCA, (byte) 0xFE}, bits);
	}

	@Test
	@DisplayName("getUnalignedBitString conserva la longitud en bits")
	void unalignedBitStringAccessor() throws IOException {
		// 1 bit sin usar, 1 byte → 7 bits útiles
		final byte[] der = {0x03, 0x02, 0x01, (byte) 0x80};
		final BitArray ba = new DerValue(der).getUnalignedBitString();
		assertEquals(7, ba.length());
	}

	@Test
	@DisplayName("getUTF8String lee texto UTF-8 con caracteres no ASCII")
	void utf8Accessor() throws IOException {
		final DerValue v = new DerValue(DerValue.tag_UTF8String, "Año".getBytes("UTF-8")); //$NON-NLS-1$ //$NON-NLS-2$
		assertEquals("Año", v.getUTF8String()); //$NON-NLS-1$
	}

	@Test
	@DisplayName("getIA5String lee ASCII puro")
	void ia5Accessor() throws IOException {
		final DerValue v = new DerValue(DerValue.tag_IA5String, "rfc822@example.org".getBytes("US-ASCII")); //$NON-NLS-1$ //$NON-NLS-2$
		assertEquals("rfc822@example.org", v.getIA5String()); //$NON-NLS-1$
	}

	// === Encode round-trip + length + reset ===

	@Test
	@DisplayName("encode + DerValue(byte[]) reproduce el datum original")
	void encodeRoundtrip() throws IOException {
		final DerValue original = new DerValue(new byte[] {0x02, 0x02, 0x01, 0x00});
		final DerOutputStream out = new DerOutputStream();
		original.encode(out);
		final DerValue parsed = new DerValue(out.toByteArray());
		assertEquals(original, parsed);
	}

	@Test
	@DisplayName("length() reporta la longitud del payload sin tag/length-bytes")
	void lengthReturnsPayloadOnly() {
		final DerValue v = new DerValue(DerValue.tag_OctetString, new byte[] {0x01, 0x02, 0x03});
		assertEquals(3, v.length());
	}

	@Test
	@DisplayName("resetTag cambia el tag observable")
	void resetTagMutates() {
		final DerValue v = new DerValue(DerValue.tag_OctetString, new byte[] {0x01});
		v.resetTag(DerValue.tag_BitString);
		assertEquals(DerValue.tag_BitString, v.tag);
	}

	@Test
	@DisplayName("equals/hashCode son consistentes para mismos contenidos")
	void equalsAndHashCode() throws IOException {
		final DerValue a = new DerValue(new byte[] {0x02, 0x01, 0x07});
		final DerValue b = new DerValue(new byte[] {0x02, 0x01, 0x07});
		final DerValue c = new DerValue(new byte[] {0x02, 0x01, 0x08});
		assertAll(
				() -> assertEquals(a, b),
				() -> assertEquals(a.hashCode(), b.hashCode()),
				() -> assertNotEquals(a, c));
	}

	@Test
	@DisplayName("toString no falla en datums comunes")
	void toStringSmokeTest() {
		final DerValue v = new DerValue(DerValue.tag_OctetString, new byte[] {0x01, 0x02});
		assertTrue(v.toString().length() > 0);
	}

	@Test
	@DisplayName("toDerInputStream sólo acepta SEQUENCE/SET y devuelve sus miembros")
	void toDerInputStreamOnlySeqOrSet() throws IOException {
		// SEQUENCE { INTEGER 5, INTEGER 9 }
		final byte[] der = {0x30, 0x06, 0x02, 0x01, 0x05, 0x02, 0x01, 0x09};
		final DerValue seq = new DerValue(der);
		final DerInputStream members = seq.toDerInputStream();
		// Primer miembro = INTEGER 5
		assertEquals(5, members.getInteger());
		// Segundo miembro = INTEGER 9
		assertEquals(9, members.getInteger());
		// Llamarlo sobre un INTEGER plano debe rechazar.
		final DerValue plain = new DerValue(new byte[] {0x02, 0x01, 0x05});
		assertThrows(IOException.class, plain::toDerInputStream);
	}
}
