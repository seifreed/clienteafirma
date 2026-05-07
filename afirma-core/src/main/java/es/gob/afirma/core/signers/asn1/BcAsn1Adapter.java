/* Copyright (C) 2011 [Gobierno de Espana]
 * This file is part of "Cliente @Firma".
 * "Cliente @Firma" is free software; you can redistribute it and/or modify it under the terms of:
 *   - the GNU General Public License as published by the Free Software Foundation;
 *     either version 2 of the License, or (at your option) any later version.
 *   - or The European Software License; either version 1.1 or (at your option) any later version.
 * You may contact the copyright holder at: soporte.afirma@seap.minhap.es
 */

package es.gob.afirma.core.signers.asn1;

import java.io.IOException;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;

/**
 * Adaptador que envuelve los patrones m&aacute;s comunes de la API
 * {@code org.bouncycastle.asn1.*}.
 *
 * <p>Origen hist&oacute;rico: este helper naci&oacute; para puentear la
 * migraci&oacute;n desde el fork Oracle {@code DerValue} (paquete
 * {@code es.gob.afirma.core.signers.der}, eliminado en Fase F.3 del plan
 * Clean Code) hacia BouncyCastle ASN.1. Una vez completada la migraci&oacute;n
 * el helper se conserva por su valor pedag&oacute;gico (la tabla de mapping
 * sigue documentando c&oacute;mo se traducen los patrones legacy) y por la
 * concisi&oacute;n que aporta a los call sites — una sola llamada en lugar
 * de cuatro l&iacute;neas de {@code ASN1InputStream}/{@code ASN1OutputStream}.</p>
 *
 * <h2>Mapping legacy {@code DerValue} → BouncyCastle (referencia)</h2>
 *
 * <table border="1">
 *   <caption>Equivalencias funcionales (paquete legacy &rarr; BouncyCastle)</caption>
 *   <tr><th>Legacy</th><th>BouncyCastle</th></tr>
 *   <tr><td>{@code new DerValue(byte[] enc)}</td>
 *       <td>{@link ASN1Primitive#fromByteArray(byte[]) ASN1Primitive.fromByteArray(enc)}</td></tr>
 *   <tr><td>{@code new DerInputStream(byte[])}</td>
 *       <td>{@link ASN1InputStream}</td></tr>
 *   <tr><td>{@code new DerOutputStream(); out.putXxx(...)}</td>
 *       <td>{@link DERSequence}/{@link DEROctetString}/{@link ASN1Integer} +
 *           {@link ASN1Encodable#toASN1Primitive()}.{@link ASN1Primitive#getEncoded(String)
 *           getEncoded(ASN1Encoding.DER)}</td></tr>
 *   <tr><td>{@code DerValue.getInteger()}</td>
 *       <td>{@code ASN1Integer.getInstance(prim).getValue().intValue()}</td></tr>
 *   <tr><td>{@code DerValue.getBigInteger()}</td>
 *       <td>{@code ASN1Integer.getInstance(prim).getValue()}</td></tr>
 *   <tr><td>{@code DerValue.getPositiveBigInteger()}</td>
 *       <td>{@code ASN1Integer.getInstance(prim).getPositiveValue()}</td></tr>
 *   <tr><td>{@code DerValue.getOctetString()}</td>
 *       <td>{@code ASN1OctetString.getInstance(prim).getOctets()}</td></tr>
 *   <tr><td>{@code DerValue.getOID()}</td>
 *       <td>{@code ASN1ObjectIdentifier.getInstance(prim).getId()}</td></tr>
 *   <tr><td>{@code in.getSequence(n)}</td>
 *       <td>{@code ASN1Sequence.getInstance(prim)} (size se valida via
 *           {@code seq.size()})</td></tr>
 *   <tr><td>{@code DerValue(tag_Sequence, out.toByteArray())}</td>
 *       <td>{@code new DERSequence(items)}</td></tr>
 *   <tr><td>{@code DerValue(tag_OctetString, octets)}</td>
 *       <td>{@code new DEROctetString(octets)}</td></tr>
 * </table>
 *
 * <h2>Helpers de migraci&oacute;n</h2>
 *
 * <p>Los m&eacute;todos est&aacute;ticos de esta clase capturan los patrones
 * que aparecen repetidos en consumidores como {@code Pkcs1Utils}: encode /
 * decode de {@code SEQUENCE OF INTEGER}, OCTET STRING y OID. As&iacute;
 * el call site queda con una sola llamada en lugar de cuatro l&iacute;neas
 * de {@code ASN1InputStream + ASN1OutputStream}.</p>
 *
 * <p>El plan F del refactor Clean Code elimina el fork Oracle DerValue una
 * vez todos los call sites han migrado a este adaptador o directamente a la
 * API BC. Este helper existe como puente para hacer la migraci&oacute;n
 * incremental, no como wrapper permanente.</p>
 */
public final class BcAsn1Adapter {

	private BcAsn1Adapter() {
		// Utilidad estática.
	}

	/**
	 * Codifica una secuencia de {@link BigInteger} como
	 * {@code SEQUENCE OF INTEGER} en codificaci&oacute;n DER.
	 *
	 * <p>Patr&oacute;n usado por las firmas ECDSA al construir la concatenaci&oacute;n
	 * (R, S) en formato DER.</p>
	 *
	 * @param values Enteros a codificar.
	 * @return Codificaci&oacute;n DER de la secuencia.
	 * @throws IOException Si BouncyCastle falla al codificar.
	 */
	public static byte[] encodeSequenceOfIntegers(final BigInteger... values) throws IOException {
		final ASN1Encodable[] items = new ASN1Encodable[values.length];
		for (int i = 0; i < values.length; i++) {
			items[i] = new ASN1Integer(values[i]);
		}
		return new DERSequence(items).getEncoded(ASN1Encoding.DER);
	}

	/**
	 * Decodifica un {@code SEQUENCE OF INTEGER} en DER y devuelve los
	 * enteros como {@link BigInteger}, validando el tama&ntilde;o esperado.
	 *
	 * @param der Codificaci&oacute;n DER de la secuencia.
	 * @param expectedCount Tama&ntilde;o esperado (lanza {@link IOException}
	 *   si difiere o si quedan bytes sin consumir).
	 * @return Array de enteros con la longitud {@code expectedCount}.
	 * @throws IOException Si los datos no son una secuencia DER, el tama&ntilde;o
	 *   no coincide o hay basura tras el SEQUENCE.
	 */
	public static BigInteger[] decodeSequenceOfIntegers(final byte[] der, final int expectedCount)
			throws IOException {

		try (final ASN1InputStream ais = new ASN1InputStream(der)) {
			final ASN1Primitive prim = ais.readObject();
			if (prim == null) {
				throw new IOException("Codificación DER vacía"); //$NON-NLS-1$
			}
			if (ais.readObject() != null) {
				throw new IOException("Datos sobrantes tras la SEQUENCE DER"); //$NON-NLS-1$
			}
			final ASN1Sequence seq = ASN1Sequence.getInstance(prim);
			if (seq.size() != expectedCount) {
				throw new IOException(
						"La SEQUENCE tiene " + seq.size() + " elementos en lugar de los " //$NON-NLS-1$ //$NON-NLS-2$
								+ expectedCount + " esperados"); //$NON-NLS-1$
			}
			final BigInteger[] result = new BigInteger[expectedCount];
			for (int i = 0; i < expectedCount; i++) {
				result[i] = ASN1Integer.getInstance(seq.getObjectAt(i)).getValue();
			}
			return result;
		}
	}

	/**
	 * Codifica un array de bytes como {@code OCTET STRING} DER.
	 *
	 * @param octets Bytes a envolver.
	 * @return Codificaci&oacute;n DER del OCTET STRING.
	 * @throws IOException Si BouncyCastle falla al codificar.
	 */
	public static byte[] encodeOctetString(final byte[] octets) throws IOException {
		return new DEROctetString(octets).getEncoded(ASN1Encoding.DER);
	}

	/**
	 * Extrae el contenido de un {@code OCTET STRING} DER.
	 *
	 * @param der Codificaci&oacute;n DER.
	 * @return Bytes del OCTET STRING (sin tag ni longitud).
	 * @throws IOException Si los datos no son un OCTET STRING DER v&aacute;lido.
	 */
	public static byte[] getOctetStringContent(final byte[] der) throws IOException {
		try (final ASN1InputStream ais = new ASN1InputStream(der)) {
			final ASN1Primitive prim = ais.readObject();
			return ASN1OctetString.getInstance(prim).getOctets();
		}
	}

	/**
	 * Codifica un OID en su representaci&oacute;n DER. La cadena debe seguir
	 * la sintaxis de ITU X.660 (n&uacute;meros separados por puntos, primer
	 * arco 0/1/2, segundo arco &le;39 si el primero es 0/1).
	 *
	 * @param oid Representaci&oacute;n textual del OID (e.g. {@code 1.2.840.113549.1.1.1}).
	 * @return Codificaci&oacute;n DER del OID.
	 * @throws IOException Si BouncyCastle falla al codificar.
	 */
	public static byte[] encodeOid(final String oid) throws IOException {
		return new ASN1ObjectIdentifier(oid).getEncoded(ASN1Encoding.DER);
	}

	/**
	 * Decodifica un OID DER y lo devuelve como cadena {@code 1.2.3...}.
	 *
	 * @param der Codificaci&oacute;n DER del OID.
	 * @return Representaci&oacute;n textual del OID.
	 * @throws IOException Si los datos no son un OID DER v&aacute;lido.
	 */
	public static String decodeOid(final byte[] der) throws IOException {
		try (final ASN1InputStream ais = new ASN1InputStream(der)) {
			final ASN1Primitive prim = ais.readObject();
			return ASN1ObjectIdentifier.getInstance(prim).getId();
		}
	}

	/**
	 * Codifica un {@link BigInteger} como {@code INTEGER} DER.
	 *
	 * @param value Entero a codificar.
	 * @return Codificaci&oacute;n DER del INTEGER.
	 * @throws IOException Si BouncyCastle falla al codificar.
	 */
	public static byte[] encodeInteger(final BigInteger value) throws IOException {
		return new ASN1Integer(value).getEncoded(ASN1Encoding.DER);
	}

	/**
	 * Decodifica un {@code INTEGER} DER como {@link BigInteger}.
	 *
	 * @param der Codificaci&oacute;n DER.
	 * @return Valor del INTEGER.
	 * @throws IOException Si los datos no son un INTEGER DER v&aacute;lido.
	 */
	public static BigInteger decodeInteger(final byte[] der) throws IOException {
		try (final ASN1InputStream ais = new ASN1InputStream(der)) {
			final ASN1Primitive prim = ais.readObject();
			return ASN1Integer.getInstance(prim).getValue();
		}
	}

	/**
	 * Itera sobre los elementos de un {@code SEQUENCE} DER y los devuelve
	 * como {@link ASN1Primitive} para que el caller los proyecte al tipo
	 * concreto.
	 *
	 * <p>Esto sustituye el patr&oacute;n
	 * {@code DerInputStream.getSequence(int)} cuando los miembros son de
	 * tipos heterog&eacute;neos.</p>
	 *
	 * @param der Codificaci&oacute;n DER del SEQUENCE.
	 * @return Lista de primitives en el orden del SEQUENCE.
	 * @throws IOException Si los datos no son un SEQUENCE DER v&aacute;lido.
	 */
	public static List<ASN1Primitive> readSequenceMembers(final byte[] der) throws IOException {
		try (final ASN1InputStream ais = new ASN1InputStream(der)) {
			final ASN1Primitive prim = ais.readObject();
			final ASN1Sequence seq = ASN1Sequence.getInstance(prim);
			final List<ASN1Primitive> members = new ArrayList<>(seq.size());
			for (int i = 0; i < seq.size(); i++) {
				members.add(seq.getObjectAt(i).toASN1Primitive());
			}
			return members;
		}
	}
}
