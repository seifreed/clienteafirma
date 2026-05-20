/* Copyright (C) 2011 [Gobierno de Espana]
 * This file is part of "Cliente @Firma".
 * "Cliente @Firma" is free software; you can redistribute it and/or modify it under the terms of:
 *   - the GNU General Public License as published by the Free Software Foundation;
 *     either version 2 of the License, or (at your option) any later version.
 *   - or The European Software License; either version 1.1 or (at your option) any later version.
 * You may contact the copyright holder at: soporte.afirma@seap.minhap.es
 */

package es.gob.afirma.signers.padestri.client;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.InputStream;
import java.security.KeyStore;
import java.security.KeyStore.PrivateKeyEntry;
import java.util.Properties;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfSystemProperty;

import es.gob.afirma.core.misc.AOUtil;
import es.gob.afirma.core.misc.Base64;
import es.gob.afirma.core.signers.AOSigner;
import es.gob.afirma.signers.pades.common.BadPdfPasswordException;
import es.gob.afirma.signers.pades.common.PdfExtraParams;
import es.gob.afirma.signers.pades.common.PdfIsCertifiedException;
import es.gob.afirma.signers.pades.common.PdfIsPasswordProtectedException;

/** Pruebas de firma PAdES trif&aacute;sica end-to-end contra el WAR
 * {@code afirma-server-triphase-signer}.
 *
 * <p>{@link #testFormat} se ejecuta siempre (s&oacute;lo lee el PDF de fixture).
 * Todos los dem&aacute;s tests requieren un servidor triphase corriendo y van
 * gateados por {@code afirma.it.triphase.pades=true}; sin la propiedad, los
 * tests se omiten — no se mockean — conforme a la pol&iacute;tica "No mocks
 * (mandatory)" del CLAUDE.md.
 *
 * <p>Para apuntar a otro servidor:
 * {@code -Dafirma.it.triphase.pades.url=https://miservidor/.../SignatureService}. */
final class TestPdfTriphase {

	private static final String DEFAULT_SERVER_URL = "http://localhost:8080/afirma-server-triphase-signer/SignatureService"; //$NON-NLS-1$
	private static final String PROPERTY_SIGN_SERVER_URL = "serverUrl"; //$NON-NLS-1$
	private static final String PROPERTY_DOC_ID = "documentId"; //$NON-NLS-1$
	private static final String SIGN_ALGO = "SHA512withRSA"; //$NON-NLS-1$

	private static final String PDF_FILENAME = "TEST_PDF.pdf"; //$NON-NLS-1$
	private static final String PDF_WITH_PASSWORD_FILENAME = "TEST_PDF_Password.pdf"; //$NON-NLS-1$
	private static final String PDF_CERTIFIED_TYPE1_FILENAME = "TEST_PDF_Certified_Type1.pdf"; //$NON-NLS-1$
	private static final String TEST_IMAGE_FILE = "splash.png"; //$NON-NLS-1$

	private static final String PROPERTY_ATTACH = "attach"; //$NON-NLS-1$
	private static final String PROPERTY_ATTACH_FILENAME = "attachFileName"; //$NON-NLS-1$
	private static final String PROPERTY_ATTACH_DESCRIPTION = "attachDescription"; //$NON-NLS-1$

    private static final String CERT_PATH = "PFActivoFirSHA256.pfx"; //$NON-NLS-1$
    private static final String CERT_PASS = "12341234"; //$NON-NLS-1$
    private static final String CERT_ALIAS = "fisico activo prueba"; //$NON-NLS-1$

	private static final String CERT_PATH_2 = "ANF PJURIDICA ACTIVO.pfx"; //$NON-NLS-1$
	private static final String CERT_PASS_2 = "12341234"; //$NON-NLS-1$
	private static final String CERT_ALIAS_2 = "anf usuario activo"; //$NON-NLS-1$

	private PrivateKeyEntry pke;
	private PrivateKeyEntry pke2;
	private Properties serverConfig;
	private byte[] data;
	private byte[] certifiedType1Pdf;
	private byte[] protectedData;

	/** Carga los almacenes de prueba, los PDFs fixture y la URL del servidor.
	 * @throws Exception En cualquier error. */
	@BeforeEach
	void init() throws Exception {
		this.pke = loadKeyEntry(CERT_PATH, CERT_PASS, CERT_ALIAS);
		this.pke2 = loadKeyEntry(CERT_PATH_2, CERT_PASS_2, CERT_ALIAS_2);

		final String url = System.getProperty("afirma.it.triphase.pades.url", DEFAULT_SERVER_URL); //$NON-NLS-1$
		this.serverConfig = new Properties();
		this.serverConfig.setProperty(PROPERTY_SIGN_SERVER_URL, url);

		this.data = loadFile(PDF_FILENAME);
		this.protectedData = loadFile(PDF_WITH_PASSWORD_FILENAME);
		this.certifiedType1Pdf = loadFile(PDF_CERTIFIED_TYPE1_FILENAME);
	}

	private static PrivateKeyEntry loadKeyEntry(final String path, final String pass, final String alias) throws Exception {
		final KeyStore ks = KeyStore.getInstance("PKCS12"); //$NON-NLS-1$
		try (final InputStream is = ClassLoader.getSystemResourceAsStream(path)) {
			ks.load(is, pass.toCharArray());
		}
		return (PrivateKeyEntry) ks.getEntry(alias, new KeyStore.PasswordProtection(pass.toCharArray()));
	}

	private static byte[] loadFile(final String filename) throws Exception {
		try (final InputStream is = ClassLoader.getSystemResourceAsStream(filename)) {
			return AOUtil.getDataFromInputStream(is);
		}
	}

	private static String loadFileOnBase64(final String filename) throws Exception {
		return Base64.encode(loadFile(filename), true);
	}

	private Properties freshServerConfig() {
		final Properties config = new Properties();
		config.putAll(this.serverConfig);
		return config;
	}

	/** Prueba de validaci&oacute;n de formato — corre sin servidor, sobre fixture local. */
	@Test
	void testFormat() throws Exception {
		assertTrue(
			new AOPDFTriPhaseSigner().isValidDataFile(
				AOUtil.getDataFromInputStream(TestPdfTriphase.class.getResourceAsStream("/" + PDF_FILENAME)) //$NON-NLS-1$
			)
		);
	}

	/** Prueba de firma trif&aacute;sica normal. */
	@Test
	@EnabledIfSystemProperty(named = "afirma.it.triphase.pades", matches = "true")
	void testFirma() throws Exception {
		final AOSigner signer = new AOPDFTriPhaseSigner();
		final byte[] result = signer.sign(
			this.data, SIGN_ALGO,
			this.pke.getPrivateKey(), this.pke.getCertificateChain(),
			freshServerConfig()
		);
		assertNotNull(result, "Error durante el proceso de firma, resultado nulo"); //$NON-NLS-1$
		assertFalse(new String(result).startsWith("ERR-"), "Se recibio un codigo de error desde el servidor"); //$NON-NLS-1$ //$NON-NLS-2$
	}

	/** Prueba de firma trif&aacute;sica de un PDF certificado:
	 * (1) sin par&aacute;metro debe pedir confirmaci&oacute;n al usuario,
	 * (2) prohibida con {@code ALLOW_SIGNING_CERTIFIED_PDFS=false} debe fallar sin pedir confirmaci&oacute;n,
	 * (3) forzada con {@code ALLOW_SIGNING_CERTIFIED_PDFS=true} debe completar. */
	@Test
	@EnabledIfSystemProperty(named = "afirma.it.triphase.pades", matches = "true")
	void testFirmaPdfCertificado() throws Exception {
		final AOSigner signer = new AOPDFTriPhaseSigner();

		// Caso 1: sin parametro, debe lanzar PdfIsCertifiedException con isDenied()=false
		final PdfIsCertifiedException certEx = assertThrows(
			PdfIsCertifiedException.class,
			() -> signer.sign(this.certifiedType1Pdf, SIGN_ALGO, this.pke.getPrivateKey(), this.pke.getCertificateChain(), freshServerConfig())
		);
		assertFalse(certEx.isDenied(), "La excepcion debia dar lugar a que el usuario confirmase la operacion"); //$NON-NLS-1$

		// Caso 2: prohibido, debe fallar sin pedir confirmacion
		final Properties denyConfig = freshServerConfig();
		denyConfig.setProperty(PdfExtraParams.ALLOW_SIGNING_CERTIFIED_PDFS, Boolean.FALSE.toString());
		assertThrows(
			Exception.class,
			() -> signer.sign(this.certifiedType1Pdf, SIGN_ALGO, this.pke.getPrivateKey(), this.pke.getCertificateChain(), denyConfig)
		);

		// Caso 3: forzado, debe completar
		final Properties allowConfig = freshServerConfig();
		allowConfig.setProperty(PdfExtraParams.ALLOW_SIGNING_CERTIFIED_PDFS, Boolean.TRUE.toString());
		final byte[] result = signer.sign(
			this.certifiedType1Pdf, SIGN_ALGO,
			this.pke.getPrivateKey(), this.pke.getCertificateChain(),
			allowConfig
		);
		assertNotNull(result, "Error durante el proceso de firma, resultado nulo"); //$NON-NLS-1$
		assertFalse(new String(result).startsWith("ERR-"), "Se recibio un codigo de error desde el servidor"); //$NON-NLS-1$ //$NON-NLS-2$
	}

	/** Firma trif&aacute;sica PAdES con par&aacute;metros del portafirmas MinHAP. */
	@Test
	@EnabledIfSystemProperty(named = "afirma.it.triphase.pades", matches = "true")
	void testFirmaParamsPortafirmas() throws Exception {
		final AOSigner signer = new AOPDFTriPhaseSigner();
		final Properties config = freshServerConfig();
		config.setProperty("signatureSubFilter", "ETSI.CAdES.detached"); //$NON-NLS-1$ //$NON-NLS-2$
		config.setProperty("policyIdentifier", "2.16.724.1.3.1.1.2.1.9"); //$NON-NLS-1$ //$NON-NLS-2$
		config.setProperty("policyIdentifierHash", "G7roucf600+f03r/o0bAOQ6WAs0="); //$NON-NLS-1$ //$NON-NLS-2$
		config.setProperty("policyIdentifierHashAlgorithm", "1.3.14.3.2.26"); //$NON-NLS-1$ //$NON-NLS-2$
		config.setProperty("policyQualifier", "https://sede.060.gob.es/politica_de_firma_anexo_1.pdf"); //$NON-NLS-1$ //$NON-NLS-2$

		final byte[] result = signer.sign(
			this.data, SIGN_ALGO,
			this.pke.getPrivateKey(), this.pke.getCertificateChain(),
			config
		);
		assertNotNull(result, "Error durante el proceso de firma, resultado nulo"); //$NON-NLS-1$
		assertFalse(new String(result).startsWith("ERR-"), "Se recibio un codigo de error desde el servidor"); //$NON-NLS-1$ //$NON-NLS-2$
	}

	/** Firma trif&aacute;sica con adjunto en el PDF. */
	@Test
	@EnabledIfSystemProperty(named = "afirma.it.triphase.pades", matches = "true")
	void firmaConAdjunto() throws Exception {
		final AOSigner signer = new AOPDFTriPhaseSigner();
		final Properties config = freshServerConfig();
		config.setProperty(PROPERTY_ATTACH, loadFileOnBase64(TEST_IMAGE_FILE));
		config.setProperty(PROPERTY_ATTACH_FILENAME, TEST_IMAGE_FILE);
		config.setProperty(PROPERTY_ATTACH_DESCRIPTION, "Imagen adjunta de prueba"); //$NON-NLS-1$

		final byte[] result = signer.sign(
			this.data, SIGN_ALGO,
			this.pke.getPrivateKey(), this.pke.getCertificateChain(),
			config
		);
		assertNotNull(result, "Error durante el proceso de firma, resultado nulo"); //$NON-NLS-1$
		assertFalse(new String(result).startsWith("ERR-"), "Se recibio un codigo de error desde el servidor"); //$NON-NLS-1$ //$NON-NLS-2$
	}

	/** Cofirma trif&aacute;sica con segundo certificado. */
	@Test
	@EnabledIfSystemProperty(named = "afirma.it.triphase.pades", matches = "true")
	void cofirma() throws Exception {
		final AOSigner signer = new AOPDFTriPhaseSigner();
		final Properties config = freshServerConfig();

		final byte[] signature = signer.sign(
			this.data, SIGN_ALGO,
			this.pke.getPrivateKey(), this.pke.getCertificateChain(),
			config
		);
		assertNotNull(signature, "Error durante el proceso de firma, resultado nulo"); //$NON-NLS-1$
		assertFalse(new String(signature).startsWith("ERR-"), "Se recibio un codigo de error desde el servidor"); //$NON-NLS-1$ //$NON-NLS-2$

		config.setProperty(PROPERTY_DOC_ID, Base64.encode(signature, true));

		final byte[] coSignature = signer.cosign(
			signature, SIGN_ALGO,
			this.pke2.getPrivateKey(), this.pke2.getCertificateChain(),
			config
		);
		assertNotNull(coSignature, "Error durante el proceso de cofirma, resultado nulo"); //$NON-NLS-1$
		assertFalse(new String(coSignature).startsWith("ERR-"), "Se recibio un codigo de error desde el servidor"); //$NON-NLS-1$ //$NON-NLS-2$
	}

	/** Firmar un PDF con contrase&ntilde;a sin pasarla → debe lanzar
	 * {@link PdfIsPasswordProtectedException}. */
	@Test
	@EnabledIfSystemProperty(named = "afirma.it.triphase.pades", matches = "true")
	void firmaConContrasenaSinIndicar() {
		final AOSigner signer = new AOPDFTriPhaseSigner();
		assertThrows(
			PdfIsPasswordProtectedException.class,
			() -> signer.sign(
				this.protectedData, SIGN_ALGO,
				this.pke.getPrivateKey(), this.pke.getCertificateChain(),
				freshServerConfig()
			)
		);
	}

	/** Firmar un PDF con contrase&ntilde;a errónea → debe lanzar
	 * {@link BadPdfPasswordException}. */
	@Test
	@EnabledIfSystemProperty(named = "afirma.it.triphase.pades", matches = "true")
	void firmaConContrasenaErronea() {
		final AOSigner signer = new AOPDFTriPhaseSigner();
		final Properties config = freshServerConfig();
		config.setProperty(PdfExtraParams.OWNER_PASSWORD_STRING, "1234"); //$NON-NLS-1$

		assertThrows(
			BadPdfPasswordException.class,
			() -> signer.sign(
				this.protectedData, SIGN_ALGO,
				this.pke.getPrivateKey(), this.pke.getCertificateChain(),
				config
			)
		);
	}

}
