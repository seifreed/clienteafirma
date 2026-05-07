/* Copyright (C) 2026 [Gobierno de España] / Agencia Estatal de Administración Digital
 * This file is part of "Cliente @Firma".
 * "Cliente @Firma" is free software; you can redistribute it and/or modify it under the terms of:
 *   - the GNU General Public License as published by the Free Software Foundation;
 *     either version 2 of the License, or (at your option) any later version.
 *   - or The European Software License; either version 1.1 or (at your option) any later version.
 */

package es.gob.afirma.massive;

import java.util.Set;

import es.gob.afirma.core.signers.AOSigner;

/**
 * Helper para clasificar {@link AOSigner} por familia funcional. Sustituye
 * las constantes string FQCN hardcoded que vivían en
 * {@link DirectorySignatureHelper} (líneas 52-57 antes de la Fase B del plan
 * Clean Code, 2026-05-07): comparar el class name por igualdad funcional
 * en lugar de literal hace que el código siga funcionando si un signer
 * cambia de paquete, y centraliza los grupos en un solo sitio donde añadir
 * formatos nuevos (JAdES, FacturaE, etc.).
 *
 * <p>Los signers se identifican por su FQCN. Una alternativa más pura
 * sería instanciarlos vía {@code AOSignerFactory.getSigner(format)}, pero
 * eso requiere conocer el formato a priori — aquí recibimos el {@code AOSigner}
 * ya construido y necesitamos detectar su familia <em>a posteriori</em>.</p>
 */
final class SignerFamilies {

	private static final String CADES = "es.gob.afirma.signers.cades.AOCAdESSigner"; //$NON-NLS-1$
	private static final String XADES = "es.gob.afirma.signers.xades.AOXAdESSigner"; //$NON-NLS-1$
	private static final String XMLDSIG = "es.gob.afirma.signers.xmldsig.AOXMLDSigSigner"; //$NON-NLS-1$
	private static final String PDF = "es.gob.afirma.signers.pades.AOPDFSigner"; //$NON-NLS-1$
	private static final String ODF = "es.gob.afirma.signers.odf.AOODFSSigner"; //$NON-NLS-1$
	private static final String OOXML = "es.gob.afirma.signers.ooxml.AOOOXMLSigner"; //$NON-NLS-1$

	/** Signers que producen firmas XML — el flujo masivo añade transformaciones
	 *  XML específicas (XAdES, XMLDSig). */
	private static final Set<String> XML_SIGNERS = Set.of(XADES, XMLDSIG);

	/** Signers que soportan multifirma (cofirma/contrafirma) en el pipeline
	 *  masivo: los basados en CMS o XML. */
	private static final Set<String> MULTI_SIGNATURE_SIGNERS = Set.of(CADES, XADES, XMLDSIG);

	/** Signers que firman formatos de documento embebido (PDF, ODF, OOXML).
	 *  El flujo masivo trata estos como casos especiales — la firma se guarda
	 *  en un fichero del mismo formato. */
	private static final Set<String> DOCUMENT_SIGNERS = Set.of(PDF, ODF, OOXML);

	private SignerFamilies() {
		// Helper de utilidad — no instanciable.
	}

	/** {@code true} si el signer produce firmas XML (XAdES o XMLDSig). */
	static boolean isXmlBased(final AOSigner signer) {
		return signer != null && XML_SIGNERS.contains(signer.getClass().getName());
	}

	/** {@code true} si el signer soporta multifirma estándar (CAdES, XAdES, XMLDSig). */
	static boolean supportsMultiSignature(final AOSigner signer) {
		return signer != null && MULTI_SIGNATURE_SIGNERS.contains(signer.getClass().getName());
	}

	/** {@code true} si el signer firma formatos de documento embebido (PDF, ODF, OOXML). */
	static boolean isDocumentBased(final AOSigner signer) {
		return signer != null && DOCUMENT_SIGNERS.contains(signer.getClass().getName());
	}
}
