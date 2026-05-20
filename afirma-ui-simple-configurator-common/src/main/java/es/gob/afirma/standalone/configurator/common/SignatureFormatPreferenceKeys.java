/* Copyright (C) 2026 [Gobierno de España] / Agencia Estatal de Administración Digital */

package es.gob.afirma.standalone.configurator.common;

/**
 * Catálogo de claves de preferencias relacionadas con formatos de firma
 * (XAdES, PAdES, CAdES, FacturaE, PDF).
 *
 * <p>Reexporta las constantes {@code public static final String} que
 * estaban dispersas en {@link PreferencesManager} bajo nombres más
 * cortos (sin el prefijo redundante {@code PREFERENCE_}). Los valores
 * son los mismos que los de {@link PreferencesManager}, así que
 * código nuevo y código existente conviven sin tocar callsites.</p>
 *
 * <p>Primera fase del split temático: las constantes siguen residiendo
 * en {@link PreferencesManager} como fuente de verdad; esta clase
 * provee solo aliases para facilitar el acceso al dominio. Sesiones
 * futuras pueden mover los valores aquí y dejar aliases en
 * {@link PreferencesManager} (inversión).</p>
 */
public final class SignatureFormatPreferenceKeys {

	private SignatureFormatPreferenceKeys() {
		// No permitimos la instanciacion
	}

	// =====================================================================
	// XAdES (11 claves)
	// =====================================================================

	public static final String XADES_POLICY_IDENTIFIER = PreferencesManager.PREFERENCE_XADES_POLICY_IDENTIFIER;
	public static final String XADES_POLICY_HASH = PreferencesManager.PREFERENCE_XADES_POLICY_HASH;
	public static final String XADES_POLICY_HASH_ALGORITHM = PreferencesManager.PREFERENCE_XADES_POLICY_HASH_ALGORITHM;
	public static final String XADES_POLICY_QUALIFIER = PreferencesManager.PREFERENCE_XADES_POLICY_QUALIFIER;
	public static final String XADES_SIGN_FORMAT = PreferencesManager.PREFERENCE_XADES_SIGN_FORMAT;
	public static final String XADES_MULTISIGN = PreferencesManager.PREFERENCE_XADES_MULTISIGN;
	public static final String XADES_SIGNATURE_PRODUCTION_CITY = PreferencesManager.PREFERENCE_XADES_SIGNATURE_PRODUCTION_CITY;
	public static final String XADES_SIGNATURE_PRODUCTION_PROVINCE = PreferencesManager.PREFERENCE_XADES_SIGNATURE_PRODUCTION_PROVINCE;
	public static final String XADES_SIGNATURE_PRODUCTION_POSTAL_CODE = PreferencesManager.PREFERENCE_XADES_SIGNATURE_PRODUCTION_POSTAL_CODE;
	public static final String XADES_SIGNATURE_PRODUCTION_COUNTRY = PreferencesManager.PREFERENCE_XADES_SIGNATURE_PRODUCTION_COUNTRY;
	public static final String XADES_SIGNER_CLAIMED_ROLE = PreferencesManager.PREFERENCE_XADES_SIGNER_CLAIMED_ROLE;

	// =====================================================================
	// PAdES (16 claves)
	// =====================================================================

	public static final String PADES_FORMAT = PreferencesManager.PREFERENCE_PADES_FORMAT;
	public static final String PADES_POLICY_IDENTIFIER = PreferencesManager.PREFERENCE_PADES_POLICY_IDENTIFIER;
	public static final String PADES_POLICY_HASH = PreferencesManager.PREFERENCE_PADES_POLICY_HASH;
	public static final String PADES_POLICY_HASH_ALGORITHM = PreferencesManager.PREFERENCE_PADES_POLICY_HASH_ALGORITHM;
	public static final String PADES_POLICY_QUALIFIER = PreferencesManager.PREFERENCE_PADES_POLICY_QUALIFIER;
	public static final String PADES_VISIBLE = PreferencesManager.PREFERENCE_PADES_VISIBLE;
	public static final String PADES_OBFUSCATE_CERT_INFO = PreferencesManager.PREFERENCE_PADES_OBFUSCATE_CERT_INFO;
	public static final String PADES_STAMP = PreferencesManager.PREFERENCE_PADES_STAMP;
	public static final String PADES_CHECK_SHADOW_ATTACK = PreferencesManager.PREFERENCE_PADES_CHECK_SHADOW_ATTACK;
	public static final String PADES_CHECK_ALLOW_CERTIFIED_PDF = PreferencesManager.PREFERENCE_PADES_CHECK_ALLOW_CERTIFIED_PDF;
	public static final String PADES_DEFAULT_CERTIFICATION_LEVEL = PreferencesManager.PREFERENCE_PADES_DEFAULT_CERTIFICATION_LEVEL;
	public static final String PADES_SIGN_REASON = PreferencesManager.PREFERENCE_PADES_SIGN_REASON;
	public static final String PADES_SIGN_PRODUCTION_CITY = PreferencesManager.PREFERENCE_PADES_SIGN_PRODUCTION_CITY;
	public static final String PADES_SIGNER_CONTACT = PreferencesManager.PREFERENCE_PADES_SIGNER_CONTACT;

	// =====================================================================
	// CAdES (6 claves)
	// =====================================================================

	public static final String CADES_POLICY_IDENTIFIER = PreferencesManager.PREFERENCE_CADES_POLICY_IDENTIFIER;
	public static final String CADES_POLICY_HASH = PreferencesManager.PREFERENCE_CADES_POLICY_HASH;
	public static final String CADES_POLICY_HASH_ALGORITHM = PreferencesManager.PREFERENCE_CADES_POLICY_HASH_ALGORITHM;
	public static final String CADES_POLICY_QUALIFIER = PreferencesManager.PREFERENCE_CADES_POLICY_QUALIFIER;
	public static final String CADES_IMPLICIT = PreferencesManager.PREFERENCE_CADES_IMPLICIT;
	public static final String CADES_MULTISIGN = PreferencesManager.PREFERENCE_CADES_MULTISIGN;

	// =====================================================================
	// FacturaE (10 claves)
	// =====================================================================

	public static final String FACTURAE_POLICY = PreferencesManager.PREFERENCE_FACTURAE_POLICY;
	public static final String FACTURAE_POLICY_IDENTIFIER = PreferencesManager.PREFERENCE_FACTURAE_POLICY_IDENTIFIER;
	public static final String FACTURAE_POLICY_IDENTIFIER_HASH = PreferencesManager.PREFERENCE_FACTURAE_POLICY_IDENTIFIER_HASH;
	public static final String FACTURAE_POLICY_IDENTIFIER_HASH_ALGORITHM = PreferencesManager.PREFERENCE_FACTURAE_POLICY_IDENTIFIER_HASH_ALGORITHM;
	public static final String FACTURAE_POLICY_QUALIFIER = PreferencesManager.PREFERENCE_FACTURAE_POLICY_QUALIFIER;
	public static final String FACTURAE_SIGNER_ROLE = PreferencesManager.PREFERENCE_FACTURAE_SIGNER_ROLE;
	public static final String FACTURAE_SIGNATURE_PRODUCTION_CITY = PreferencesManager.PREFERENCE_FACTURAE_SIGNATURE_PRODUCTION_CITY;
	public static final String FACTURAE_SIGNATURE_PRODUCTION_PROVINCE = PreferencesManager.PREFERENCE_FACTURAE_SIGNATURE_PRODUCTION_PROVINCE;
	public static final String FACTURAE_SIGNATURE_PRODUCTION_POSTAL_CODE = PreferencesManager.PREFERENCE_FACTURAE_SIGNATURE_PRODUCTION_POSTAL_CODE;
	public static final String FACTURAE_SIGNATURE_PRODUCTION_COUNTRY = PreferencesManager.PREFERENCE_FACTURAE_SIGNATURE_PRODUCTION_COUNTRY;

	// =====================================================================
	// PDF (apariencia visual de firma — 7 claves)
	// =====================================================================

	public static final String PDF_SIGN_LAYER2TEXT = PreferencesManager.PREFERENCE_PDF_SIGN_LAYER2TEXT;
	public static final String PDF_SIGN_LAYER2FONTFAMILY = PreferencesManager.PREFERENCE_PDF_SIGN_LAYER2FONTFAMILY;
	public static final String PDF_SIGN_LAYER2FONTSIZE = PreferencesManager.PREFERENCE_PDF_SIGN_LAYER2FONTSIZE;
	public static final String PDF_SIGN_LAYER2FONTSTYLE = PreferencesManager.PREFERENCE_PDF_SIGN_LAYER2FONTSTYLE;
	public static final String PDF_SIGN_LAYER2FONTCOLOR = PreferencesManager.PREFERENCE_PDF_SIGN_LAYER2FONTCOLOR;
	public static final String PDF_SIGN_SIGNATUREROTATION = PreferencesManager.PREFERENCE_PDF_SIGN_SIGNATUREROTATION;
	public static final String PDF_SIGN_IMAGE = PreferencesManager.PREFERENCE_PDF_SIGN_IMAGE;
}
