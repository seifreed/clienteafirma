/* Copyright (C) 2026 [Gobierno de España] / Agencia Estatal de Administración Digital */

package es.gob.afirma.standalone.configurator.common;

/**
 * Catálogo de claves de preferencias relacionadas con formatos de firma
 * (XAdES, PAdES, CAdES, FacturaE, PDF).
 *
 * <p>Esta clase es la <strong>fuente de verdad</strong> de las ~48 claves
 * de los 5 dominios de formatos de firma: aquí residen los valores
 * literales. {@link PreferencesManager} mantiene sus constantes
 * {@code PREFERENCE_*} como aliases que apuntan aquí, de modo que los
 * ~43 ficheros consumidores que usan {@code PreferencesManager.PREFERENCE_*}
 * siguen compilando sin cambios.</p>
 */
public final class SignatureFormatPreferenceKeys {

	private SignatureFormatPreferenceKeys() {
		// No permitimos la instanciacion
	}

	// =====================================================================
	// XAdES (11 claves)
	// =====================================================================

	public static final String XADES_POLICY_IDENTIFIER = "xadesPolicyIdentifier"; //$NON-NLS-1$
	public static final String XADES_POLICY_HASH = "xadesPolicyIdentifierHash"; //$NON-NLS-1$
	public static final String XADES_POLICY_HASH_ALGORITHM = "xadesPolicyIdentifierHashAlgorithm"; //$NON-NLS-1$
	public static final String XADES_POLICY_QUALIFIER = "xadesPolicyQualifier"; //$NON-NLS-1$
	public static final String XADES_SIGN_FORMAT = "xadesSignFormat"; //$NON-NLS-1$
	public static final String XADES_MULTISIGN = "xadesMultisign"; //$NON-NLS-1$
	public static final String XADES_SIGNATURE_PRODUCTION_CITY = "xadesSignatureProductionCity"; //$NON-NLS-1$
	public static final String XADES_SIGNATURE_PRODUCTION_PROVINCE = "xadesSignatureProductionProvince"; //$NON-NLS-1$
	public static final String XADES_SIGNATURE_PRODUCTION_POSTAL_CODE = "xadesSignatureProductionPostalCode"; //$NON-NLS-1$
	public static final String XADES_SIGNATURE_PRODUCTION_COUNTRY = "xadesSignatureProductionCountry"; //$NON-NLS-1$
	public static final String XADES_SIGNER_CLAIMED_ROLE = "xadesSignerClaimedRole"; //$NON-NLS-1$

	// =====================================================================
	// PAdES (14 claves)
	// =====================================================================

	public static final String PADES_FORMAT = "padesBasicFormat"; //$NON-NLS-1$
	public static final String PADES_POLICY_IDENTIFIER = "padesPolicyIdentifier"; //$NON-NLS-1$
	public static final String PADES_POLICY_HASH = "padesPolicyIdentifierHash"; //$NON-NLS-1$
	public static final String PADES_POLICY_HASH_ALGORITHM = "padesPolicyIdentifierHashAlgorithm"; //$NON-NLS-1$
	public static final String PADES_POLICY_QUALIFIER = "padesPolicyQualifier"; //$NON-NLS-1$
	public static final String PADES_VISIBLE = "padesVisibleSignature"; //$NON-NLS-1$
	public static final String PADES_OBFUSCATE_CERT_INFO = "padesObfuscateCertInfo"; //$NON-NLS-1$
	public static final String PADES_STAMP = "padesVisibleStamp"; //$NON-NLS-1$
	public static final String PADES_CHECK_SHADOW_ATTACK = "allowShadowAttack"; //$NON-NLS-1$
	public static final String PADES_CHECK_ALLOW_CERTIFIED_PDF = "allowCertifiedPDF"; //$NON-NLS-1$
	public static final String PADES_DEFAULT_CERTIFICATION_LEVEL = "padesCertificationLevel"; //$NON-NLS-1$
	public static final String PADES_SIGN_REASON = "padesSignReason"; //$NON-NLS-1$
	public static final String PADES_SIGN_PRODUCTION_CITY = "padesSignProductionCity"; //$NON-NLS-1$
	public static final String PADES_SIGNER_CONTACT = "padesSignerContact"; //$NON-NLS-1$

	// =====================================================================
	// CAdES (6 claves)
	// =====================================================================

	public static final String CADES_POLICY_IDENTIFIER = "cadesPolicyIdentifier"; //$NON-NLS-1$
	public static final String CADES_POLICY_HASH = "cadesPolicyIdentifierHash"; //$NON-NLS-1$
	public static final String CADES_POLICY_HASH_ALGORITHM = "cadesPolicyIdentifierHashAlgorithm"; //$NON-NLS-1$
	public static final String CADES_POLICY_QUALIFIER = "cadesPolicyQualifier"; //$NON-NLS-1$
	public static final String CADES_IMPLICIT = "cadesImplicitMode"; //$NON-NLS-1$
	public static final String CADES_MULTISIGN = "cadesMultisign"; //$NON-NLS-1$

	// =====================================================================
	// FacturaE (10 claves)
	// =====================================================================

	public static final String FACTURAE_POLICY = "facturaEPolicy"; //$NON-NLS-1$
	public static final String FACTURAE_POLICY_IDENTIFIER = "facturaePolicyIdentifier"; //$NON-NLS-1$
	public static final String FACTURAE_POLICY_IDENTIFIER_HASH = "facturaePolicyIdentifierHash"; //$NON-NLS-1$
	public static final String FACTURAE_POLICY_IDENTIFIER_HASH_ALGORITHM = "facturaePolicyIdentifierHashAlgorithm"; //$NON-NLS-1$
	public static final String FACTURAE_POLICY_QUALIFIER = "facturaePolicyQualifier"; //$NON-NLS-1$
	public static final String FACTURAE_SIGNER_ROLE = "facturaeSignerRole"; //$NON-NLS-1$
	public static final String FACTURAE_SIGNATURE_PRODUCTION_CITY = "facturaeSignatureProductionCity"; //$NON-NLS-1$
	public static final String FACTURAE_SIGNATURE_PRODUCTION_PROVINCE = "facturaeSignatureProductionProvince"; //$NON-NLS-1$
	public static final String FACTURAE_SIGNATURE_PRODUCTION_POSTAL_CODE = "facturaeSignatureProductionPostalCode"; //$NON-NLS-1$
	public static final String FACTURAE_SIGNATURE_PRODUCTION_COUNTRY = "facturaeSignatureProductionCountry"; //$NON-NLS-1$

	// =====================================================================
	// PDF (apariencia visual de firma — 7 claves)
	// =====================================================================

	public static final String PDF_SIGN_LAYER2TEXT = "pdfLayer2Text"; //$NON-NLS-1$
	public static final String PDF_SIGN_LAYER2FONTFAMILY = "pdfLayer2FontFamily"; //$NON-NLS-1$
	public static final String PDF_SIGN_LAYER2FONTSIZE = "pdfLayer2FontSize"; //$NON-NLS-1$
	public static final String PDF_SIGN_LAYER2FONTSTYLE = "pdfLayer2FontStyle"; //$NON-NLS-1$
	public static final String PDF_SIGN_LAYER2FONTCOLOR = "pdfLayer2FontColor"; //$NON-NLS-1$
	public static final String PDF_SIGN_SIGNATUREROTATION = "pdfSignatureRotation"; //$NON-NLS-1$
	public static final String PDF_SIGN_IMAGE = "pdfSignatureImage"; //$NON-NLS-1$
}
