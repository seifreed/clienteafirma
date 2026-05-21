/* Copyright (C) 2026 [Gobierno de España] / Agencia Estatal de Administración Digital */

package es.gob.afirma.standalone.configurator.common;

/**
 * Catálogo de claves de preferencias relacionadas con el almacén de
 * certificados (keystore) de la aplicación.
 *
 * <p>Esta clase es la <strong>fuente de verdad</strong> de las 5 claves
 * del dominio keystore: aquí residen los valores literales.
 * {@link PreferencesManager} mantiene sus constantes
 * {@code PREFERENCE_KEYSTORE_*} como aliases que apuntan aquí, de modo
 * que los ficheros consumidores siguen compilando sin cambios.</p>
 */
public final class KeyStorePreferenceKeys {

	private KeyStorePreferenceKeys() {
		// No permitimos la instanciacion
	}

	/** Almacén de certificados por defecto. */
	public static final String DEFAULT_STORE = "defaultKeystore"; //$NON-NLS-1$

	/** Filtrar certificados que solo permitan firma. */
	public static final String SIGN_ONLY_CERTS = "useOnlySignatureCertificates"; //$NON-NLS-1$

	/** Mostrar certificados expirados en la lista de selección. */
	public static final String SHOW_EXPIRED_CERTS = "showExpiredCerts"; //$NON-NLS-1$

	/** Filtrar certificados por alias. */
	public static final String ALIAS_ONLY_CERTS = "useOnlyAliasCertificates"; //$NON-NLS-1$

	/** Saltar el certificado de autenticación del DNIe (usar solo el de firma). */
	public static final String SKIP_AUTH_CERT_DNIE = "skipAuthCertDnie"; //$NON-NLS-1$
}
