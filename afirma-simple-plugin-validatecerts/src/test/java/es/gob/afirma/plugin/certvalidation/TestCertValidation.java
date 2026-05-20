package es.gob.afirma.plugin.certvalidation;

import java.io.InputStream;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfSystemProperty;

import es.gob.afirma.plugin.certvalidation.validation.CertificateVerifierFactory;
import es.gob.afirma.plugin.certvalidation.validation.ValidationResult;

/** Pruebas de validaci&oacute;n de certificados.
 *
 * <p>Las dos pruebas usan {@link CertificateVerifierFactory#getCertificateVerifier(X509Certificate)},
 * que efect&uacute;a comprobaciones OCSP/CRL contra responders externos.
 * Por eso van gateadas con {@code afirma.it.net.cert=true}; sin la propiedad
 * activa los tests se omiten — no se mockean — conforme a la pol&iacute;tica
 * "No mocks (mandatory)" del CLAUDE.md.
 *
 * @author Tom&aacute;s Garc&iacute;a-Mer&aacute;s. */
final class TestCertValidation {

	/** Prueba de certificados FNMT Componentes.
	 * @throws Exception En cualquier error. */
	@Test
	@EnabledIfSystemProperty(named = "afirma.it.net.cert", matches = "true")
	void testFnmt() throws Exception {
		final X509Certificate cert;
		try (final InputStream is = TestCertValidation.class.getResourceAsStream("/cert_test_fnmt.cer")) { //$NON-NLS-1$
			cert = (X509Certificate) CertificateFactory.getInstance("X.509").generateCertificate(is); //$NON-NLS-1$
		}
		final ValidationResult vr = CertificateVerifierFactory.getCertificateVerifier(cert).validateCertificate();
		vr.check();
	}

	/** Prueba de certificados gen&eacute;ricos.
	 * @throws Exception En cualquier error. */
	@Test
	@EnabledIfSystemProperty(named = "afirma.it.net.cert", matches = "true")
	void testGen() throws Exception {
		final X509Certificate cert;
		try (final InputStream is = TestCertValidation.class.getResourceAsStream("/CERT_ATOS_TEST.cer")) { //$NON-NLS-1$
			cert = (X509Certificate) CertificateFactory.getInstance("X.509").generateCertificate(is); //$NON-NLS-1$
		}
		final ValidationResult vr = CertificateVerifierFactory.getCertificateVerifier(cert).validateCertificate();
		vr.check();
	}

}
