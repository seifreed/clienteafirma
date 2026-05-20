package es.gob.afirma.plugin.certvalidation;

import static org.junit.jupiter.api.Assertions.fail;

import java.io.InputStream;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateFactory;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.X509Certificate;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfSystemProperty;

import es.gob.afirma.plugin.certvalidation.validation.CertificateRevokedException;
import es.gob.afirma.plugin.certvalidation.validation.CertificateVerifierFactory;
import es.gob.afirma.plugin.certvalidation.validation.ValidationResult;

/** Pruebas de validaci&oacute;n de certificados FNMT.
 *
 * <p>Las pruebas iteran sobre fixtures locales de certificados activos y
 * revocados, y consultan OCSP/CRL de la FNMT para validarlos. Van gateadas
 * por {@code afirma.it.net.fnmt=true}; sin la propiedad activa se omiten —
 * no se mockean — conforme a la pol&iacute;tica "No mocks (mandatory)" del
 * CLAUDE.md.
 *
 * @author Tom&aacute;s Garc&iacute;a-Mer&aacute;s. */
final class TestFnmtCertValidation {

	private static final String[] ACTIVOS = {
		"ejemploADM_SLD_ACTIVO.cer", //$NON-NLS-1$
		"ejemploESPJ_ACTIVO.cer", //$NON-NLS-1$
		"ejemploPJ_ACTIVO.cer", //$NON-NLS-1$
		"SELLO_ACTIVO_EIDAS_ACAP.crt", //$NON-NLS-1$
		"SOFTWARE_ACTIVO_EIDAS_ACAP.cer", //$NON-NLS-1$
		"TARJETA_ACTIVO_EIDAS_ACAP.cer" //$NON-NLS-1$
	};

	private static final String[] REVOCADOS = {
		"ejemploADM_SLD_REVOCADO.cer", //$NON-NLS-1$
		"ejemploESPJ_REVOCADO.cer", //$NON-NLS-1$
		"ejemploPJ_REVOCADO.cer" //$NON-NLS-1$
	};

	/** Prueba de certificados FNMT revocados.
	 * @throws Exception En cualquier error. */
	@Test
	@EnabledIfSystemProperty(named = "afirma.it.net.fnmt", matches = "true")
	void testRevoked() throws Exception {
		final CertificateFactory cf = CertificateFactory.getInstance("X.509"); //$NON-NLS-1$
		for (final String c : REVOCADOS) {
			final X509Certificate cert;
			try (final InputStream is = TestFnmtCertValidation.class.getResourceAsStream("/fnmt/" + c)) { //$NON-NLS-1$
				cert = (X509Certificate) cf.generateCertificate(is);
			}
			final ValidationResult vr = CertificateVerifierFactory.getCertificateVerifier(cert).validateCertificate();
			try {
				vr.check();
			}
			catch (final CertificateExpiredException | CertificateNotYetValidException | CertificateRevokedException e) {
				continue;
			}
			fail("El certificado " + c + " deberia estar revocado/caducado"); //$NON-NLS-1$ //$NON-NLS-2$
		}
	}

	/** Prueba de certificados FNMT v&aacute;lidos.
	 * @throws Exception En cualquier error. */
	@Test
	@EnabledIfSystemProperty(named = "afirma.it.net.fnmt", matches = "true")
	void testValid() throws Exception {
		final CertificateFactory cf = CertificateFactory.getInstance("X.509"); //$NON-NLS-1$
		for (final String c : ACTIVOS) {
			final X509Certificate cert;
			try (final InputStream is = TestFnmtCertValidation.class.getResourceAsStream("/fnmt/" + c)) { //$NON-NLS-1$
				cert = (X509Certificate) cf.generateCertificate(is);
			}
			final ValidationResult vr = CertificateVerifierFactory.getCertificateVerifier(cert).validateCertificate();
			vr.check();
		}
	}

}
