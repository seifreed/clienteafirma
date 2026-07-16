package es.gob.afirma.keystores.filters;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.InputStream;
import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.Principal;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.Properties;

import org.junit.jupiter.api.Test;

import es.gob.afirma.core.misc.AOUtil;
import es.gob.afirma.core.misc.Base64;
import es.gob.afirma.keystores.CertificateFilter;

/** Pruebas de contratos locales de filtros de certificados. */
final class TestFilterLocalContracts {

	/** Comprueba filtros que operan sobre certificados reales ya presentes como recursos. */
	@Test
	void certificateFiltersMatchRealCertificateData() throws Exception {
		final X509Certificate cert = loadCertificate("Tomas_DNI_FIRMA.cer"); //$NON-NLS-1$

		assertTrue(new TextContainedCertificateFilter(new String[] { "11830960J" }, new String[] { "POLICIA" }).matches(cert)); //$NON-NLS-1$ //$NON-NLS-2$
		assertFalse(new TextContainedCertificateFilter(new String[] { "NO_EXISTE" }, null).matches(cert)); //$NON-NLS-1$
		assertThrows(IllegalArgumentException.class, () -> new TextContainedCertificateFilter(null, null));

		assertTrue(new EncodedCertificateFilter(Base64.encode(cert.getEncoded())).matches(cert));
		assertFalse(new EncodedCertificateFilter("AA==").matches(cert)); //$NON-NLS-1$
		assertThrows(NullPointerException.class, () -> new EncodedCertificateFilter(null));

		final String sha1 = AOUtil.hexify(MessageDigest.getInstance("SHA-1").digest(cert.getEncoded()), ""); //$NON-NLS-1$ //$NON-NLS-2$
		assertTrue(new ThumbPrintCertificateFilter("SHA-1", sha1).matches(cert)); //$NON-NLS-1$
		assertTrue(new ThumbPrintCertificateFilter("SHA-1", sha1.replaceAll("(.{2})", "$1 ")).matches(cert)); //$NON-NLS-1$ //$NON-NLS-2$ //$NON-NLS-3$
		assertFalse(new ThumbPrintCertificateFilter("NOPE", sha1).matches(cert)); //$NON-NLS-1$
		assertThrows(IllegalArgumentException.class, () -> new ThumbPrintCertificateFilter(null, sha1));
		assertThrows(IllegalArgumentException.class, () -> new ThumbPrintCertificateFilter("SHA-1", null)); //$NON-NLS-1$

		assertTrue(new ExpiredCertificateFilter(true).matches(cert));
		assertNotNull(FilterUtils.getSubjectSN(cert));
		assertTrue(FilterUtils.bigIntegerToHex(new BigInteger("255")).endsWith("FF")); //$NON-NLS-1$ //$NON-NLS-2$
	}

	/** Comprueba patrones de usos de clave y filtros DNIe compuestos. */
	@Test
	void keyUsagePatternsAndDnieFiltersKeepExpectedContracts() throws Exception {
		final Principal genericIssuer = new NamedPrincipal("CN=Generica"); //$NON-NLS-1$
		assertArrayEquals(
			new Boolean[] { null, Boolean.TRUE, null, null, null, null, null, null },
			new KeyUsagesPattern(genericIssuer).getSignaturePattern()
		);

		final Principal accvIssuer = new NamedPrincipal("C=ES, O=Generalitat Valenciana, OU=PKIGVA, CN=ACCV-CA2"); //$NON-NLS-1$
		assertArrayEquals(
			new Boolean[] { Boolean.TRUE, Boolean.FALSE, Boolean.FALSE, Boolean.FALSE, Boolean.FALSE, Boolean.FALSE, Boolean.FALSE, Boolean.FALSE },
			new KeyUsagesPattern(accvIssuer).getSignaturePattern()
		);

		final X509Certificate cert = loadCertificate("Tomas_DNI_FIRMA.cer"); //$NON-NLS-1$
		assertTrue(new SigningCertificateFilter().matches(cert));
		assertFalse(new AuthCertificateFilter().matches(cert));
		assertFalse(new SignatureDNIeFilter().matches(loadCertificate("Certicficado_AP_CarlosGG.cer"))); //$NON-NLS-1$
		assertTrue(new SkipAuthDNIeFilter().matches(cert));
	}

	/** Comprueba la construcci&oacute;n local de gestores de filtros desde propiedades. */
	@Test
	void certFilterManagerBuildsFiltersFromProperties() {
		final CertFilterManager defaults = new CertFilterManager(new Properties());
		assertFalse(defaults.isMandatoryCertificate());
		assertTrue(defaults.isExternalStoresOpeningAllowed());
		assertEquals(1, defaults.getFilters().size());
		assertTrue(defaults.getFilters().get(0) instanceof ExpiredCertificateFilter);

		final Properties headless = new Properties();
		headless.setProperty("headless", "true"); //$NON-NLS-1$ //$NON-NLS-2$
		assertTrue(new CertFilterManager(headless).isMandatoryCertificate());

		final Properties mandatory = new Properties();
		mandatory.setProperty("mandatoryCertSelection", "false"); //$NON-NLS-1$ //$NON-NLS-2$
		assertTrue(new CertFilterManager(mandatory).isMandatoryCertificate());

		final Properties disableExternalStores = new Properties();
		disableExternalStores.setProperty("filter", "disableopeningexternalstores;signingcert:"); //$NON-NLS-1$ //$NON-NLS-2$
		final CertFilterManager disabled = new CertFilterManager(disableExternalStores);
		assertFalse(disabled.isExternalStoresOpeningAllowed());
		assertEquals(1, disabled.getFilters().size());
		assertTrue(disabled.getFilters().get(0) instanceof SigningCertificateFilter);

		final Properties enumerated = new Properties();
		enumerated.setProperty("filters.1", "subject.contains:11830960J"); //$NON-NLS-1$ //$NON-NLS-2$
		enumerated.setProperty("filters.2", "issuer.contains:POLICIA"); //$NON-NLS-1$ //$NON-NLS-2$
		assertEquals(2, new CertFilterManager(enumerated).getFilters().size());

		final Properties keyUsage = new Properties();
		keyUsage.setProperty("filters", "keyusage.digitalSignature:true;keyusage.nonRepudiation:null;desconocido:valor"); //$NON-NLS-1$ //$NON-NLS-2$
		assertEquals(1, new CertFilterManager(keyUsage).getFilters().size());

		final List<CertificateFilter> sourceFilters = List.of(new ExpiredCertificateFilter(true));
		final CertFilterManager explicit = new CertFilterManager(sourceFilters, true, false);
		assertTrue(explicit.isMandatoryCertificate());
		assertFalse(explicit.isExternalStoresOpeningAllowed());
		assertEquals(1, explicit.getFilters().size());
		final List<CertificateFilter> exposedFilters = explicit.getFilters();
		exposedFilters.clear();
		assertEquals(1, explicit.getFilters().size());
	}

	private static X509Certificate loadCertificate(final String resource) throws Exception {
		try (InputStream input = ClassLoader.getSystemResourceAsStream(resource)) {
			return (X509Certificate) CertificateFactory.getInstance("X.509").generateCertificate(input); //$NON-NLS-1$
		}
	}

	private static final class NamedPrincipal implements Principal {
		private final String name;

		NamedPrincipal(final String name) {
			this.name = name;
		}

		@Override
		public String getName() {
			return this.name;
		}

		@Override
		public String toString() {
			return this.name;
		}
	}
}
