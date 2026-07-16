package es.gob.afirma.core.misc.http;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.lang.reflect.Method;
import java.net.URL;
import java.util.Properties;

import javax.net.ssl.SSLHandshakeException;

import org.junit.jupiter.api.Test;

/** Pruebas de contratos HTTP locales. */
final class TestHttpLocalContracts {

	/** Comprueba configuraci&oacute;n de conexi&oacute;n sin realizar red. */
	@Test
	void connectionConfigKeepsTimeoutAndAcceptsNullManager() {
		final ConnectionConfig config = new ConnectionConfig();
		assertEquals(UrlHttpManager.DEFAULT_TIMEOUT, config.getReadTimeout());
		config.apply(null);
		config.setReadTimeout(1500);
		assertEquals(1500, config.getReadTimeout());
		config.apply(null);
	}

	/** Comprueba datos expuestos por errores HTTP. */
	@Test
	void httpErrorExposesResponseDetailsDefensively() {
		final byte[] body = "error".getBytes(); //$NON-NLS-1$
		final HttpError error = new HttpError(500, "Servidor", body, "https://example.test"); //$NON-NLS-1$ //$NON-NLS-2$
		assertEquals(500, error.getResponseCode());
		assertEquals("Servidor", error.getResponseDescription()); //$NON-NLS-1$
		assertArrayEquals(body, error.getErrorStreamBytes());
		error.getErrorStreamBytes()[0] = 0;
		assertArrayEquals(body, error.getErrorStreamBytes());
		assertTrue(error.getMessage().contains("500")); //$NON-NLS-1$

		final HttpError minimal = new HttpError(404);
		assertEquals(404, minimal.getResponseCode());
		assertNull(minimal.getResponseDescription());
		assertNull(minimal.getErrorStreamBytes());
	}

	/** Comprueba parseo y comparaci&oacute;n local de nombres de URL. */
	@Test
	void urlNameParsesAndComparesWithoutOpeningConnections() {
		final URLName url = new URLName("https://user%20name:p%2Bss@localhost:8443/path/file.txt#section"); //$NON-NLS-1$
		assertEquals("https", url.getProtocol()); //$NON-NLS-1$
		assertEquals("localhost", url.getHost()); //$NON-NLS-1$
		assertEquals(8443, url.getPort());
		assertEquals("path/file.txt", url.getFile()); //$NON-NLS-1$
		assertEquals("user name", url.getUsername()); //$NON-NLS-1$
		assertEquals("p+ss", url.getPassword()); //$NON-NLS-1$
		assertEquals("https://user%20name:p%2Bss@localhost:8443/path/file.txt#section", url.toString()); //$NON-NLS-1$

		final URLName sameWithoutPassword = new URLName("https://user%20name:other@LOCALHOST:8443/path/file.txt"); //$NON-NLS-1$
		assertEquals(url, sameWithoutPassword);
		assertEquals(url.hashCode(), sameWithoutPassword.hashCode());
		assertNotEquals(url, new URLName("https://user%20name:p%2Bss@localhost:8444/path/file.txt")); //$NON-NLS-1$
		assertNotEquals(url, new URLName("https://user%20name:p%2Bss@localhost:8443/other.txt")); //$NON-NLS-1$
		assertFalse(url.equals("https://localhost")); //$NON-NLS-1$

		final URLName ipv6 = new URLName("http://[::1]:8080/"); //$NON-NLS-1$
		assertEquals("[::1]", ipv6.getHost()); //$NON-NLS-1$
		assertEquals(8080, ipv6.getPort());
		assertEquals("", ipv6.getFile()); //$NON-NLS-1$

		final URLName badPort = new URLName("imap://mail.invalid:abc/inbox"); //$NON-NLS-1$
		assertEquals("mail.invalid", badPort.getHost()); //$NON-NLS-1$
		assertEquals(-1, badPort.getPort());
		assertEquals("imap://mail.invalid/inbox", badPort.toString()); //$NON-NLS-1$

		final URLName localFile = new URLName("mailto:user@example.test"); //$NON-NLS-1$
		assertEquals("mailto", localFile.getProtocol()); //$NON-NLS-1$
		assertNull(localFile.getHost());
		assertEquals("user@example.test", localFile.getFile()); //$NON-NLS-1$

		assertEquals("a b/c", URLName.decode("a+b%2Fc")); //$NON-NLS-1$ //$NON-NLS-2$
		assertNull(URLName.decode(null));
		assertThrows(IllegalArgumentException.class, () -> URLName.decode("%zz")); //$NON-NLS-1$
	}

	/** Comprueba que el procesador SSL solo act&uacute;a sobre errores SSL tratables. */
	@Test
	void sslErrorProcessorRethrowsNonSslErrors() {
		final IOException cause = new IOException("sin ssl"); //$NON-NLS-1$
		final SSLErrorProcessor processor = new SSLErrorProcessor(true);

		final IOException thrown = assertThrows(IOException.class, () -> processor.processHttpError(
				cause, null, "https://localhost", 1000, UrlHttpMethod.GET, new Properties())); //$NON-NLS-1$

		assertEquals(cause, thrown);
		assertFalse(processor.isCancelled());
	}

	/** Comprueba rutas locales de configuraci&oacute;n del procesador SSL. */
	@Test
	void sslErrorProcessorHonorsHeadlessAndBlockedModes() {
		final SSLHandshakeException cause = new SSLHandshakeException("certificado"); //$NON-NLS-1$

		final SSLErrorProcessor explicitHeadless = new SSLErrorProcessor(true);
		assertEquals(cause, assertThrows(IOException.class, () -> explicitHeadless.processHttpError(
				cause, null, "https://localhost", 1000, UrlHttpMethod.GET, new Properties()))); //$NON-NLS-1$
		assertFalse(explicitHeadless.isCancelled());

		final Properties params = new Properties();
		params.setProperty("sslOmitImportationDialog", "true"); //$NON-NLS-1$ //$NON-NLS-2$
		final SSLErrorProcessor configuredHeadless = new SSLErrorProcessor(params);
		assertEquals(cause, assertThrows(IOException.class, () -> configuredHeadless.processHttpError(
				cause, null, "https://localhost", 1000, UrlHttpMethod.GET, new Properties()))); //$NON-NLS-1$

		final String oldValue = System.getProperty(SSLErrorProcessor.SYSTEM_PREFERENCE_BLOCK_AUTO_IMPORT_TRUSTED_CERTS);
		try {
			System.setProperty(SSLErrorProcessor.SYSTEM_PREFERENCE_BLOCK_AUTO_IMPORT_TRUSTED_CERTS, "true"); //$NON-NLS-1$
			final SSLErrorProcessor blocked = new SSLErrorProcessor(true);
			assertEquals(cause, assertThrows(IOException.class, () -> blocked.processHttpError(
					cause, null, "https://localhost", 1000, UrlHttpMethod.GET, new Properties()))); //$NON-NLS-1$
		}
		finally {
			if (oldValue == null) {
				System.clearProperty(SSLErrorProcessor.SYSTEM_PREFERENCE_BLOCK_AUTO_IMPORT_TRUSTED_CERTS);
			}
			else {
				System.setProperty(SSLErrorProcessor.SYSTEM_PREFERENCE_BLOCK_AUTO_IMPORT_TRUSTED_CERTS, oldValue);
			}
		}
	}

	/** Comprueba ramas locales del gestor HTTP sin realizar conexiones remotas. */
	@Test
	void urlHttpManagerLocalHelpersAndTimeouts() throws Exception {
		final UrlHttpManagerImpl manager = new UrlHttpManagerImpl();
		assertEquals(UrlHttpManager.DEFAULT_TIMEOUT, manager.getReadTimeout());
		manager.setReadTimeout(1234);
		assertEquals(1234, manager.getReadTimeout());
		assertThrows(IllegalArgumentException.class, () -> manager.readUrl(null, UrlHttpMethod.GET));

		final Method isLocal = UrlHttpManagerImpl.class.getDeclaredMethod("isLocal", URL.class); //$NON-NLS-1$
		isLocal.setAccessible(true);
		assertTrue((Boolean) isLocal.invoke(null, new URL("http://localhost/"))); //$NON-NLS-1$
		assertTrue((Boolean) isLocal.invoke(null, new URL("http://127.0.0.1/"))); //$NON-NLS-1$
		assertFalse((Boolean) isLocal.invoke(null, new URL("http://example.invalid/"))); //$NON-NLS-1$

		final Method checkIsSecureDomain = UrlHttpManagerImpl.class.getDeclaredMethod("checkIsSecureDomain", URL.class); //$NON-NLS-1$
		checkIsSecureDomain.setAccessible(true);
		final String oldDomains = System.getProperty(UrlHttpManagerImpl.JAVA_PARAM_SECURE_DOMAINS_LIST);
		try {
			System.clearProperty(UrlHttpManagerImpl.JAVA_PARAM_SECURE_DOMAINS_LIST);
			assertFalse((Boolean) checkIsSecureDomain.invoke(null, new URL("https://sub.redsara.es/"))); //$NON-NLS-1$

			System.setProperty(UrlHttpManagerImpl.JAVA_PARAM_SECURE_DOMAINS_LIST, "*.redsara.*,*.example.test,secure.*,exact.test"); //$NON-NLS-1$
			assertTrue((Boolean) checkIsSecureDomain.invoke(null, new URL("https://sub.redsara.es/"))); //$NON-NLS-1$
			assertTrue((Boolean) checkIsSecureDomain.invoke(null, new URL("https://api.example.test/"))); //$NON-NLS-1$
			assertTrue((Boolean) checkIsSecureDomain.invoke(null, new URL("https://secure.domain/"))); //$NON-NLS-1$
			assertTrue((Boolean) checkIsSecureDomain.invoke(null, new URL("https://exact.test/"))); //$NON-NLS-1$
			assertFalse((Boolean) checkIsSecureDomain.invoke(null, new URL("https://other.test/"))); //$NON-NLS-1$
		}
		finally {
			if (oldDomains == null) {
				System.clearProperty(UrlHttpManagerImpl.JAVA_PARAM_SECURE_DOMAINS_LIST);
			}
			else {
				System.setProperty(UrlHttpManagerImpl.JAVA_PARAM_SECURE_DOMAINS_LIST, oldDomains);
			}
		}
	}
}
