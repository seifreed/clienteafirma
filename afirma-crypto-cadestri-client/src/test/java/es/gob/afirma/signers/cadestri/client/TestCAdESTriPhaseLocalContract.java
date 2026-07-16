package es.gob.afirma.signers.cadestri.client;

import java.io.File;
import java.io.FileInputStream;
import java.nio.charset.StandardCharsets;
import java.net.InetSocketAddress;
import java.net.URL;
import java.lang.reflect.Constructor;
import java.security.KeyPairGenerator;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.util.Properties;
import java.util.concurrent.atomic.AtomicReference;

import org.junit.Assert;
import org.junit.Test;

import com.sun.net.httpserver.HttpServer;

import es.gob.afirma.core.misc.http.UrlHttpManagerFactory;
import es.gob.afirma.core.signers.CounterSignTarget;
import es.gob.afirma.signers.cadestri.client.asic.AOCAdESASiCSTriPhaseSigner;

/** Pruebas locales del contrato del cliente CAdES trif&aacute;sico. */
public final class TestCAdESTriPhaseLocalContract {

	@Test
	public void testPrivateConstructors() throws Exception {
		instantiate(ProtocolConstants.class);
		instantiate(PreSigner.class);
		instantiate(PostSigner.class);
	}

	@Test
	public void testUnsupportedOperations() {
		final AOCAdESTriPhaseSigner signer = new AOCAdESTriPhaseSigner();
		assertUnsupported(() -> signer.getSignersStructure(new byte[0], true));
		assertUnsupported(() -> signer.getSignersStructure(new byte[0], new Properties(), true));
		assertUnsupported(() -> signer.isSign(new byte[0]));
		assertUnsupported(() -> signer.isSign(new byte[0], new Properties()));
		assertUnsupported(() -> signer.getData(new byte[0]));
		assertUnsupported(() -> signer.getData(new byte[0], new Properties()));
		assertUnsupported(() -> signer.getSignInfo(new byte[0]));
		assertUnsupported(() -> signer.getSignInfo(new byte[0], new Properties()));
	}

	@Test
	public void testLocalHelpers() {
		final AOCAdESTriPhaseSigner signer = new AOCAdESTriPhaseSigner();
		Assert.assertFalse(signer.isValidDataFile(null));
		Assert.assertTrue(signer.isValidDataFile(new byte[0]));
		Assert.assertEquals("doc.txt.csig", signer.getSignedName("doc.txt", null)); //$NON-NLS-1$ //$NON-NLS-2$
		Assert.assertEquals("doc.txt-signed.csig", signer.getSignedName("doc.txt", "-signed")); //$NON-NLS-1$ //$NON-NLS-2$ //$NON-NLS-3$
	}

	@Test
	public void testValidationBeforeNetwork() throws Exception {
		final AOCAdESTriPhaseSigner signer = new AOCAdESTriPhaseSigner();
		final Properties extraParams = new Properties();
		final var key = KeyPairGenerator.getInstance("RSA").generateKeyPair().getPrivate(); //$NON-NLS-1$

		assertIllegalArgument(() -> signer.sign(new byte[0], "SHA256withRSA", null, null, null)); //$NON-NLS-1$
		assertIllegalArgument(() -> signer.sign(new byte[0], "SHA256withRSA", null, null, extraParams)); //$NON-NLS-1$
		assertIllegalArgument(() -> signer.sign(new byte[0], "SHA256withRSA", key, null, extraParams)); //$NON-NLS-1$
		assertIllegalArgument(() -> signer.countersign(new byte[0], "SHA256withRSA", null, null, null, null, extraParams)); //$NON-NLS-1$
		assertIllegalArgument(() -> signer.countersign(new byte[0], "SHA256withRSA", CounterSignTarget.SIGNERS, null, null, null, extraParams)); //$NON-NLS-1$
	}

	@Test
	public void testASiCSContract() {
		final AOCAdESASiCSTriPhaseSigner signer = new AOCAdESASiCSTriPhaseSigner();
		Assert.assertEquals("doc.txt.asics", signer.getSignedName("doc.txt", null)); //$NON-NLS-1$ //$NON-NLS-2$
		Assert.assertEquals("doc.txt-signed.asics", signer.getSignedName("doc.txt", "-signed")); //$NON-NLS-1$ //$NON-NLS-2$ //$NON-NLS-3$
		assertUnsupported(() -> signer.cosign(new byte[0], new byte[0], "SHA256withRSA", null, null, new Properties())); //$NON-NLS-1$
		assertUnsupported(() -> signer.cosign(new byte[0], "SHA256withRSA", null, null, new Properties())); //$NON-NLS-1$
		assertUnsupported(() -> signer.countersign(new byte[0], "SHA256withRSA", CounterSignTarget.TREE, null, null, null, new Properties())); //$NON-NLS-1$
		assertIllegalArgument(() -> signer.sign(new byte[0], "SHA256withRSA", null, null, null)); //$NON-NLS-1$
	}

	@Test
	public void testPrePostSignHttpCalls() throws Exception {
		final Certificate[] certChain = new Certificate[] { loadCertificate() };
		final Properties preParams = new Properties();
		preParams.setProperty("serverUrl", "se-elimina"); //$NON-NLS-1$ //$NON-NLS-2$
		preParams.setProperty("documentId", "se-elimina"); //$NON-NLS-1$ //$NON-NLS-2$
		preParams.setProperty("modo", "prueba"); //$NON-NLS-1$ //$NON-NLS-2$

		final AtomicReference<String> preQuery = new AtomicReference<>();
		final byte[] preResponse = "PRESIGN".getBytes(); //$NON-NLS-1$
		final HttpServer preServer = server(preResponse, preQuery);
		try {
			final URL url = new URL("http://127.0.0.1:" + preServer.getAddress().getPort() + "/tri"); //$NON-NLS-1$ //$NON-NLS-2$
			Assert.assertArrayEquals(
				preResponse,
				PreSigner.preSign("CAdES", "SHA256withRSA", certChain, "sign", "doc", UrlHttpManagerFactory.getManager(), url, preParams) //$NON-NLS-1$ //$NON-NLS-2$ //$NON-NLS-3$ //$NON-NLS-4$
			);
			Assert.assertFalse(preParams.containsKey("serverUrl")); //$NON-NLS-1$
			Assert.assertFalse(preParams.containsKey("documentId")); //$NON-NLS-1$
			Assert.assertTrue(preQuery.get().contains("op=pre")); //$NON-NLS-1$
			Assert.assertTrue(preQuery.get().contains("cop=sign")); //$NON-NLS-1$
		}
		finally {
			preServer.stop(0);
		}

		final Properties postParams = new Properties();
		postParams.setProperty("modo", "prueba"); //$NON-NLS-1$ //$NON-NLS-2$
		final AtomicReference<String> postQuery = new AtomicReference<>();
		final byte[] postResponse = "POSTSIGN".getBytes(); //$NON-NLS-1$
		final HttpServer postServer = server(postResponse, postQuery);
		try {
			final URL url = new URL("http://127.0.0.1:" + postServer.getAddress().getPort() + "/tri"); //$NON-NLS-1$ //$NON-NLS-2$
			Assert.assertArrayEquals(
				postResponse,
				PostSigner.postSign("CAdES", "SHA256withRSA", certChain, "sign", "doc", postParams, true, UrlHttpManagerFactory.getManager(), url, "session") //$NON-NLS-1$ //$NON-NLS-2$ //$NON-NLS-3$ //$NON-NLS-4$ //$NON-NLS-5$
			);
			Assert.assertTrue(postQuery.get().contains("op=post")); //$NON-NLS-1$
			Assert.assertTrue(postQuery.get().contains("session=session")); //$NON-NLS-1$
			Assert.assertTrue(postQuery.get().contains("doc=doc")); //$NON-NLS-1$
		}
		finally {
			postServer.stop(0);
		}
	}

	private static void instantiate(final Class<?> type) throws Exception {
		final Constructor<?> constructor = type.getDeclaredConstructor();
		constructor.setAccessible(true);
		constructor.newInstance();
	}

	private static void assertUnsupported(final ThrowingRunnable runnable) {
		try {
			runnable.run();
			Assert.fail("Se esperaba UnsupportedOperationException"); //$NON-NLS-1$
		}
		catch (final UnsupportedOperationException expected) {
			// Operacion no soportada por contrato.
		}
		catch (final Exception e) {
			throw new AssertionError(e);
		}
	}

	private static void assertIllegalArgument(final ThrowingRunnable runnable) {
		try {
			runnable.run();
			Assert.fail("Se esperaba IllegalArgumentException"); //$NON-NLS-1$
		}
		catch (final IllegalArgumentException expected) {
			// Validacion temprana.
		}
		catch (final Exception e) {
			throw new AssertionError(e);
		}
	}

	private interface ThrowingRunnable {
		void run() throws Exception;
	}

	private static Certificate loadCertificate() throws Exception {
		File file = new File("afirma-core/src/test/resources/CERES.cer"); //$NON-NLS-1$
		if (!file.isFile()) {
			file = new File("../afirma-core/src/test/resources/CERES.cer"); //$NON-NLS-1$
		}
		try (FileInputStream in = new FileInputStream(file)) {
			return CertificateFactory.getInstance("X.509").generateCertificate(in); //$NON-NLS-1$
		}
	}

	private static HttpServer server(final byte[] response, final AtomicReference<String> query) throws Exception {
		final HttpServer server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0); //$NON-NLS-1$
		server.createContext(
			"/tri", //$NON-NLS-1$
			exchange -> {
				final String rawQuery = exchange.getRequestURI().getRawQuery();
				query.set(rawQuery != null ? rawQuery : new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8));
				exchange.sendResponseHeaders(200, response.length);
				exchange.getResponseBody().write(response);
				exchange.close();
			}
		);
		server.start();
		return server;
	}
}
