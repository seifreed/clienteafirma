package es.gob.afirma.triphase.signer.processors;

import java.lang.reflect.Constructor;
import java.lang.reflect.Method;
import java.nio.charset.StandardCharsets;
import java.util.Properties;

import org.junit.Assert;
import org.junit.Test;

import es.gob.afirma.core.signers.AOSignConstants;
import es.gob.afirma.triphase.signer.xades.NodeDelimiter;

/** Pruebas locales de utilidades XAdES trif&aacute;sicas. */
public final class TestXAdESUtilContracts {

	private static final byte[] XML = "<?xml version=\"1.0\" encoding=\"UTF-8\"?><root><data>contenido</data></root>".getBytes(StandardCharsets.UTF_8); //$NON-NLS-1$

	/** Comprueba reemplazo reversible de partes comunes y salidas tempranas. */
	@Test
	public void testRemoveAndInsertCommonParts() throws Exception {
		final Constructor<XAdESTriPhaseSignerUtil> constructor = XAdESTriPhaseSignerUtil.class.getDeclaredConstructor();
		constructor.setAccessible(true);
		Assert.assertNotNull(constructor.newInstance());

		Assert.assertArrayEquals(XML, XAdESTriPhaseSignerUtil.removeCommonParts(XML, StandardCharsets.UTF_8.name(), envelopedParams()));
		Assert.assertArrayEquals(XML, XAdESTriPhaseSignerUtil.insertCommonParts(XML, XML, manifestParams()));
		Assert.assertArrayEquals("no-xml".getBytes(StandardCharsets.UTF_8), //$NON-NLS-1$
			XAdESTriPhaseSignerUtil.removeCommonParts("no-xml".getBytes(StandardCharsets.UTF_8), null, null)); //$NON-NLS-1$
		assertIllegalArgument(() -> XAdESTriPhaseSignerUtil.removeCommonParts(null, null, null));

		final String cleaned = (String) privateMethod("cleanNode", String.class).invoke( //$NON-NLS-1$
			null,
			"<?xml version=\"1.0\"?><n xmlns=\"urn:test\" xmlns:x='urn:x'>v</n>" //$NON-NLS-1$
		);
		Assert.assertEquals("<n>v</n>", cleaned); //$NON-NLS-1$

		final NodeDelimiter delimiter = (NodeDelimiter) privateMethod("getFirstTagPair", String.class).invoke(null, "<n a=\"1\">v</n>"); //$NON-NLS-1$ //$NON-NLS-2$
		Assert.assertEquals("n", delimiter.getNodeName()); //$NON-NLS-1$
		Assert.assertEquals("<n a=\"1\">", delimiter.getOpenTag()); //$NON-NLS-1$
		Assert.assertEquals("</n>", delimiter.getCloseTag()); //$NON-NLS-1$

		final int tagIdx = ((Integer) privateMethod("findOpenTag", StringBuilder.class, String.class, int.class).invoke( //$NON-NLS-1$
			null,
			new StringBuilder("<nodeX/><node a=\"1\"/>"), //$NON-NLS-1$
			"node", //$NON-NLS-1$
			Integer.valueOf(0)
		)).intValue();
		Assert.assertEquals(8, tagIdx);

		final Object content = privateMethod("getContent", StringBuilder.class, NodeDelimiter.class).invoke( //$NON-NLS-1$
			null,
			new StringBuilder("<a>uno<a>dos</a></a>"), //$NON-NLS-1$
			new NodeDelimiter("a", "<a>", "</a>") //$NON-NLS-1$ //$NON-NLS-2$ //$NON-NLS-3$
		);
		Assert.assertEquals("uno<a>dos</a>", content.getClass().getMethod("getContent").invoke(content)); //$NON-NLS-1$ //$NON-NLS-2$
		Assert.assertEquals(Integer.valueOf(3), content.getClass().getMethod("getStartContentIdx").invoke(content)); //$NON-NLS-1$
	}

	private static Method privateMethod(final String name, final Class<?>... parameterTypes) throws Exception {
		final Method method = XAdESTriPhaseSignerUtil.class.getDeclaredMethod(name, parameterTypes);
		method.setAccessible(true);
		return method;
	}

	private static Properties envelopedParams() {
		final Properties properties = new Properties();
		properties.setProperty("format", AOSignConstants.SIGN_FORMAT_XADES_ENVELOPED); //$NON-NLS-1$
		return properties;
	}

	private static Properties manifestParams() {
		final Properties properties = new Properties();
		properties.setProperty("useManifest", "true"); //$NON-NLS-1$ //$NON-NLS-2$
		return properties;
	}

	private static void assertIllegalArgument(final ThrowingRunnable runnable) throws Exception {
		try {
			runnable.run();
			Assert.fail("Se esperaba IllegalArgumentException"); //$NON-NLS-1$
		}
		catch (final IllegalArgumentException e) {
			// Esperado
		}
	}

	private interface ThrowingRunnable {
		void run() throws Exception;
	}
}
