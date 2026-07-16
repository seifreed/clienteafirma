package es.gob.afirma.standalone;

import java.io.File;
import java.lang.reflect.Constructor;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.cert.CertificateException;

import org.junit.Assert;
import org.junit.Test;

import es.gob.afirma.core.ErrorCode;
import es.gob.afirma.core.misc.Base64;
import es.gob.afirma.standalone.ProxyConfig.ConfigType;

/** Pruebas del parser de par&aacute;metros por consola. */
public final class TestCommandLineParameters {

	/** Comprueba parseo correcto y valores por defecto. */
	@Test
	public void testValidParametersAndDefaults() throws Exception {
		final File input = File.createTempFile("afirma-cli-in", ".txt"); //$NON-NLS-1$ //$NON-NLS-2$
		final File aux = File.createTempFile("afirma-cli-aux", ".txt"); //$NON-NLS-1$ //$NON-NLS-2$
		final File output = new File(input.getParentFile(), "afirma-cli-out.txt"); //$NON-NLS-1$
		try {
			Files.write(input.toPath(), "entrada".getBytes(StandardCharsets.UTF_8)); //$NON-NLS-1$
			Files.write(aux.toPath(), "aux".getBytes(StandardCharsets.UTF_8)); //$NON-NLS-1$
			final CommandLineParameters params = new CommandLineParameters(
				CommandLineCommand.SIGN,
				new String[] {
					"sign", //$NON-NLS-1$
					"-i", aux.getAbsolutePath(), //$NON-NLS-1$
					"-o", output.getAbsolutePath(), //$NON-NLS-1$
					"-store", "pkcs12:store.p12", //$NON-NLS-1$ //$NON-NLS-2$
					"-alias", "alias1", //$NON-NLS-1$ //$NON-NLS-2$
					"-format", "XAdES", //$NON-NLS-1$ //$NON-NLS-2$
					"-algorithm", "SHA256withRSA", //$NON-NLS-1$ //$NON-NLS-2$
					"-password", "secret", //$NON-NLS-1$ //$NON-NLS-2$
					"-config", "mode=explicit", //$NON-NLS-1$ //$NON-NLS-2$
					"-preurl", "https://example.test/pre", //$NON-NLS-1$ //$NON-NLS-2$
					"-posturl", "https://example.test/post", //$NON-NLS-1$ //$NON-NLS-2$
					"-xml", //$NON-NLS-1$
					"-gui", //$NON-NLS-1$
					"-certgui" //$NON-NLS-1$
				}
			);
			Assert.assertEquals(aux.getCanonicalFile(), params.getInputFile().getCanonicalFile());
			Assert.assertEquals(output.getCanonicalFile(), params.getOutputFile().getCanonicalFile());
			Assert.assertEquals("pkcs12:store.p12", params.getStore()); //$NON-NLS-1$
			Assert.assertEquals("alias1", params.getAlias()); //$NON-NLS-1$
			Assert.assertEquals(CommandLineParameters.FORMAT_XADES, params.getFormat());
			Assert.assertEquals("SHA256withRSA", params.getAlgorithm()); //$NON-NLS-1$
			Assert.assertEquals("secret", params.getPassword()); //$NON-NLS-1$
			Assert.assertEquals("mode=explicit", params.getExtraParams()); //$NON-NLS-1$
			Assert.assertEquals("https://example.test/pre", params.getPreSignUrl().toString()); //$NON-NLS-1$
			Assert.assertEquals("https://example.test/post", params.getPostSignUrl().toString()); //$NON-NLS-1$
			Assert.assertTrue(params.isXml());
			Assert.assertTrue(params.isGui());
			Assert.assertTrue(params.isCertGui());
			Assert.assertFalse(params.isRecursive());
			Assert.assertFalse(params.isHelp());

			final CommandLineParameters defaults = new CommandLineParameters(CommandLineCommand.LIST, new String[] { "listaliases" }); //$NON-NLS-1$
			Assert.assertEquals(CommandLineParameters.DEFAULT_FORMAT, defaults.getFormat());
			Assert.assertEquals(CommandLineParameters.ALGO_SHA512, defaults.getAlgorithm());
			Assert.assertEquals(CommandLineParameters.MASSIVE_OP_SIGN, defaults.getMassiveOperation());
			Assert.assertEquals(CommandLineParameters.DEFAULT_FORMAT_FILE_HASH, defaults.getHashFileFormat());
			Assert.assertEquals(CommandLineParameters.DEFAULT_FORMAT_DIR_HASH, defaults.getHashDirectoryFormat());
		}
		finally {
			input.delete();
			aux.delete();
			output.delete();
		}
	}

	/** Comprueba par&aacute;metros de hash y operaci&oacute;n masiva. */
	@Test
	public void testHashAndMassiveParameters() throws Exception {
		final CommandLineParameters params = new CommandLineParameters(
			CommandLineCommand.BATCHSIGN,
			new String[] {
				"batchsign", //$NON-NLS-1$
				"-hformat", "txt", //$NON-NLS-1$ //$NON-NLS-2$
				"-halgorithm", "sha256", //$NON-NLS-1$ //$NON-NLS-2$
				"-operation", "cosign", //$NON-NLS-1$ //$NON-NLS-2$
				"-filter", "CN=Test", //$NON-NLS-1$ //$NON-NLS-2$
				"-r" //$NON-NLS-1$
			}
		);
		Assert.assertEquals(CommandLineParameters.FORMAT_HASH_DIR_PLAIN, params.getHashFormat());
		Assert.assertEquals(CommandLineParameters.FORMAT_HASH_DIR_PLAIN, params.getHashDirectoryFormat());
		Assert.assertEquals(CommandLineParameters.MASSIVE_OP_COSIGN, params.getMassiveOperation());
		Assert.assertEquals("CN=Test", params.getFilter()); //$NON-NLS-1$
		Assert.assertTrue(params.isRecursive());
		try {
			params.getHashFileFormat();
			Assert.fail("Se esperaba rechazo de formato de hash de directorio para fichero"); //$NON-NLS-1$
		}
		catch (final CommandLineException e) {
			// Esperado
		}

		final CommandLineParameters xmlDirHash = new CommandLineParameters(
			CommandLineCommand.BATCHSIGN,
			new String[] { "batchsign", "-hformat", "xml", "-operation", "countersign" } //$NON-NLS-1$ //$NON-NLS-2$ //$NON-NLS-3$ //$NON-NLS-4$ //$NON-NLS-5$
		);
		Assert.assertEquals(CommandLineParameters.FORMAT_HASH_DIR_XML, xmlDirHash.getHashDirectoryFormat());
		Assert.assertEquals(CommandLineParameters.MASSIVE_OP_COUNTERSIGN, xmlDirHash.getMassiveOperation());

		for (final String fileHashFormat : new String[] {
			CommandLineParameters.FORMAT_HASH_FILE_HEX,
			CommandLineParameters.FORMAT_HASH_FILE_BASE64,
			CommandLineParameters.FORMAT_HASH_FILE_BIN
		}) {
			final CommandLineParameters fileHash = new CommandLineParameters(
				CommandLineCommand.SIGN,
				new String[] { "sign", "-hformat", fileHashFormat } //$NON-NLS-1$ //$NON-NLS-2$
			);
			Assert.assertEquals(fileHashFormat, fileHash.getHashFileFormat());
			try {
				fileHash.getHashDirectoryFormat();
				Assert.fail("Se esperaba rechazo de formato de hash de fichero para directorio"); //$NON-NLS-1$
			}
			catch (final CommandLineException e) {
				// Esperado
			}
		}
	}

	/** Comprueba errores de parseo representativos. */
	@Test
	public void testInvalidParameters() throws Exception {
		assertCommandLineError(new String[] { "sign", "-format", "bad" }, CommandLineParameterException.class); //$NON-NLS-1$ //$NON-NLS-2$ //$NON-NLS-3$
		assertCommandLineError(new String[] { "sign", "-preurl", "bad url" }, CommandLineParameterException.class); //$NON-NLS-1$ //$NON-NLS-2$ //$NON-NLS-3$
		assertCommandLineError(new String[] { "sign", "-alias", "a", "-filter", "f" }, CommandLineException.class); //$NON-NLS-1$ //$NON-NLS-2$ //$NON-NLS-3$ //$NON-NLS-4$ //$NON-NLS-5$
		assertCommandLineError(new String[] { "sign", "-i", "missing.file" }, CommandLineException.class); //$NON-NLS-1$ //$NON-NLS-2$ //$NON-NLS-3$
		assertCommandLineError(new String[] { "sign", "-store" }, CommandLineException.class); //$NON-NLS-1$ //$NON-NLS-2$
		assertCommandLineError(new String[] { "sign", "-unknown" }, CommandLineException.class); //$NON-NLS-1$ //$NON-NLS-2$
		assertCommandLineError(new String[] { "sign", "-store", "auto", "-store", "auto" }, CommandLineException.class); //$NON-NLS-1$ //$NON-NLS-2$ //$NON-NLS-3$ //$NON-NLS-4$ //$NON-NLS-5$
		assertCommandLineError(new String[] { "sign", "-operation" }, CommandLineException.class); //$NON-NLS-1$ //$NON-NLS-2$
		assertCommandLineError(new String[] { "sign", "-halgorithm" }, CommandLineException.class); //$NON-NLS-1$ //$NON-NLS-2$
		assertCommandLineError(new String[] { "sign", "-hformat", "bad" }, CommandLineParameterException.class); //$NON-NLS-1$ //$NON-NLS-2$ //$NON-NLS-3$
		assertCommandLineError(new String[] { "sign", "-posturl", "bad url" }, CommandLineParameterException.class); //$NON-NLS-1$ //$NON-NLS-2$ //$NON-NLS-3$
	}

	/** Comprueba parseo de comandos y constructores de excepciones. */
	@Test
	public void testCommandsSyntaxAndExceptions() {
		Assert.assertEquals(CommandLineCommand.SIGN, CommandLineCommand.parse("sign")); //$NON-NLS-1$
		Assert.assertNull(CommandLineCommand.parse("missing")); //$NON-NLS-1$
		for (final CommandLineCommand command : CommandLineCommand.values()) {
			Assert.assertTrue(CommandLineParameters.buildSyntaxError(command, "error").contains(command.getOp())); //$NON-NLS-1$
		}
		Assert.assertEquals("error", new CommandLineException("error").getMessage()); //$NON-NLS-1$ //$NON-NLS-2$
		Assert.assertTrue(new CommandLineException("error", true).isUsingGui()); //$NON-NLS-1$
		final Exception cause = new Exception("cause"); //$NON-NLS-1$
		Assert.assertSame(cause, new CommandLineException(cause).getCause());
		Assert.assertSame(cause, new CommandLineException("error", cause).getCause()); //$NON-NLS-1$
		Assert.assertSame(cause, new CommandLineException(cause, true).getCause());
		Assert.assertTrue(new CommandLineException("error", cause, true).isUsingGui()); //$NON-NLS-1$

		Assert.assertEquals("error", new CommandLineParameterException("error").getMessage()); //$NON-NLS-1$ //$NON-NLS-2$
		Assert.assertSame(cause, new CommandLineParameterException(cause).getCause());
		Assert.assertSame(cause, new CommandLineParameterException("error", cause).getCause()); //$NON-NLS-1$
		Assert.assertTrue(new CommandLineParameterException("error", true).isUsingGui()); //$NON-NLS-1$
		Assert.assertTrue(new CommandLineParameterException(cause, true).isUsingGui());
		Assert.assertTrue(new CommandLineParameterException("error", cause, true).isUsingGui()); //$NON-NLS-1$
	}

	/** Comprueba contratos sencillos compartidos por la consola. */
	@Test
	public void testSupportContracts() throws Exception {
		CommandLineMessages.updateLocale();
		Assert.assertTrue(CommandLineMessages.getString("CommandLineLauncher.0", "entrada.txt").contains("entrada.txt")); //$NON-NLS-1$ //$NON-NLS-2$ //$NON-NLS-3$
		Assert.assertEquals("!clave.inexistente!", CommandLineMessages.getString("clave.inexistente")); //$NON-NLS-1$ //$NON-NLS-2$

		SimpleAfirmaMessages.changeLocale();
		Assert.assertNotNull(SimpleAfirmaMessages.getString("SimpleAfirma.7")); //$NON-NLS-1$
		Assert.assertEquals("!clave.inexistente!", SimpleAfirmaMessages.getString("clave.inexistente")); //$NON-NLS-1$ //$NON-NLS-2$

		final ProxyConfig proxy = new ProxyConfig(ConfigType.CUSTOM);
		proxy.setHost("proxy.test"); //$NON-NLS-1$
		proxy.setPort("8080"); //$NON-NLS-1$
		proxy.setUsername("user"); //$NON-NLS-1$
		proxy.setPassword(new char[] { 's', 'e', 'c' });
		proxy.setExcludedUrls("localhost|127.0.0.1"); //$NON-NLS-1$
		Assert.assertEquals(ConfigType.CUSTOM, proxy.getConfigType());
		Assert.assertEquals("proxy.test", proxy.getHost()); //$NON-NLS-1$
		Assert.assertEquals("8080", proxy.getPort()); //$NON-NLS-1$
		Assert.assertEquals("user", proxy.getUsername()); //$NON-NLS-1$
		Assert.assertArrayEquals(new char[] { 's', 'e', 'c' }, proxy.getPassword());
		final char[] password = proxy.getPassword();
		password[0] = 'x';
		Assert.assertArrayEquals(new char[] { 's', 'e', 'c' }, proxy.getPassword());
		proxy.setPassword(null);
		Assert.assertNull(proxy.getPassword());
		Assert.assertEquals("localhost|127.0.0.1", proxy.getExcludedUrls()); //$NON-NLS-1$

		assertErrorCode(SimpleErrorCode.Internal.CANT_LOAD_HELP, "200004"); //$NON-NLS-1$
		assertErrorCode(SimpleErrorCode.Communication.EXTERNAL_REQUEST, "420001"); //$NON-NLS-1$
		assertErrorCode(SimpleErrorCode.Functional.INVALID_PROXY_CONFIG, "521010"); //$NON-NLS-1$
		assertErrorCode(SimpleErrorCode.Request.UNSUPPORTED_OPERATION, "600002"); //$NON-NLS-1$
		Assert.assertNotNull(new NoDnieFoundException());

		assertPrivateConstructor(CommandLineMessages.class);
		assertPrivateConstructor(SimpleAfirmaMessages.class);
	}

	/** Comprueba los detectores locales de tipo de dato sin depender de UI. */
	@Test
	public void testDataAnalizerUtilContracts() throws Exception {
		final byte[] cert = Files.readAllBytes(Path.of("../afirma-keystores-filters/src/test/resources/pseu-000.cer")); //$NON-NLS-1$
		Assert.assertNotNull(DataAnalizerUtil.isCertificate(cert));
		Assert.assertNotNull(DataAnalizerUtil.isCertificate(Base64.encode(cert).getBytes(StandardCharsets.UTF_8)));

		assertCertificateError(null);
		assertCertificateError(new byte[0]);
		assertCertificateError("no es un certificado".getBytes(StandardCharsets.UTF_8)); //$NON-NLS-1$

		final byte[] xml = "<root/>".getBytes(StandardCharsets.UTF_8); //$NON-NLS-1$
		final byte[] data = "no es firma".getBytes(StandardCharsets.UTF_8); //$NON-NLS-1$
		Assert.assertTrue(DataAnalizerUtil.isXML(xml));
		Assert.assertFalse(DataAnalizerUtil.isXML(data));
		Assert.assertFalse(DataAnalizerUtil.isSignedXML(data));
		Assert.assertFalse(DataAnalizerUtil.isPDF(data));
		Assert.assertFalse(DataAnalizerUtil.isSignedPDF(data));
		Assert.assertFalse(DataAnalizerUtil.isSignedBinary(data));
		Assert.assertFalse(DataAnalizerUtil.isFacturae(data));
		Assert.assertFalse(DataAnalizerUtil.isSignedFacturae(data));
		Assert.assertFalse(DataAnalizerUtil.isODF(data));
		Assert.assertFalse(DataAnalizerUtil.isSignedODF(data));
		Assert.assertFalse(DataAnalizerUtil.isOOXML(data));
		Assert.assertFalse(DataAnalizerUtil.isSignedOOXML(data));

		assertPrivateConstructor(DataAnalizerUtil.class);
	}

	private static void assertCommandLineError(final String[] args, final Class<?> expected) throws Exception {
		try {
			new CommandLineParameters(CommandLineCommand.SIGN, args);
			Assert.fail("Se esperaba error de linea de comandos"); //$NON-NLS-1$
		}
		catch (final CommandLineException e) {
			Assert.assertTrue(expected.isInstance(e));
		}
	}

	private static void assertErrorCode(final ErrorCode errorCode, final String code) {
		Assert.assertEquals(code, errorCode.getCode());
		Assert.assertNotNull(errorCode.getDescription());
		Assert.assertTrue(errorCode.toString().contains(code));
	}

	private static void assertCertificateError(final byte[] data) {
		try {
			DataAnalizerUtil.isCertificate(data);
			Assert.fail("Se esperaba rechazo del certificado"); //$NON-NLS-1$
		}
		catch (final CertificateException e) {
			Assert.assertNotNull(e.getMessage());
		}
	}

	private static void assertPrivateConstructor(final Class<?> clazz) throws Exception {
		final Constructor<?> constructor = clazz.getDeclaredConstructor();
		constructor.setAccessible(true);
		Assert.assertNotNull(constructor.newInstance());
	}
}
