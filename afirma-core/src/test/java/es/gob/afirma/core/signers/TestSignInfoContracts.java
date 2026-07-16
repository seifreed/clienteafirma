package es.gob.afirma.core.signers;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.lang.reflect.Constructor;
import java.nio.charset.StandardCharsets;
import java.util.Map;
import java.util.Properties;

import org.junit.jupiter.api.Test;

import es.gob.afirma.core.ErrorCode;
import es.gob.afirma.core.misc.Base64;
import es.gob.afirma.core.signers.asic.ASiCUtil;

/** Pruebas de contratos de informaci&oacute;n de firma. */
final class TestSignInfoContracts {

	/** Comprueba getters, setters y formato por defecto. */
	@Test
	void signInfoKeepsOptionalMetadata() {
		final AOSignInfo unknown = new AOSignInfo(null);
		assertEquals("Desconocido", unknown.getFormat()); //$NON-NLS-1$

		final AOSignInfo info = new AOSignInfo("CAdES"); //$NON-NLS-1$
		info.setVariant("Detached"); //$NON-NLS-1$
		info.setUrlSignObject("https://example.test/signature"); //$NON-NLS-1$
		info.setUrlSignedData("https://example.test/data"); //$NON-NLS-1$
		info.setB64VerificationCode("AQID"); //$NON-NLS-1$
		assertEquals("CAdES", info.getFormat()); //$NON-NLS-1$
		assertEquals("Detached", info.getVariant()); //$NON-NLS-1$
		assertEquals("https://example.test/signature", info.getUrlSignObject()); //$NON-NLS-1$
		assertEquals("https://example.test/data", info.getUrlSignedData()); //$NON-NLS-1$
		assertEquals("AQID", info.getB64VerificationCode()); //$NON-NLS-1$
	}

	/** Comprueba pol&iacute;ticas AdES sin descargas remotas. */
	@Test
	void adesPolicyKeepsExplicitValuesAndExpandsKnownPolicies() throws Exception {
		final String hash = Base64.encode("hash".getBytes(StandardCharsets.UTF_8)); //$NON-NLS-1$
		final AdESPolicy policy = new AdESPolicy(
			true,
			"urn:oid:1.2.3.4", //$NON-NLS-1$
			hash,
			"SHA-256", //$NON-NLS-1$
			"https://example.com/policy.pdf" //$NON-NLS-1$
		);
		assertEquals("urn:oid:1.2.3.4", policy.getPolicyIdentifier()); //$NON-NLS-1$
		assertEquals(hash, policy.getPolicyIdentifierHash());
		assertEquals("SHA-256", policy.getPolicyIdentifierHashAlgorithm()); //$NON-NLS-1$
		assertEquals("https://example.com/policy.pdf", policy.getPolicyQualifier().toString()); //$NON-NLS-1$
		assertTrue(policy.isPredefined());
		assertTrue(policy.toString().contains("urn:oid:1.2.3.4")); //$NON-NLS-1$
		assertEquals(policy, new AdESPolicy("urn:oid:1.2.3.4", hash, "SHA-256", null)); //$NON-NLS-1$ //$NON-NLS-2$
		assertEquals(policy.hashCode(), new AdESPolicy("urn:oid:1.2.3.4", hash, "SHA-256", null).hashCode()); //$NON-NLS-1$ //$NON-NLS-2$
		assertFalse(policy.equals("urn:oid:1.2.3.4")); //$NON-NLS-1$

		final Properties extra = policy.asExtraParams();
		assertEquals("urn:oid:1.2.3.4", extra.getProperty("policyIdentifier")); //$NON-NLS-1$ //$NON-NLS-2$
		assertEquals(hash, extra.getProperty("policyIdentifierHash")); //$NON-NLS-1$
		assertEquals("SHA-256", extra.getProperty("policyIdentifierHashAlgorithm")); //$NON-NLS-1$ //$NON-NLS-2$
		assertEquals("https://example.com/policy.pdf", extra.get("policyQualifier").toString()); //$NON-NLS-1$ //$NON-NLS-2$
		assertEquals(policy, AdESPolicy.buildAdESPolicy(extra));
		assertNull(AdESPolicy.buildAdESPolicy(new Properties()));
		assertThrows(IllegalArgumentException.class, () -> AdESPolicy.buildAdESPolicy(null));
		assertThrows(IllegalArgumentException.class, () -> new AdESPolicy("", hash, "SHA-256", null)); //$NON-NLS-1$ //$NON-NLS-2$
		assertThrows(IllegalArgumentException.class, () -> new AdESPolicy("urn:oid:1.2.3.4", "no-base64", "SHA-256", null)); //$NON-NLS-1$ //$NON-NLS-2$ //$NON-NLS-3$
		assertThrows(IllegalArgumentException.class, () -> new AdESPolicy("urn:oid:1.2.3.4", hash, null, null)); //$NON-NLS-1$
		assertThrows(IllegalArgumentException.class, () -> new AdESPolicy("urn:oid:1.2.3.4", hash, "SHA-256", "bad-url")); //$NON-NLS-1$ //$NON-NLS-2$ //$NON-NLS-3$

		final Properties expanded = new Properties();
		expanded.setProperty("policyIdentifier", "previo"); //$NON-NLS-1$ //$NON-NLS-2$
		AdESPolicyPropertiesManager.setProperties(
			expanded,
			AdESPolicyPropertiesManager.POLICY_ID_AGE,
			AdESPolicyPropertiesManager.FORMAT_CADES
		);
		assertEquals("urn:oid:2.16.724.1.3.1.1.2.1.9", expanded.getProperty("policyIdentifier")); //$NON-NLS-1$ //$NON-NLS-2$
		assertEquals("G7roucf600+f03r/o0bAOQ6WAs0=", expanded.getProperty("policyIdentifierHash")); //$NON-NLS-1$ //$NON-NLS-2$
		assertEquals("http://www.w3.org/2000/09/xmldsig#sha1", expanded.getProperty("policyIdentifierHashAlgorithm")); //$NON-NLS-1$ //$NON-NLS-2$
		assertTrue(AdESPolicyPropertiesManager.isAgePolicyConfigurated(expanded.getProperty("policyIdentifier"))); //$NON-NLS-1$
		assertFalse(AdESPolicyPropertiesManager.isAgePolicyConfigurated(null));
		assertFalse(AdESPolicyPropertiesManager.isAgePolicyConfigurated("urn:oid:9.9.9")); //$NON-NLS-1$

		final Constructor<AdESPolicyPropertiesManager> constructor = AdESPolicyPropertiesManager.class.getDeclaredConstructor();
		constructor.setAccessible(true);
		assertNotNull(constructor.newInstance());
	}

	/** Comprueba el mapeo local de errores trif&aacute;sicos devueltos por servidor. */
	@Test
	void triphaseExceptionsMapServerErrorsToErrorCodes() {
		final AOTriphaseException presign = AOTriphaseException.parsePresignException(
			"ERR-1", //$NON-NLS-1$
			"prefirma", //$NON-NLS-1$
			IllegalStateException.class.getName()
		);
		assertEquals("prefirma", presign.getMessage()); //$NON-NLS-1$
		assertEquals(IllegalStateException.class.getName(), presign.getServerExceptionClassname());
		assertEquals(ErrorCode.ThirdParty.TRI_SERVER_PRESIGN_ERROR_1, presign.getErrorCode());

		assertEquals(
			ErrorCode.ThirdParty.TRI_SERVER_PRESIGN_ERROR_20,
			AOTriphaseException.parsePresignException(20, "prefirma", new IOException("causa")).getErrorCode() //$NON-NLS-1$ //$NON-NLS-2$
		);
		assertEquals(
			ErrorCode.ThirdParty.TRI_SERVER_UNKNOWN_PRESIGN_ERROR,
			AOTriphaseException.parsePresignException("ERR-99", "prefirma", "Servidor").getErrorCode() //$NON-NLS-1$ //$NON-NLS-2$ //$NON-NLS-3$
		);
		assertEquals(
			ErrorCode.ThirdParty.TRI_SERVER_POSTSIGN_ERROR_1,
			AOTriphaseException.parsePostsignException("ERR-1", "postfirma", "Servidor").getErrorCode() //$NON-NLS-1$ //$NON-NLS-2$ //$NON-NLS-3$
		);
		assertEquals(
			ErrorCode.ThirdParty.TRI_SERVER_POSTSIGN_ERROR_20,
			AOTriphaseException.parsePostsignException("ERR-20", "postfirma", "Servidor").getErrorCode() //$NON-NLS-1$ //$NON-NLS-2$ //$NON-NLS-3$
		);
		assertEquals(
			ErrorCode.ThirdParty.TRI_SERVER_UNKNOWN_POSTSIGN_ERROR,
			AOTriphaseException.parsePostsignException("ERR-99", "postfirma", "Servidor").getErrorCode() //$NON-NLS-1$ //$NON-NLS-2$ //$NON-NLS-3$
		);
	}

	/** Comprueba contratos locales de la factor&iacute;a de firmadores. */
	@Test
	void signerFactoryFindsCoreSignerAndRejectsInvalidInput() throws Exception {
		final String[] formats = AOSignerFactory.getSupportedFormats();
		assertTrue(formats.length > 0);
		assertEquals(AOSignConstants.SIGN_FORMAT_CADES, formats[0]);
		formats[0] = "modificado"; //$NON-NLS-1$
		assertEquals(AOSignConstants.SIGN_FORMAT_CADES, AOSignerFactory.getSupportedFormats()[0]);

		final AOSigner pkcs1 = AOSignerFactory.getSigner(AOSignConstants.SIGN_FORMAT_PKCS1);
		assertNotNull(pkcs1);
		assertEquals(AOSignConstants.SIGN_FORMAT_PKCS1, AOSignerFactory.getSignFormat(pkcs1));
		assertSame(pkcs1, AOSignerFactory.getSigner(AOSignConstants.SIGN_FORMAT_PKCS1));
		assertNotNull(AOSignerFactory.getSigner(AOSignConstants.SIGN_FORMAT_PKCS1.toLowerCase()));

		assertNull(AOSignerFactory.getSigner("desconocido")); //$NON-NLS-1$
		assertNull(AOSignerFactory.getSigner("datos".getBytes(StandardCharsets.UTF_8))); //$NON-NLS-1$
		assertNull(AOSignerFactory.getSigner("datos".getBytes(StandardCharsets.UTF_8), new Properties())); //$NON-NLS-1$
		assertThrows(IllegalArgumentException.class, () -> AOSignerFactory.getSigner((byte[]) null));
		assertThrows(IllegalArgumentException.class, () -> AOSignerFactory.getSigner(null, new Properties()));

		final Constructor<AOSignerFactory> constructor = AOSignerFactory.class.getDeclaredConstructor();
		constructor.setAccessible(true);
		assertNotNull(constructor.newInstance());
	}

	/** Comprueba contratos locales de los firmadores PKCS#1. */
	@Test
	void pkcs1SignersExposeLocalContracts() {
		final AOPkcs1Signer pkcs1 = new AOPkcs1Signer();
		assertFalse(pkcs1.isSign("firma".getBytes(StandardCharsets.UTF_8))); //$NON-NLS-1$
		assertFalse(pkcs1.isSign("firma".getBytes(StandardCharsets.UTF_8), new Properties())); //$NON-NLS-1$
		assertFalse(pkcs1.isValidDataFile(null));
		assertFalse(pkcs1.isValidDataFile(new byte[0]));
		assertTrue(pkcs1.isValidDataFile("datos".getBytes(StandardCharsets.UTF_8))); //$NON-NLS-1$
		assertEquals("signature.p1", pkcs1.getSignedName(null, "-firmado")); //$NON-NLS-1$ //$NON-NLS-2$
		assertEquals("documento-firmado.p1", pkcs1.getSignedName("documento", "-firmado")); //$NON-NLS-1$ //$NON-NLS-2$ //$NON-NLS-3$
		assertEquals("documento-nuevo.p1", pkcs1.getSignedName("documento.p1", "-nuevo")); //$NON-NLS-1$ //$NON-NLS-2$ //$NON-NLS-3$
		assertThrows(IllegalArgumentException.class, () -> pkcs1.sign(new byte[0], null, null, null, null));
		assertThrows(UnsupportedOperationException.class, () -> pkcs1.getData(new byte[0]));
		assertThrows(UnsupportedOperationException.class, () -> pkcs1.getData(new byte[0], new Properties()));
		assertThrows(UnsupportedOperationException.class, () -> pkcs1.getSignInfo(new byte[0]));
		assertThrows(UnsupportedOperationException.class, () -> pkcs1.getSignInfo(new byte[0], new Properties()));
		assertThrows(UnsupportedOperationException.class, () -> pkcs1.cosign(new byte[0], new byte[0], "SHA256withRSA", null, null, null)); //$NON-NLS-1$
		assertThrows(UnsupportedOperationException.class, () -> pkcs1.cosign(new byte[0], "SHA256withRSA", null, null, null)); //$NON-NLS-1$
		assertThrows(UnsupportedOperationException.class, () -> pkcs1.countersign(new byte[0], "SHA256withRSA", CounterSignTarget.LEAFS, null, null, null, null)); //$NON-NLS-1$
		assertThrows(UnsupportedOperationException.class, () -> pkcs1.getSignersStructure(new byte[0], false));
		assertThrows(UnsupportedOperationException.class, () -> pkcs1.getSignersStructure(new byte[0], new Properties(), false));

		final AOPkcs1TriPhaseSigner tri = new AOPkcs1TriPhaseSigner();
		assertFalse(tri.isSign("firma".getBytes(StandardCharsets.UTF_8))); //$NON-NLS-1$
		assertFalse(tri.isSign("firma".getBytes(StandardCharsets.UTF_8), new Properties())); //$NON-NLS-1$
		assertFalse(tri.isValidDataFile(null));
		assertTrue(tri.isValidDataFile(new byte[0]));
		assertEquals("documento-firmado.p1", tri.getSignedName("documento", "-firmado")); //$NON-NLS-1$ //$NON-NLS-2$ //$NON-NLS-3$
		assertEquals("documento.p1", tri.getSignedName("documento", null)); //$NON-NLS-1$ //$NON-NLS-2$
		assertThrows(IllegalArgumentException.class, () -> tri.sign(new byte[0], "SHA256withRSA", null, null, null)); //$NON-NLS-1$
		assertThrows(IllegalArgumentException.class, () -> tri.sign(new byte[0], "SHA256withRSA", null, null, new Properties())); //$NON-NLS-1$
		assertThrows(UnsupportedOperationException.class, () -> tri.getData(new byte[0]));
		assertThrows(UnsupportedOperationException.class, () -> tri.getData(new byte[0], new Properties()));
		assertThrows(UnsupportedOperationException.class, () -> tri.getSignInfo(new byte[0]));
		assertThrows(UnsupportedOperationException.class, () -> tri.getSignInfo(new byte[0], new Properties()));
		assertThrows(UnsupportedOperationException.class, () -> tri.cosign(new byte[0], new byte[0], "SHA256withRSA", null, null, null)); //$NON-NLS-1$
		assertThrows(UnsupportedOperationException.class, () -> tri.cosign(new byte[0], "SHA256withRSA", null, null, null)); //$NON-NLS-1$
		assertThrows(UnsupportedOperationException.class, () -> tri.countersign(new byte[0], "SHA256withRSA", CounterSignTarget.LEAFS, null, null, null, null)); //$NON-NLS-1$
		assertThrows(UnsupportedOperationException.class, () -> tri.getSignersStructure(new byte[0], false));
		assertThrows(UnsupportedOperationException.class, () -> tri.getSignersStructure(new byte[0], new Properties(), false));
	}

	/** Comprueba contenedores ASiC-S creados en memoria. */
	@Test
	void asicUtilCreatesAndReadsSContainers() throws Exception {
		final byte[] signature = "firma".getBytes(StandardCharsets.UTF_8); //$NON-NLS-1$
		final byte[] xmlSignature = "<sig/>".getBytes(StandardCharsets.UTF_8); //$NON-NLS-1$
		final byte[] data = "datos".getBytes(StandardCharsets.UTF_8); //$NON-NLS-1$

		assertTrue(ASiCUtil.getASiCSDefaultDataFilename("<r/>".getBytes(StandardCharsets.UTF_8)).startsWith("dataobject.")); //$NON-NLS-1$ //$NON-NLS-2$
		assertTrue(ASiCUtil.isDataEntry("documento.txt")); //$NON-NLS-1$
		assertFalse(ASiCUtil.isDataEntry(ASiCUtil.ENTRY_NAME_BINARY_SIGNATURE));
		assertFalse(ASiCUtil.isDataEntry(ASiCUtil.ENTRY_NAME_XML_SIGNATURE));
		assertFalse(ASiCUtil.isDataEntry("mimetype")); //$NON-NLS-1$

		final byte[] binaryContainer = ASiCUtil.createSContainer(signature, data, null, "documento.txt"); //$NON-NLS-1$
		assertArrayEquals(signature, ASiCUtil.getASiCSBinarySignature(binaryContainer));
		final Map<String, byte[]> signedData = ASiCUtil.getASiCSData(binaryContainer);
		assertArrayEquals(data, signedData.get("documento.txt")); //$NON-NLS-1$
		assertEquals("documento.txt", ASiCUtil.getASiCSDataFilename(binaryContainer)); //$NON-NLS-1$

		final byte[] xmlContainer = ASiCUtil.createSContainer(xmlSignature, data, ASiCUtil.ENTRY_NAME_XML_SIGNATURE, null);
		assertArrayEquals(xmlSignature, ASiCUtil.getASiCSXMLSignature(xmlContainer));
		assertTrue(ASiCUtil.getASiCSDataFilename(xmlContainer).startsWith("dataobject.")); //$NON-NLS-1$

		assertThrows(IllegalArgumentException.class, () -> ASiCUtil.createSContainer(null, data, null, null));
		assertThrows(IllegalArgumentException.class, () -> ASiCUtil.createSContainer(signature, null, null, null));
		assertThrows(IllegalArgumentException.class, () -> ASiCUtil.getASiCSBinarySignature(null));
		assertThrows(IOException.class, () -> ASiCUtil.getASiCSXMLSignature(binaryContainer));
		assertThrows(IOException.class, () -> ASiCUtil.getASiCSData("no zip".getBytes(StandardCharsets.UTF_8))); //$NON-NLS-1$
		assertThrows(IOException.class, () -> ASiCUtil.getASiCSDataFilename("no zip".getBytes(StandardCharsets.UTF_8))); //$NON-NLS-1$

		final Constructor<ASiCUtil> constructor = ASiCUtil.class.getDeclaredConstructor();
		constructor.setAccessible(true);
		assertNotNull(constructor.newInstance());
	}
}
