/* Copyright (C) 2011 [Gobierno de Espana]
 * This file is part of "Cliente @Firma".
 * "Cliente @Firma" is free software; you can redistribute it and/or modify it under the terms of:
 *   - the GNU General Public License as published by the Free Software Foundation;
 *     either version 2 of the License, or (at your option) any later version.
 *   - or The European Software License; either version 1.1 or (at your option) any later version.
 * You may contact the copyright holder at: soporte.afirma@seap.minhap.es
 */

package es.gob.afirma.core.signers;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.io.IOException;
import java.lang.reflect.Constructor;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Properties;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import es.gob.afirma.core.SignaturePolicyIncompatibilityException;
import es.gob.afirma.core.misc.Base64;

/** Pruebas del paso de propiedades desde JavaScript a Java. */
final class TestExtraParamsProcessor {

    /** Prueba del paso de propiedades desde String con l&iacute;neas delimitadas por <code>\n</code> a <code>Properties</code> de Java. */
	@Test
	void testExtraParamProcessor() throws Exception {

		final String entries =
				"Clave1=valor\n" + //$NON-NLS-1$
				"2=valor\n" + //$NON-NLS-1$
				"clave3=v\n" + //$NON-NLS-1$
				"4=v\n" + //$NON-NLS-1$
				"=v\n" + //$NON-NLS-1$
				"5=\n" + //$NON-NLS-1$
				"=\n" + //$NON-NLS-1$
				"\n" + //$NON-NLS-1$
				"=valor\n" + //$NON-NLS-1$
				"clave6=\n" + //$NON-NLS-1$
				"clave7=val=or\n" + //$NON-NLS-1$
				"clave8=valor\n" + //$NON-NLS-1$
				"cla=ve9=valor\n" + //$NON-NLS-1$
				"clave0\n"; //$NON-NLS-1$

		final Properties params = ExtraParamsProcessor.convertToProperties(entries);
		assertNotNull(params);

		assertEquals(11, params.size());
		assertEquals("valor", params.getProperty("Clave1")); //$NON-NLS-1$ //$NON-NLS-2$
		assertEquals("val=or", params.getProperty("clave7")); //$NON-NLS-1$ //$NON-NLS-2$
		assertEquals("", params.getProperty("clave6")); //$NON-NLS-1$ //$NON-NLS-2$
		assertEquals(0, ExtraParamsProcessor.convertToProperties(null).size());

		final Properties expanded = new Properties();
		expanded.setProperty("sinExpandir", "valor"); //$NON-NLS-1$ //$NON-NLS-2$
		assertEquals("valor", ExtraParamsProcessor.expandProperties(expanded).getProperty("sinExpandir")); //$NON-NLS-1$ //$NON-NLS-2$
		assertFalse(ExtraParamsProcessor.expandProperties(expanded).containsKey("expPolicy")); //$NON-NLS-1$

		final Constructor<ExtraParamsProcessor> constructor = ExtraParamsProcessor.class.getDeclaredConstructor();
		constructor.setAccessible(true);
		assertNotNull(constructor.newInstance());
	}

	/** Comprueba la expansi&oacute;n de pol&iacute;ticas y la carga de binarios desde extraParams. */
	@Test
	void expandsPoliciesAndLoadsBinaryExtraParams(@TempDir final Path tempDir) throws Exception {
		final Properties cades = new Properties();
		cades.setProperty("expPolicy", AdESPolicyPropertiesManager.POLICY_ID_AGE); //$NON-NLS-1$
		cades.setProperty("profile", AOSignConstants.SIGN_PROFILE_BASELINE); //$NON-NLS-1$
		final Properties expandedCades = ExtraParamsProcessor.expandProperties(
			cades,
			"datos".getBytes(StandardCharsets.UTF_8), //$NON-NLS-1$
			AOSignConstants.SIGN_FORMAT_CADES_TRI
		);
		assertEquals(AOSignConstants.SIGN_MODE_IMPLICIT, expandedCades.getProperty("mode")); //$NON-NLS-1$
		assertEquals(AOSignConstants.SIGN_PROFILE_ADVANCED, expandedCades.getProperty("profile")); //$NON-NLS-1$
		assertEquals("urn:oid:2.16.724.1.3.1.1.2.1.9", expandedCades.getProperty("policyIdentifier")); //$NON-NLS-1$ //$NON-NLS-2$
		assertFalse(expandedCades.containsKey("expPolicy")); //$NON-NLS-1$

		final Properties xades = new Properties();
		xades.setProperty("expPolicy", AdESPolicyPropertiesManager.POLICY_ID_AGE_1_8); //$NON-NLS-1$
		xades.setProperty("format", AOSignConstants.SIGN_FORMAT_XADES_ENVELOPED); //$NON-NLS-1$
		assertEquals(
			AOSignConstants.SIGN_FORMAT_XADES_ENVELOPED,
			ExtraParamsProcessor.expandProperties(xades, null, AOSignConstants.SIGN_FORMAT_XADES).getProperty("format") //$NON-NLS-1$
		);

		final Properties pades = new Properties();
		pades.setProperty("expPolicy", AdESPolicyPropertiesManager.POLICY_ID_AGE); //$NON-NLS-1$
		assertEquals(
			"ETSI.CAdES.detached", //$NON-NLS-1$
			ExtraParamsProcessor.expandProperties(pades, null, AOSignConstants.SIGN_FORMAT_PDF).getProperty("signatureSubFilter") //$NON-NLS-1$
		);

		final Properties badPolicy = new Properties();
		badPolicy.setProperty("expPolicy", "desconocida"); //$NON-NLS-1$ //$NON-NLS-2$
		assertThrows(
			SignaturePolicyIncompatibilityException.class,
			() -> ExtraParamsProcessor.expandProperties(badPolicy, null, AOSignConstants.SIGN_FORMAT_CADES)
		);

		final Properties incompatiblePades = new Properties();
		incompatiblePades.setProperty("expPolicy", AdESPolicyPropertiesManager.POLICY_ID_AGE); //$NON-NLS-1$
		incompatiblePades.setProperty("signatureSubFilter", "otro"); //$NON-NLS-1$ //$NON-NLS-2$
		assertThrows(
			SignaturePolicyIncompatibilityException.class,
			() -> ExtraParamsProcessor.expandProperties(incompatiblePades, null, AOSignConstants.SIGN_FORMAT_PADES)
		);

		final Properties base64Param = new Properties();
		base64Param.setProperty("dato", Base64.encode("abc".getBytes(StandardCharsets.UTF_8))); //$NON-NLS-1$ //$NON-NLS-2$
		assertArrayEquals("abc".getBytes(StandardCharsets.UTF_8), ExtraParamsProcessor.loadByteArrayFromExtraParams(base64Param, "dato", true)); //$NON-NLS-1$ //$NON-NLS-2$

		final Path binary = tempDir.resolve("dato.bin"); //$NON-NLS-1$
		Files.write(binary, "archivo".getBytes(StandardCharsets.UTF_8)); //$NON-NLS-1$
		final Properties fileParam = new Properties();
		fileParam.setProperty("dato", binary.toString()); //$NON-NLS-1$
		assertArrayEquals("archivo".getBytes(StandardCharsets.UTF_8), ExtraParamsProcessor.loadByteArrayFromExtraParams(fileParam, "dato", false)); //$NON-NLS-1$ //$NON-NLS-2$
		assertThrows(IOException.class, () -> ExtraParamsProcessor.loadByteArrayFromExtraParams(new Properties(), "dato", true)); //$NON-NLS-1$
	}
}
