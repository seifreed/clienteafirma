package es.gob.afirma.standalone.configurator.common.xmlwise;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.lang.reflect.Constructor;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.Test;

/** Pruebas de contratos locales del parser XML/plist. */
final class TestXmlwiseContracts {

	/** Comprueba parseo, atributos y serializaci&oacute;n XML b&aacute;sica. */
	@Test
	void xmlElementsExposeAttributesChildrenAndEscaping() throws Exception {
		final XmlElement root = Xmlwise.createXml(
			"<root int='7' real='2.5' yes='yes' no='n'><child>texto</child></root>" //$NON-NLS-1$
		);

		assertEquals("root", root.getName()); //$NON-NLS-1$
		assertTrue(root.contains("child")); //$NON-NLS-1$
		assertEquals("texto", root.getUnique("child").getValue()); //$NON-NLS-1$ //$NON-NLS-2$
		assertEquals(7, root.getIntAttribute("int")); //$NON-NLS-1$
		assertEquals(9, root.getIntAttribute("missing", 9)); //$NON-NLS-1$
		assertEquals(2.5d, root.getDoubleAttribute("real")); //$NON-NLS-1$
		assertEquals(3.5d, root.getDoubleAttribute("missing", 3.5d)); //$NON-NLS-1$
		assertTrue(root.getBoolAttribute("yes")); //$NON-NLS-1$
		assertFalse(root.getBoolAttribute("no")); //$NON-NLS-1$
		assertTrue(root.getBoolAttribute("missing", true)); //$NON-NLS-1$
		assertEquals("fallback", root.getAttribute("missing", "fallback")); //$NON-NLS-1$ //$NON-NLS-2$

		root.setAttribute("escaped", "<&\"'"); //$NON-NLS-1$ //$NON-NLS-2$
		assertTrue(root.containsAttribute("escaped")); //$NON-NLS-1$
		assertTrue(root.toXml().contains("&lt;&amp;&quot;&apos;")); //$NON-NLS-1$
		assertTrue(root.removeAttribute("escaped")); //$NON-NLS-1$
		assertFalse(root.removeAttribute("escaped")); //$NON-NLS-1$

		assertEquals(
			"&lt;&gt;&amp;&quot;&apos;",
			Xmlwise.escapeXML("<>&\"'") //$NON-NLS-1$ //$NON-NLS-2$
		);
		assertThrows(XmlParseException.class, () -> Xmlwise.createXml("<root>")); //$NON-NLS-1$
		assertThrows(XmlParseException.class, () -> root.getUnique("missing")); //$NON-NLS-1$
		assertThrows(XmlParseException.class, () -> root.getIntAttribute("missing")); //$NON-NLS-1$
		assertThrows(XmlParseException.class, () -> root.getBoolAttribute("int")); //$NON-NLS-1$

		final XmlElement fromBytes = Xmlwise.createXml("<bytes/>".getBytes(StandardCharsets.UTF_8)); //$NON-NLS-1$
		assertEquals("bytes", fromBytes.getName()); //$NON-NLS-1$
		assertNotNull(Xmlwise.createXml(Xmlwise.createDocument("<doc/>"))); //$NON-NLS-1$
		assertPrivateConstructor(Xmlwise.class);
	}

	/** Comprueba parseo y emisi&oacute;n de plist con tipos simples y compuestos. */
	@Test
	void plistParsesAndSerializesSupportedTypes() throws Exception {
		final String plist =
			"<plist><dict>" + //$NON-NLS-1$
			"<key>entero</key><integer>5</integer>" + //$NON-NLS-1$
			"<key>largo</key><integer>2147483648</integer>" + //$NON-NLS-1$
			"<key>real</key><real>1.5</real>" + //$NON-NLS-1$
			"<key>texto</key><string>hola</string>" + //$NON-NLS-1$
			"<key>verdadero</key><true/>" + //$NON-NLS-1$
			"<key>falso</key><false/>" + //$NON-NLS-1$
			"<key>binario</key><data>AQI=</data>" + //$NON-NLS-1$
			"<key>lista</key><array><string>a</string><false/></array>" + //$NON-NLS-1$
			"</dict></plist>"; //$NON-NLS-1$

		final Map<String, Object> parsed = Plist.fromXml(plist.getBytes(StandardCharsets.UTF_8));
		assertEquals(Integer.valueOf(5), parsed.get("entero")); //$NON-NLS-1$
		assertEquals(Long.valueOf(2147483648L), parsed.get("largo")); //$NON-NLS-1$
		assertEquals(Double.valueOf(1.5d), parsed.get("real")); //$NON-NLS-1$
		assertEquals("hola", parsed.get("texto")); //$NON-NLS-1$ //$NON-NLS-2$
		assertEquals(Boolean.TRUE, parsed.get("verdadero")); //$NON-NLS-1$
		assertEquals(Boolean.FALSE, parsed.get("falso")); //$NON-NLS-1$
		assertArrayEquals(new byte[] { 1, 2 }, (byte[]) parsed.get("binario")); //$NON-NLS-1$
		assertEquals(List.of("a", Boolean.FALSE), parsed.get("lista")); //$NON-NLS-1$ //$NON-NLS-2$

		final XmlElement xml = Plist.objectToXml(Map.of("clave", List.of("valor", Boolean.FALSE))); //$NON-NLS-1$ //$NON-NLS-2$
		assertEquals("dict", xml.getName()); //$NON-NLS-1$
		assertTrue(xml.toXml().contains("<key>clave</key>")); //$NON-NLS-1$
		assertEquals("<false/>", Plist.objectToXml(Boolean.FALSE).toXml()); //$NON-NLS-1$
		assertEquals("AQI=", Plist.base64encode(new byte[] { 1, 2 })); //$NON-NLS-1$
		assertArrayEquals(new byte[] { 1, 2 }, Plist.base64decode("AQI=")); //$NON-NLS-1$

		assertThrows(RuntimeException.class, () -> Plist.objectToXml(new Object()));
		assertThrows(XmlParseException.class, () -> Plist.fromXml("<root/>".getBytes(StandardCharsets.UTF_8))); //$NON-NLS-1$
	}

	private static void assertPrivateConstructor(final Class<?> clazz) throws Exception {
		final Constructor<?> constructor = clazz.getDeclaredConstructor();
		constructor.setAccessible(true);
		assertNotNull(constructor.newInstance());
	}
}
