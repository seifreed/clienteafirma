package es.gob.afirma.keystores.filters.rfc;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import javax.naming.directory.BasicAttribute;
import javax.naming.directory.BasicAttributes;
import javax.naming.directory.InvalidSearchFilterException;

import org.junit.jupiter.api.Test;

/** Pruebas del parser RFC2254 local. */
final class TestSearchFilterContracts {

	/** Comprueba filtros at&oacute;micos, compuestos y negados sobre atributos reales. */
	@Test
	void searchFilterChecksAtomicCompoundAndNotExpressions() throws Exception {
		final BasicAttributes attrs = new BasicAttributes(true);
		attrs.put("cn", "Juan Perez"); //$NON-NLS-1$ //$NON-NLS-2$
		attrs.put("age", "20"); //$NON-NLS-1$ //$NON-NLS-2$
		attrs.put("mail", "juan@example.test"); //$NON-NLS-1$ //$NON-NLS-2$

		assertTrue(new SearchFilter("cn=Juan*").check(attrs)); //$NON-NLS-1$
		assertTrue(new SearchFilter("(&(cn=Juan*)(age>=18))").check(attrs)); //$NON-NLS-1$
		assertTrue(new SearchFilter("(|(cn=Otro)(age<=20))").check(attrs)); //$NON-NLS-1$
		assertTrue(new SearchFilter("(!(cn=Otro))").check(attrs)); //$NON-NLS-1$
		assertTrue(new SearchFilter("(mail=*)").check(attrs)); //$NON-NLS-1$
		assertFalse(new SearchFilter("(cn=Pedro*)").check(attrs)); //$NON-NLS-1$
		assertFalse(new SearchFilter("(missing=*)").check(attrs)); //$NON-NLS-1$
		assertFalse(new SearchFilter("(cn=Juan*)").check(null)); //$NON-NLS-1$

		assertThrows(InvalidSearchFilterException.class, () -> new SearchFilter("(cn:=Juan)")); //$NON-NLS-1$
		assertThrows(InvalidSearchFilterException.class, () -> new SearchFilter("(&(cn=Juan*)")); //$NON-NLS-1$
	}

	/** Comprueba formateo, selecci&oacute;n de atributos y escapes. */
	@Test
	void searchFilterFormatsArgumentsAndAttributes() throws Exception {
		final BasicAttributes attrs = new BasicAttributes(true);
		attrs.put(new BasicAttribute("cn", "A*B(C)\\")); //$NON-NLS-1$ //$NON-NLS-2$
		attrs.put(new BasicAttribute("empty"));
		attrs.put(new BasicAttribute("bin", new byte[] { 0x00, 0x2a })); //$NON-NLS-1$

		final String formattedAttrs = SearchFilter.format(attrs);
		assertTrue(formattedAttrs.contains("(cn=A\\2aB\\28C\\29\\5c)")); //$NON-NLS-1$
		assertTrue(formattedAttrs.contains("(empty=*)")); //$NON-NLS-1$
		assertTrue(formattedAttrs.contains("(bin=\\00\\2A)")); //$NON-NLS-1$

		assertEquals("(cn=A\\2aB)", SearchFilter.format("(cn={0})", new Object[] { "A*B" })); //$NON-NLS-1$ //$NON-NLS-2$ //$NON-NLS-3$
		assertEquals("(bin=\\00\\2A)", SearchFilter.format("(bin={0})", new Object[] { new byte[] { 0, 0x2a } })); //$NON-NLS-1$ //$NON-NLS-2$
		assertThrows(InvalidSearchFilterException.class, () -> SearchFilter.format("(cn={x})", new Object[] { "A" })); //$NON-NLS-1$ //$NON-NLS-2$
		assertThrows(InvalidSearchFilterException.class, () -> SearchFilter.format("(cn={1})", new Object[] { "A" })); //$NON-NLS-1$ //$NON-NLS-2$
		assertThrows(InvalidSearchFilterException.class, () -> SearchFilter.format("(cn={0", new Object[] { "A" })); //$NON-NLS-1$ //$NON-NLS-2$

		assertEquals(2, SearchFilter.findUnescaped('*', "ab*cd", 0)); //$NON-NLS-1$
		assertEquals(-1, SearchFilter.findUnescaped('*', "ab\\*cd", 0)); //$NON-NLS-1$
		assertSame(attrs, SearchFilter.selectAttributes(attrs, null));
		assertEquals(1, SearchFilter.selectAttributes(attrs, new String[] { "cn", "missing" }).size()); //$NON-NLS-1$ //$NON-NLS-2$
	}
}
