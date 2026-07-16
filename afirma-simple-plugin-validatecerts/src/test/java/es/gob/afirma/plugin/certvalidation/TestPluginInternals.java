package es.gob.afirma.plugin.certvalidation;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

import java.lang.reflect.Constructor;

import org.junit.jupiter.api.Test;

/** Pruebas internas del plugin de validaci&oacute;n. */
final class TestPluginInternals {

	/** Comprueba la carga de mensajes y la clase de plugin. */
	@Test
	void messagesAndPluginAreConstructible() throws Exception {
		assertEquals("Error", Messages.getString("ValidateCertAction.11")); //$NON-NLS-1$ //$NON-NLS-2$
		assertEquals("!clave.inexistente!", Messages.getString("clave.inexistente")); //$NON-NLS-1$ //$NON-NLS-2$

		final Constructor<Messages> constructor = Messages.class.getDeclaredConstructor();
		constructor.setAccessible(true);
		assertNotNull(constructor.newInstance());
		assertNotNull(new ValidateCertsPlugin());
	}
}
