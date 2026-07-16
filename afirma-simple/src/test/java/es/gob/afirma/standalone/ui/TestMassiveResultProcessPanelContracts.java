package es.gob.afirma.standalone.ui;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.awt.Component;
import java.awt.Container;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

import javax.swing.JList;
import javax.swing.SwingUtilities;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/** Pruebas locales del panel de resultado de firma masiva. */
final class TestMassiveResultProcessPanelContracts {

	/** Comprueba el panel y renderizado de filas con resultado correcto y fallido. */
	@Test
	void massiveResultProcessPanelRendersSuccessfulAndFailedRows(@TempDir final Path tempDir) throws Exception {
		final Path data = tempDir.resolve("datos.txt"); //$NON-NLS-1$
		final Path signature = tempDir.resolve("datos.txt.csig"); //$NON-NLS-1$
		Files.writeString(data, "datos", StandardCharsets.UTF_8); //$NON-NLS-1$
		Files.writeString(signature, "firma", StandardCharsets.UTF_8); //$NON-NLS-1$

		final SignOperationConfig ok = new SignOperationConfig();
		ok.setDataFile(data.toFile());
		ok.setSignatureFile(signature.toFile());
		final SignOperationConfig ko = new SignOperationConfig();
		ko.setDataFile(data.toFile());

		SwingUtilities.invokeAndWait(() -> {
			final MassiveResultProcessPanel panel = new MassiveResultProcessPanel(List.of(ok, ko), tempDir.toFile(), null);
			panel.createUI(List.of(ok, ko), tempDir.toFile(), null);

			assertTrue(panel.getComponentCount() > 0);
			final JList<?> list = findList(panel);
			assertNotNull(list);
			assertEquals(2, list.getModel().getSize());
		});
	}

	private static JList<?> findList(final Container container) {
		for (final Component component : container.getComponents()) {
			if (component instanceof JList<?>) {
				return (JList<?>) component;
			}
			if (component instanceof Container) {
				final JList<?> nested = findList((Container) component);
				if (nested != null) {
					return nested;
				}
			}
		}
		return null;
	}
}
