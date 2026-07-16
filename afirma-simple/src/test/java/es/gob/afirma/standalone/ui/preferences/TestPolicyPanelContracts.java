package es.gob.afirma.standalone.ui.preferences;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.awt.Component;
import java.awt.Container;
import java.util.List;
import java.util.concurrent.atomic.AtomicReference;

import javax.swing.JComboBox;
import javax.swing.SwingUtilities;

import org.junit.jupiter.api.Test;

import es.gob.afirma.core.signers.AOSignConstants;
import es.gob.afirma.core.signers.AdESPolicy;

/** Pruebas locales del panel de politicas de firma. */
final class TestPolicyPanelContracts {

	/** Comprueba seleccion, edicion y guardado de politicas sin abrir ventanas. */
	@Test
	void policyPanelUpdatesFieldsAndCurrentPolicy() throws Exception {
		final AtomicReference<PolicyPanel> panelRef = new AtomicReference<>();

		SwingUtilities.invokeAndWait(() -> {
			final AdESPolicy predefined = policy("1.2.3.4", "https://example.invalid/predefinida.pdf"); //$NON-NLS-1$ //$NON-NLS-2$
			final AdESPolicy custom = policy("1.2.3.5", "https://example.invalid/custom.pdf"); //$NON-NLS-1$ //$NON-NLS-2$
			final PolicyPanel panel = new PolicyPanel(
				AOSignConstants.SIGN_FORMAT_XADES_DETACHED,
				List.of(new PolicyItem("Prefijada", predefined)), //$NON-NLS-1$
				custom,
				true,
				true,
				true,
				false
			);
			panelRef.set(panel);

			assertEquals("1.2.3.5", panel.getIdentifierField().getText()); //$NON-NLS-1$
			assertEquals("AQID", panel.getHashField().getText()); //$NON-NLS-1$
			assertEquals("SHA-256", panel.getHashAlgorithmField().getSelectedItem()); //$NON-NLS-1$
			assertTrue(panel.getIdentifierField().isEditable());
			assertFalse(panel.isNoPolicySelected());

			final JComboBox<?> combo = findCombo(panel);
			assertNotNull(combo);
			combo.setSelectedIndex(0);
			assertTrue(panel.isNoPolicySelected());
			assertNull(panel.getSelectedPolicy());
			assertFalse(panel.getIdentifierField().isEnabled());

			combo.setSelectedIndex(1);
			assertEquals("Prefijada", panel.getSelectedPolicyName()); //$NON-NLS-1$
			assertEquals("1.2.3.4", panel.getIdentifierField().getText()); //$NON-NLS-1$
			assertFalse(panel.getIdentifierField().isEditable());

			combo.setSelectedIndex(combo.getItemCount() - 1);
			panel.getIdentifierField().setText("1.2.3.6"); //$NON-NLS-1$
			panel.getHashField().setText("AQID"); //$NON-NLS-1$
			panel.getHashAlgorithmField().setSelectedItem("SHA-256"); //$NON-NLS-1$
			panel.getQualifierField().setText("https://example.invalid/nueva.pdf"); //$NON-NLS-1$
			panel.saveCurrentPolicy();

			assertEquals("1.2.3.6", panel.getCurrentPolicyItem().getPolicy().getPolicyIdentifier()); //$NON-NLS-1$
		});

		assertNotNull(panelRef.get());
	}

	private static AdESPolicy policy(final String identifier, final String qualifier) {
		return new AdESPolicy(identifier, "AQID", "SHA-256", qualifier); //$NON-NLS-1$ //$NON-NLS-2$
	}

	private static JComboBox<?> findCombo(final Container container) {
		for (final Component component : container.getComponents()) {
			if (component instanceof JComboBox<?>) {
				return (JComboBox<?>) component;
			}
			if (component instanceof Container) {
				final JComboBox<?> nested = findCombo((Container) component);
				if (nested != null) {
					return nested;
				}
			}
		}
		return null;
	}
}
