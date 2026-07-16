package es.gob.afirma.standalone.ui;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.List;

import javax.swing.SwingUtilities;

import org.junit.jupiter.api.Test;

import es.gob.afirma.signvalidation.SignValidity;
import es.gob.afirma.signvalidation.SignValidity.SIGN_DETAIL_TYPE;
import es.gob.afirma.signvalidation.SignValidity.VALIDITY_ERROR;

/** Pruebas locales del panel de resultado de firma. */
final class TestSignResultPanelContracts {

	/** Comprueba los estados principales del panel sin mostrar ventanas. */
	@Test
	void signResultPanelCreatesUiForMainValidityStates() throws Exception {
		SwingUtilities.invokeAndWait(() -> {
			assertPanelDescriptionContains(new SignValidity(SIGN_DETAIL_TYPE.GENERATED, null), true);
			assertPanelDescriptionContains(new SignValidity(SIGN_DETAIL_TYPE.OK, null), true);
			assertPanelDescriptionContains(new SignValidity(SIGN_DETAIL_TYPE.OK, null), false);
			assertPanelDescriptionContains(new SignValidity(SIGN_DETAIL_TYPE.KO, VALIDITY_ERROR.CORRUPTED_SIGN), true);
			assertPanelDescriptionContains(new SignValidity(SIGN_DETAIL_TYPE.UNKNOWN, VALIDITY_ERROR.NO_DATA), true);
		});
	}

	private static void assertPanelDescriptionContains(final SignValidity validity, final boolean singleSign) {
		final SignResultPanel panel = new SignResultPanel(List.of(validity), singleSign, null, new byte[] { 1 });
		panel.createUI(List.of(validity), singleSign, null, new byte[] { 1 });

		assertTrue(panel.getComponentCount() >= 4);
		assertFalse(panel.getAccessibleContext().getAccessibleDescription().isEmpty());
	}
}
