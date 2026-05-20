package es.gob.afirma.standalone.ui.pdf;

import org.junit.Test;

/** Pruebas del UI de firma PDF visible.
 * @author Tom&aacute;s Garc&iacute;a-Mer&aacute;s. */
public final class UiTester {

	private final static boolean IS_SIGN = false;
	private final static boolean IS_MASSIVE_SIGN = false;

	/** Prueba de di&aacute;logo fallido. */
	@Test
	public void testFailedDialog() {
		SignPdfDialog.getVisibleSignatureExtraParams(IS_SIGN, IS_MASSIVE_SIGN, new byte[] { (byte) 0xff, (byte) 0xff, (byte) 0xff }, null, true, false, false, extraParams -> {
			// Vacio
		});
	}

}
