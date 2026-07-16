package es.gob.afirma.standalone.ui;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.awt.Rectangle;
import java.util.List;
import java.util.Properties;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;

import javax.swing.SwingUtilities;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import es.gob.afirma.signers.pades.AOPDFSigner;
import es.gob.afirma.signers.pades.common.PdfExtraParams;
import es.gob.afirma.signvalidation.SignValidity;
import es.gob.afirma.signvalidation.SignValidity.SIGN_DETAIL_TYPE;
import es.gob.afirma.standalone.configurator.common.PreferencesManager;
import es.gob.afirma.standalone.configurator.common.PreferencesManager.PreferencesSource;
import es.gob.afirma.standalone.configurator.common.SignatureFormatPreferenceKeys;

/** Pruebas locales del panel de fichero a firmar. */
final class TestSignPanelFilePanelContracts {

	/** Comprueba construccion y contrato Scrollable sin mostrar ventanas. */
	@Test
	void signPanelFilePanelCreatesDetailsForRegularFile(@TempDir final Path tempDir) throws Exception {
		final Path file = tempDir.resolve("datos.txt"); //$NON-NLS-1$
		Files.writeString(file, "datos", StandardCharsets.UTF_8); //$NON-NLS-1$

		final SignOperationConfig config = new SignOperationConfig();
		config.setDataFile(file.toFile());
		config.setFileType(FileType.BINARY);
		config.setSignatureFormatName("CAdES"); //$NON-NLS-1$

		SwingUtilities.invokeAndWait(() -> {
			final SignPanelFilePanel panel = new SignPanelFilePanel(config);
			panel.createUI(config);

			assertTrue(panel.getComponentCount() > 0);
			assertNotNull(panel.getConfigInfoPanel());
			assertFalse(panel.isVisibleSignature());
			assertFalse(panel.isVisibleStamp());
			assertEquals(30, panel.getScrollableUnitIncrement(new Rectangle(), 0, 1));
			assertEquals(30, panel.getScrollableBlockIncrement(new Rectangle(), 0, 1));
			assertTrue(panel.getScrollableTracksViewportWidth());
			assertFalse(panel.getScrollableTracksViewportHeight());
			assertTrue(panel.getAccessibleContext().getAccessibleDescription().contains(file.toString()));
		});
	}

	/** Comprueba opciones PDF, atributos y comparacion de valores del desplegable. */
	@Test
	void signatureConfigInfoPanelBuildsPdfOptionsAndAttributes() throws Exception {
		final String previousAllowCertified = PreferencesManager.get(
				SignatureFormatPreferenceKeys.PADES_CHECK_ALLOW_CERTIFIED_PDF, PreferencesSource.USER);
		final String previousCertificationLevel = PreferencesManager.get(
				SignatureFormatPreferenceKeys.PADES_DEFAULT_CERTIFICATION_LEVEL, PreferencesSource.USER);
		final String previousVisible = PreferencesManager.get(
				SignatureFormatPreferenceKeys.PADES_VISIBLE, PreferencesSource.USER);
		final String previousStamp = PreferencesManager.get(
				SignatureFormatPreferenceKeys.PADES_STAMP, PreferencesSource.USER);

		try {
			PreferencesManager.putBoolean(SignatureFormatPreferenceKeys.PADES_CHECK_ALLOW_CERTIFIED_PDF, true);
			PreferencesManager.put(SignatureFormatPreferenceKeys.PADES_DEFAULT_CERTIFICATION_LEVEL,
					PdfExtraParams.CERTIFICATION_LEVEL_VALUE_TYPE_2);
			PreferencesManager.putBoolean(SignatureFormatPreferenceKeys.PADES_VISIBLE, true);
			PreferencesManager.putBoolean(SignatureFormatPreferenceKeys.PADES_STAMP, true);

			SwingUtilities.invokeAndWait(() -> {
				final SignatureConfigInfoPanel.ValueTextPair certLevel =
						new SignatureConfigInfoPanel.ValueTextPair(
								PdfExtraParams.CERTIFICATION_LEVEL_VALUE_TYPE_2, "Nivel 2"); //$NON-NLS-1$

				assertEquals(PdfExtraParams.CERTIFICATION_LEVEL_VALUE_TYPE_2, certLevel.getValue());
				assertEquals("Nivel 2", certLevel.toString()); //$NON-NLS-1$
				assertEquals(certLevel, new SignatureConfigInfoPanel.ValueTextPair(
						PdfExtraParams.CERTIFICATION_LEVEL_VALUE_TYPE_2));
				assertEquals(certLevel, PdfExtraParams.CERTIFICATION_LEVEL_VALUE_TYPE_2);
				assertFalse(certLevel.equals(null));
				assertEquals(5 * "Nivel 2".length() //$NON-NLS-1$
						+ 7 * PdfExtraParams.CERTIFICATION_LEVEL_VALUE_TYPE_2.length(), certLevel.hashCode());

				final SignatureConfigInfoPanel panel = new SignatureConfigInfoPanel(
						createPdfConfig(null), java.awt.Color.WHITE, null);

				assertTrue(panel.isPdfVisibleSignatureSelected());
				assertTrue(panel.isPdfStampSignatureSelected());
				assertEquals(PdfExtraParams.CERTIFICATION_LEVEL_VALUE_TYPE_2,
						panel.getPdfSignatureCertificationLevel());
				assertNotNull(panel.getAttributesPanel());
				assertNotNull(panel.getSignOptionsPanel());
				assertNotNull(panel.getSignFormatLabel());
				assertTrue(panel.getAccesibleDescription().contains("PAdES")); //$NON-NLS-1$

				final SignatureConfigInfoPanel signedPanel = new SignatureConfigInfoPanel(
						createPdfConfig(List.of(new SignValidity(SIGN_DETAIL_TYPE.OK, null, (Exception) null))),
						java.awt.Color.WHITE, null);

				assertTrue(signedPanel.isPdfVisibleSignatureSelected());
				assertTrue(signedPanel.isPdfStampSignatureSelected());
				assertNull(signedPanel.getPdfSignatureCertificationLevel());
				assertNotNull(signedPanel.getSignOptionsPanel());
			});
		}
		finally {
			restoreUserPreference(SignatureFormatPreferenceKeys.PADES_CHECK_ALLOW_CERTIFIED_PDF, previousAllowCertified);
			restoreUserPreference(SignatureFormatPreferenceKeys.PADES_DEFAULT_CERTIFICATION_LEVEL, previousCertificationLevel);
			restoreUserPreference(SignatureFormatPreferenceKeys.PADES_VISIBLE, previousVisible);
			restoreUserPreference(SignatureFormatPreferenceKeys.PADES_STAMP, previousStamp);
		}
	}

	private static SignOperationConfig createPdfConfig(final List<SignValidity> signValidity) {
		final Properties extraParams = new Properties();
		extraParams.setProperty("policyIdentifier", "2.16.724.1.3.1.1.2.1.9"); //$NON-NLS-1$ //$NON-NLS-2$
		extraParams.setProperty("signerClaimedRoles", "probador"); //$NON-NLS-1$ //$NON-NLS-2$
		extraParams.setProperty("signatureProductionCity", "Madrid"); //$NON-NLS-1$ //$NON-NLS-2$

		final SignOperationConfig config = new SignOperationConfig();
		config.setFileType(FileType.PDF);
		config.setSigner(new AOPDFSigner());
		config.setSignatureFormatName("PAdES"); //$NON-NLS-1$
		config.setExtraParams(extraParams);
		config.setSignValidity(signValidity);
		return config;
	}

	private static void restoreUserPreference(final String key, final String value) {
		if (value == null) {
			PreferencesManager.remove(key);
		}
		else {
			PreferencesManager.put(key, value);
		}
	}
}
