package es.gob.afirma.triphase.signer.processors;

import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.nio.file.Files;
import java.nio.file.Path;

import org.junit.jupiter.api.Test;

import es.gob.afirma.core.signers.AOSignConstants;

/** Pruebas locales de seleccion de preprocesadores trifasicos. */
final class TestPreProcessorFactoryContracts {

	/** Comprueba seleccion por formato declarado y por datos. */
	@Test
	void selectsPreProcessorByFormatAndData() throws Exception {
		assertInstanceOf(PAdESTriPhasePreProcessor.class, PreProcessorFactory.getPreProcessor(AOSignConstants.SIGN_FORMAT_PADES));
		assertInstanceOf(PAdESTriPhasePreProcessor.class, PreProcessorFactory.getPreProcessor(AOSignConstants.SIGN_FORMAT_PADES_TRI));
		assertInstanceOf(CAdESTriPhasePreProcessor.class, PreProcessorFactory.getPreProcessor(AOSignConstants.SIGN_FORMAT_CADES));
		assertInstanceOf(CAdESTriPhasePreProcessor.class, PreProcessorFactory.getPreProcessor(AOSignConstants.SIGN_FORMAT_CADES_TRI));
		assertInstanceOf(XAdESTriPhasePreProcessor.class, PreProcessorFactory.getPreProcessor(AOSignConstants.SIGN_FORMAT_XADES));
		assertInstanceOf(XAdESTriPhasePreProcessor.class, PreProcessorFactory.getPreProcessor(AOSignConstants.SIGN_FORMAT_XADES_TRI));
		assertInstanceOf(CAdESASiCSTriPhasePreProcessor.class, PreProcessorFactory.getPreProcessor(AOSignConstants.SIGN_FORMAT_CADES_ASIC_S));
		assertInstanceOf(CAdESASiCSTriPhasePreProcessor.class, PreProcessorFactory.getPreProcessor(AOSignConstants.SIGN_FORMAT_CADES_ASIC_S_TRI));
		assertInstanceOf(XAdESASiCSTriPhasePreProcessor.class, PreProcessorFactory.getPreProcessor(AOSignConstants.SIGN_FORMAT_XADES_ASIC_S));
		assertInstanceOf(XAdESASiCSTriPhasePreProcessor.class, PreProcessorFactory.getPreProcessor(AOSignConstants.SIGN_FORMAT_XADES_ASIC_S_TRI));
		assertInstanceOf(FacturaETriPhasePreProcessor.class, PreProcessorFactory.getPreProcessor(AOSignConstants.SIGN_FORMAT_FACTURAE));
		assertInstanceOf(FacturaETriPhasePreProcessor.class, PreProcessorFactory.getPreProcessor(AOSignConstants.SIGN_FORMAT_FACTURAE_TRI));
		assertInstanceOf(FacturaETriPhasePreProcessor.class, PreProcessorFactory.getPreProcessor(AOSignConstants.SIGN_FORMAT_FACTURAE_ALT1));
		assertInstanceOf(Pkcs1TriPhasePreProcessor.class, PreProcessorFactory.getPreProcessor(AOSignConstants.SIGN_FORMAT_PKCS1));
		assertInstanceOf(Pkcs1TriPhasePreProcessor.class, PreProcessorFactory.getPreProcessor(AOSignConstants.SIGN_FORMAT_PKCS1_TRI));

		assertInstanceOf(PAdESTriPhasePreProcessor.class, PreProcessorFactory.getPreProcessor(
			Files.readAllBytes(Path.of("../afirma-crypto-pdf/src/test/resources/TEST_PDF.pdf")) //$NON-NLS-1$
		));
		assertInstanceOf(XAdESTriPhasePreProcessor.class, PreProcessorFactory.getPreProcessor("<root/>".getBytes())); //$NON-NLS-1$
		assertInstanceOf(CAdESTriPhasePreProcessor.class, PreProcessorFactory.getPreProcessor("texto".getBytes())); //$NON-NLS-1$

		assertThrows(IllegalArgumentException.class, () -> PreProcessorFactory.getPreProcessor((byte[]) null));
		assertThrows(IllegalArgumentException.class, () -> PreProcessorFactory.getPreProcessor(new byte[0]));
		assertThrows(IllegalArgumentException.class, () -> PreProcessorFactory.getPreProcessor("no-soportado")); //$NON-NLS-1$
	}

}
