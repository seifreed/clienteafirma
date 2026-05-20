package es.gob.afirma.standalone.ui.pdf;

import java.awt.Dimension;
import java.awt.GraphicsEnvironment;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.swing.JFrame;

import org.junit.Assume;
import org.junit.Test;

import com.aowagie.text.pdf.PdfReader;

import es.gob.afirma.core.misc.AOUtil;
import es.gob.afirma.standalone.ui.pdf.PdfLoader.PdfLoaderListener;

/** Pruebas del Conversor de PDF a conjunto de im&aacute;genes.
 * @author Tom&aacute;s Garc&iacute;a-Mer&aacute;s. */
public final class Pdf2ImagesConverterTests {

	private final static String TEST_FILE = "sec1-v2.pdf"; //$NON-NLS-1$
	private final static boolean IS_SIGN = false;
	private final static boolean IS_MASSIVE_SIGN = false;

	static final Logger LOGGER = Logger.getLogger("es.gob.afirma"); //$NON-NLS-1$

	/** Prueba gr&aacute;fica de la conversi&oacute; en segundo plano de PDF a im&aacute;genes.
	 * @throws Exception En cualquier error. */
	@Test
	public void testPdfLoadUi() throws Exception {

		// Test gráfico: skip cuando no hay display (CI Linux headless,
		// contenedores). Crear un JFrame en modo headless lanza HeadlessException
		// y es ortogonal a la lógica que se está probando.
		Assume.assumeFalse("PDF UI test requires a graphical environment", //$NON-NLS-1$
				GraphicsEnvironment.isHeadless());

		final byte[] testPdf = AOUtil.getDataFromInputStream(ClassLoader.getSystemResourceAsStream(TEST_FILE));
		LOGGER.info("Inicio de la carga"); //$NON-NLS-1$
		final long time = System.currentTimeMillis();

		final JFrame frame = new JFrame("Cargando documento PDF"); //$NON-NLS-1$
		frame.setSize(300, 95);

		frame.setVisible(true);

		PdfLoader.loadPdf(
			IS_SIGN,
			IS_MASSIVE_SIGN,
			testPdf,
			new PdfLoaderListener() {
				@Override
				public void pdfLoaded(final boolean isSign, final boolean isMassiveSign, final byte[] pdf) {
					LOGGER.info(
						"Tiempo: " + Long.toString((System.currentTimeMillis()-time)/1000) + "s" //$NON-NLS-1$ //$NON-NLS-2$
					);
				}
				@Override
				public void pdfLoadedFailed(final Throwable cause) {
					LOGGER.log(Level.SEVERE, "Error en la carga del PDF", cause); //$NON-NLS-1$
				}
			}
		);
	}

	static List<Dimension> getPageSizes(final byte[] inPdf) throws IOException {
		final PdfReader reader = new PdfReader(inPdf);
		final int numberOfPages = reader.getNumberOfPages();
		final List<Dimension> pageSizes = new ArrayList<>(numberOfPages);
		for(int i=1;i<=numberOfPages;i++) {
			final com.aowagie.text.Rectangle rect = reader.getPageSize(i);
			pageSizes.add(
				new Dimension(
					Math.round(rect.getWidth()),
					Math.round(rect.getHeight())
				)
			);
		}
		return pageSizes;
	}

}
