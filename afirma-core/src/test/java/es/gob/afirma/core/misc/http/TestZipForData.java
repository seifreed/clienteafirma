package es.gob.afirma.core.misc.http;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.HashMap;
import java.util.Map;
import java.util.zip.GZIPOutputStream;

import org.junit.jupiter.api.Test;

import es.gob.afirma.core.misc.Base64;

/** Pruebas de compresi&oacute;n de datos en URL con GZIP.
 *
 * <p>Los dos tests aqu&iacute; son unitarios puros — no necesitan red ni
 * sistema externo. {@link DataDownloader#downloadData(String, boolean)} con
 * {@code gzipped=true} y un valor Base64 va por la rama local de
 * descompresi&oacute;n (ver DataDownloader.java:64-69).
 *
 * @author Tom&aacute;s Garc&iacute;a-Mer&aacute;s. */
final class TestZipForData {

	/** Comprueba que la descarga de datos con {@code gzipped=true} sobre un
	 * payload Base64 deshace el GZIP y recupera los bytes originales. */
	@Test
	void testDownloadDataGunzipsBase64Payload() throws Exception {
		final byte[] origBytes = "Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua.".getBytes(); //$NON-NLS-1$
		final byte[] compressedBytes = gzipBytes(origBytes);

		final byte[] downData = DataDownloader.downloadData(
			Base64.encode(compressedBytes, true),
			true
		);

		assertArrayEquals(origBytes, downData);
	}

	/** Comprueba el parseo del par&aacute;metro {@code gzip} desde un mapa de
	 * cadenas (ausente / "false" / "true"). */
	@Test
	void testParamParse() {
		final Map<String, String> noParam = new HashMap<>(0);
		final Map<String, String> noGzip = new HashMap<>(1);
		noGzip.put("gzip", "false"); //$NON-NLS-1$ //$NON-NLS-2$
		final Map<String, String> yesGzip = new HashMap<>(1);
		yesGzip.put("gzip", "true"); //$NON-NLS-1$ //$NON-NLS-2$

		assertFalse(Boolean.parseBoolean(noParam.get("gzip"))); //$NON-NLS-1$
		assertFalse(Boolean.parseBoolean(noGzip.get("gzip"))); //$NON-NLS-1$
		assertTrue(Boolean.parseBoolean(yesGzip.get("gzip"))); //$NON-NLS-1$
	}

	private static byte[] gzipBytes(final byte[] in) throws IOException {
		try (final ByteArrayOutputStream baos = new ByteArrayOutputStream();
		     final GZIPOutputStream zipStream = new GZIPOutputStream(baos)) {
			zipStream.write(in);
			zipStream.close();
			return baos.toByteArray();
		}
	}

}
