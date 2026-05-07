package es.gob.afirma.core.misc;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.io.InputStream;
import java.util.zip.CRC32;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/** Pruebas de codificaci&oacute;n en Base64.
 *  Migrado a JUnit&nbsp;5 (Jupiter) en M3.6 — sirve como prueba de vida del nuevo
 *  motor; el resto de las suites siguen ejecutando sobre {@code junit-vintage-engine}
 *  hasta que se vayan migrando individualmente. */
final class TestBase64 {

	private static final String[] TEST_FILES = {
		"excel.xls",
		"pdf.pdf",
		"powerpoint.ppt",
		"project.mpp",
		"rar.rar",
		"visio.vsd",
		"word.doc",
		"xml.xml"
	};

	/** Prueba simple de codificaci&oacute;n / decodificaci&oacute;n Base64.
	 * @throws Exception En cualquier error. */
	@Test
	@DisplayName("Base64 round-trip preserva CRC32 sobre cada fixture binario")
	void base64Encoding() throws Exception {
		for (final String f : TEST_FILES) {
			final byte[] data;
			try (InputStream is = TestBase64.class.getResourceAsStream(f)) {
				data = AOUtil.getDataFromInputStream(is);
			}

			final CRC32 crc = new CRC32();
			crc.update(data);
			final long crcl = crc.getValue();

			final String tmpB64Bin = Base64.encode(data);
			final byte[] newBin = Base64.decode(tmpB64Bin);

			crc.reset();
			crc.update(newBin);
			assertEquals(crcl, crc.getValue(), () -> "CRC mismatch tras round-trip Base64 en " + f);
		}
	}
}
