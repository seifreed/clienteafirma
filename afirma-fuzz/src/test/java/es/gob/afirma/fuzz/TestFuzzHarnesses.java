package es.gob.afirma.fuzz;

import java.lang.reflect.Constructor;
import java.lang.reflect.Method;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.Test;

import com.code_intelligence.jazzer.api.CannedFuzzedDataProvider;

import es.gob.afirma.core.signers.TriphaseData;
import es.gob.afirma.core.signers.TriphaseData.TriSign;

/** Pruebas de humo de los harnesses Jazzer. */
final class TestFuzzHarnesses {

	@Test
	void testDerValueFuzzer() {
		DerValueFuzzer.parseDerValue(new byte[] { 0x05, 0x00 });
		DerValueFuzzer.parseDerValue(new byte[] { 0x30, 0x7f });
		DerValueFuzzer.fuzzerTestOneInput(CannedFuzzedDataProvider.create(List.of(new byte[] { 0x05, 0x00 })));
	}

	@Test
	void testProtocolUriFuzzer() {
		final String validParams = "op=sign&format=CAdES&algorithm=SHA256withRSA&dat=AA=="; //$NON-NLS-1$

		ProtocolUriFuzzer.fuzzerTestOneInput(CannedFuzzedDataProvider.create(List.of(Boolean.TRUE, "?")));
		ProtocolUriFuzzer.fuzzerTestOneInput(CannedFuzzedDataProvider.create(List.of(Boolean.TRUE, "dat")));
		ProtocolUriFuzzer.fuzzerTestOneInput(CannedFuzzedDataProvider.create(List.of(Boolean.TRUE, "dat=%zz")));
		ProtocolUriFuzzer.fuzzerTestOneInput(CannedFuzzedDataProvider.create(List.of(Boolean.TRUE, "dat=http%3A%2F%2Fexample.invalid%2Fdoc")));
		ProtocolUriFuzzer.fuzzerTestOneInput(CannedFuzzedDataProvider.create(List.of(Boolean.TRUE, "dat=https%3A%2F%2Fexample.invalid%2Fdoc")));
		ProtocolUriFuzzer.fuzzerTestOneInput(CannedFuzzedDataProvider.create(List.of(Boolean.TRUE, "dat=ftp%3A%2F%2Fexample.invalid%2Fdoc")));
		ProtocolUriFuzzer.fuzzerTestOneInput(CannedFuzzedDataProvider.create(List.of(Boolean.TRUE, "afirma://sign?op=sign")));
		ProtocolUriFuzzer.fuzzerTestOneInput(CannedFuzzedDataProvider.create(List.of(Boolean.TRUE, "afirma://sign?" + validParams)));
		ProtocolUriFuzzer.fuzzerTestOneInput(CannedFuzzedDataProvider.create(List.of(Boolean.FALSE, "<bad/>".getBytes())));
		ProtocolUriFuzzer.fuzzerTestOneInput(CannedFuzzedDataProvider.create(List.of(Boolean.FALSE, xml(validParams))));
	}

	@Test
	void testTriphaseDataFuzzer() {
		final TriphaseData data = new TriphaseData(
			List.of(new TriSign(Map.of("NEED_PRE", "true"), "001")), //$NON-NLS-1$ //$NON-NLS-2$ //$NON-NLS-3$
			"XAdES" //$NON-NLS-1$
		);
		TriphaseDataFuzzer.fuzzerTestOneInput(CannedFuzzedDataProvider.create(List.of(data.toString().getBytes(StandardCharsets.UTF_8))));
		TriphaseDataFuzzer.fuzzerTestOneInput(CannedFuzzedDataProvider.create(List.of("<bad/>".getBytes())));
		TriphaseDataFuzzer.fuzzerTestOneInput(CannedFuzzedDataProvider.create(List.of("<".getBytes())));
	}

	@Test
	void testRemoteDataParamHelper() throws Exception {
		final Method method = ProtocolUriFuzzer.class.getDeclaredMethod("hasRemoteDataParam", String.class); //$NON-NLS-1$
		method.setAccessible(true);
		method.invoke(null, "?dat=http%3A%2F%2Fexample.invalid%2Fdoc");
		method.invoke(null, "?dat=https%3A%2F%2Fexample.invalid%2Fdoc");
		method.invoke(null, "?dat=ftp%3A%2F%2Fexample.invalid%2Fdoc");
		method.invoke(null, "?dat=data");
		method.invoke(null, "?dat=%zz");
	}

	@Test
	void testPrivateConstructors() throws Exception {
		instantiate(DerValueFuzzer.class);
		instantiate(ProtocolUriFuzzer.class);
		instantiate(TriphaseDataFuzzer.class);
	}

	private static void instantiate(final Class<?> type) throws Exception {
		final Constructor<?> constructor = type.getDeclaredConstructor();
		constructor.setAccessible(true);
		constructor.newInstance();
	}

	private static byte[] xml(final String params) {
		final StringBuilder xml = new StringBuilder("<op>"); //$NON-NLS-1$
		for (final String param : params.split("&")) { //$NON-NLS-1$
			final int separator = param.indexOf('=');
			xml.append("<e k=\"").append(param, 0, separator).append("\" v=\"") //$NON-NLS-1$ //$NON-NLS-2$
					.append(param.substring(separator + 1))
					.append("\"/>"); //$NON-NLS-1$
		}
		return xml.append("</op>").toString().getBytes(StandardCharsets.UTF_8); //$NON-NLS-1$
	}
}
