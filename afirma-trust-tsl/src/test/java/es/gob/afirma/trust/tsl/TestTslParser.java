/* Copyright (C) 2026 [Gobierno de España] / Agencia Estatal de Administración Digital */

package es.gob.afirma.trust.tsl;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.charset.StandardCharsets;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/** Pruebas del parser TSL sobre un fixture mínimo embebido. */
final class TestTslParser {

	private static final String MINI_TSL = """
		<?xml version="1.0" encoding="UTF-8"?>
		<TrustServiceStatusList xmlns="http://uri.etsi.org/02231/v2#">
		  <SchemeInformation>
		    <SchemeOperatorName>
		      <Name>Ministerio de Asuntos Económicos y Transformación Digital</Name>
		    </SchemeOperatorName>
		    <SchemeTerritory>ES</SchemeTerritory>
		    <NextUpdate>
		      <dateTime>2026-12-31T23:59:59Z</dateTime>
		    </NextUpdate>
		  </SchemeInformation>
		  <TrustServiceProviderList>
		    <TrustServiceProvider>
		      <TSPInformation>
		        <Name>FNMT-RCM</Name>
		        <TradeName>FNMT-RCM</TradeName>
		        <PostalCode>ES</PostalCode>
		      </TSPInformation>
		      <TSPServices>
		        <TSPService>
		          <ServiceInformation>
		            <ServiceTypeIdentifier>http://uri.etsi.org/TrstSvc/Svctype/CA/QC</ServiceTypeIdentifier>
		            <ServiceStatus>http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/granted</ServiceStatus>
		          </ServiceInformation>
		        </TSPService>
		      </TSPServices>
		    </TrustServiceProvider>
		  </TrustServiceProviderList>
		</TrustServiceStatusList>
		""";

	@Test
	@DisplayName("Parser extrae territorio, operador, NextUpdate y TSPs sin errores")
	void parsesMinimalTsl() throws TslException {
		final TslParser parser = new TslParser();
		final TslDocument tsl = parser.parse(MINI_TSL.getBytes(StandardCharsets.UTF_8));

		assertEquals("ES", tsl.territory());
		assertTrue(tsl.schemeOperatorName().contains("Ministerio"));
		assertEquals(1, tsl.providers().size());
		assertFalse(tsl.signed(), "Fixture sin firma — TslDocument.signed() debe ser false");

		final TrustServiceProvider tsp = tsl.providers().get(0);
		assertEquals("FNMT-RCM", tsp.name());
		assertEquals(1, tsp.services().size());

		final TrustServiceProvider.TrustService svc = tsp.services().get(0);
		assertTrue(svc.isGranted(), "El servicio debería estar 'granted'");
		assertTrue(svc.typeIdentifier().endsWith("CA/QC"));
	}

	@Test
	@DisplayName("TrustListService.findIssuer devuelve empty si la TSL no se ha cargado")
	void emptyServiceReturnsNothing() {
		final TrustListService svc = new TrustListService();
		assertEquals(0, svc.loadedCount());
		assertTrue(svc.findIssuer(null).isEmpty());
	}

	@Test
	@DisplayName("Parser rechaza entradas vacías")
	void rejectsEmpty() {
		final TslParser parser = new TslParser();
		assertThrows(TslException.class, () -> parser.parse(new byte[0]));
		assertThrows(TslException.class, () -> parser.parse(null));
	}

	@Test
	@DisplayName("Parser endurecido contra DOCTYPE (XXE)")
	void rejectsDoctype() {
		final String xxe = """
			<?xml version="1.0"?>
			<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
			<TrustServiceStatusList xmlns="http://uri.etsi.org/02231/v2#"/>
			""";
		final TslParser parser = new TslParser();
		assertThrows(TslException.class,
				() -> parser.parse(xxe.getBytes(StandardCharsets.UTF_8)));
	}
}
