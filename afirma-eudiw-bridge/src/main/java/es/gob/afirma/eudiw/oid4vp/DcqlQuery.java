/* Copyright (C) 2026 [Gobierno de España] / Agencia Estatal de Administración Digital */

package es.gob.afirma.eudiw.oid4vp;

import java.text.ParseException;
import java.util.Objects;

import com.nimbusds.jose.util.JSONObjectUtils;

/** Consulta DCQL nativa para OID4VP. */
public record DcqlQuery(String json) {

	public DcqlQuery {
		Objects.requireNonNull(json, "json"); //$NON-NLS-1$
		try {
			JSONObjectUtils.parse(json);
		}
		catch (final ParseException e) {
			throw new IllegalArgumentException("dcql_query debe ser un objeto JSON válido", e); //$NON-NLS-1$
		}
	}
}
