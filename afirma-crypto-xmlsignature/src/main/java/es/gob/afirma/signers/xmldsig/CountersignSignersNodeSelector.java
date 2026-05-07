/* Copyright (C) 2026 [Gobierno de España] / Agencia Estatal de Administración Digital */

package es.gob.afirma.signers.xmldsig;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import org.w3c.dom.Element;
import org.w3c.dom.NodeList;

import es.gob.afirma.core.misc.AOUtil;
import es.gob.afirma.signers.xml.Utils;
import es.gob.afirma.signers.xml.XMLConstants;

/**
 * Estrategia SIGNERS: selecciona las firmas cuyo CN (X.500 commonName) del
 * certificado del firmante coincide con algún valor de {@code targets}.
 */
final class CountersignSignersNodeSelector implements CountersignNodeSelector {

	@Override
	public List<Element> selectNodes(final Element root, final Object[] targets) {
		if (targets == null) {
			throw new IllegalArgumentException(
					"La lista de firmantes a contrafirmar no puede ser nula"); //$NON-NLS-1$
		}
		final NodeList signatures = root.getElementsByTagNameNS(
				XMLConstants.DSIGNNS, XMLConstants.TAG_SIGNATURE);
		final List<Object> wantedSigners = Arrays.asList(targets);
		final List<Element> result = new ArrayList<>();
		for (int i = 0; i < signatures.getLength(); i++) {
			final Element signature = (Element) signatures.item(i);
			final String cn = AOUtil.getCN(Utils.getCertificate(
					signature.getElementsByTagNameNS(XMLConstants.DSIGNNS, "X509Certificate") //$NON-NLS-1$
							.item(0)));
			if (wantedSigners.contains(cn)) {
				result.add(signature);
			}
		}
		return result;
	}
}
