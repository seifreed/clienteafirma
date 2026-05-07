/* Copyright (C) 2026 [Gobierno de España] / Agencia Estatal de Administración Digital */

package es.gob.afirma.signers.xmldsig;

import java.util.ArrayList;
import java.util.List;

import org.w3c.dom.Element;
import org.w3c.dom.NodeList;

import es.gob.afirma.signers.xml.XMLConstants;

/** Estrategia TREE: selecciona <em>todas</em> las firmas del documento. */
final class CountersignTreeNodeSelector implements CountersignNodeSelector {

	@Override
	public List<Element> selectNodes(final Element root, final Object[] targets) {
		final NodeList signatures = root.getElementsByTagNameNS(
				XMLConstants.DSIGNNS, XMLConstants.TAG_SIGNATURE);
		final List<Element> result = new ArrayList<>(signatures.getLength());
		for (int i = 0; i < signatures.getLength(); i++) {
			result.add((Element) signatures.item(i));
		}
		return result;
	}
}
