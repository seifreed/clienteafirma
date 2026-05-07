/* Copyright (C) 2026 [Gobierno de España] / Agencia Estatal de Administración Digital */

package es.gob.afirma.signers.xmldsig;

import java.util.ArrayList;
import java.util.List;

import org.w3c.dom.Element;
import org.w3c.dom.NodeList;

import es.gob.afirma.signers.xml.XMLConstants;

/**
 * Estrategia LEAFS: selecciona solo las firmas <em>hoja</em>, es decir,
 * aquellas cuyo {@code SignatureValue.Id} no aparece referenciado en
 * ningún {@code Reference URI="#..."} del documento. Las hojas son las
 * firmas más recientes en el árbol de contrafirmas.
 */
final class CountersignLeafsNodeSelector implements CountersignNodeSelector {

	@Override
	public List<Element> selectNodes(final Element root, final Object[] targets) {
		final NodeList signatures = root.getElementsByTagNameNS(
				XMLConstants.DSIGNNS, XMLConstants.TAG_SIGNATURE);
		final NodeList references = root.getElementsByTagNameNS(
				XMLConstants.DSIGNNS, REFERENCE);

		final String[] signatureValueIds = new String[signatures.getLength()];
		for (int i = 0; i < signatures.getLength(); i++) {
			signatureValueIds[i] = ((Element) signatures.item(i))
					.getElementsByTagNameNS(XMLConstants.DSIGNNS, SIGNATURE_VALUE)
					.item(0)
					.getAttributes()
					.getNamedItem(ID_ATTR)
					.getNodeValue();
		}

		final List<Element> result = new ArrayList<>();
		for (int i = 0; i < signatureValueIds.length; i++) {
			final String refUri = "#" + signatureValueIds[i]; //$NON-NLS-1$
			if (!isReferencedByAny(refUri, references)) {
				result.add((Element) signatures.item(i));
			}
		}
		return result;
	}

	private static boolean isReferencedByAny(final String refUri, final NodeList references) {
		for (int j = 0; j < references.getLength(); j++) {
			if (((Element) references.item(j)).getAttribute(URI_ATTR).equals(refUri)) {
				return true;
			}
		}
		return false;
	}
}
