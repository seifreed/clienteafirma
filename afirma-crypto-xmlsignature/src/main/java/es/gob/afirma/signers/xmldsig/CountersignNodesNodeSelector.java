/* Copyright (C) 2026 [Gobierno de España] / Agencia Estatal de Administración Digital */

package es.gob.afirma.signers.xmldsig;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import org.w3c.dom.Element;
import org.w3c.dom.NodeList;

import es.gob.afirma.signers.xml.XMLConstants;

/**
 * Estrategia NODES: ordena las firmas en preorden (las firmas raíz primero,
 * después sus contrafirmas inmediatas, recursivamente) y selecciona las
 * que están en las posiciones indicadas en {@code targets} (cada elemento
 * del array debe ser un {@link Integer}).
 */
final class CountersignNodesNodeSelector implements CountersignNodeSelector {

	@Override
	public List<Element> selectNodes(final Element root, final Object[] targets) {
		if (targets == null) {
			throw new IllegalArgumentException(
					"La lista de nodos a contrafirmar no puede ser nula"); //$NON-NLS-1$
		}

		final NodeList signatures = root.getElementsByTagNameNS(
				XMLConstants.DSIGNNS, XMLConstants.TAG_SIGNATURE);

		final String[] signatureValueIds = new String[signatures.getLength()];
		for (int i = 0; i < signatures.getLength(); i++) {
			signatureValueIds[i] = ((Element) signatures.item(i))
					.getElementsByTagNameNS(XMLConstants.DSIGNNS, SIGNATURE_VALUE)
					.item(0)
					.getAttributes()
					.getNamedItem(ID_ATTR)
					.getNodeValue();
		}

		final List<Element> sorted = new ArrayList<>(signatures.getLength());
		for (int i = 0; i < signatures.getLength(); i++) {
			if (isMainSignature((Element) signatures.item(i))) {
				sorted.add((Element) signatures.item(i));
				addSubNodes(signatureValueIds[i], signatures, signatureValueIds, sorted);
			}
		}

		final List<Object> targetsList = Arrays.asList(targets);
		final List<Element> result = new ArrayList<>();
		for (int i = 0; i < sorted.size(); i++) {
			if (targetsList.contains(Integer.valueOf(i))) {
				result.add(sorted.get(i));
			}
		}
		return result;
	}

	private static boolean isMainSignature(final Element signature) {
		final NodeList references = signature.getElementsByTagNameNS(
				XMLConstants.DSIGNNS, REFERENCE);
		for (int j = 0; j < references.getLength(); j++) {
			if (COUNTERSIGNATURE_TYPE_URI.equals(((Element) references.item(j)).getAttribute("Type"))) { //$NON-NLS-1$
				return false;
			}
		}
		return true;
	}

	/** Localiza las firmas que referencian a la dada y las añade al sorted list,
	 *  recursivamente. Diseño preservado de la implementación anterior. */
	private static void addSubNodes(final String parentSignatureValueId,
			final NodeList signatures,
			final String[] signatureValueIds,
			final List<Element> sortedSignatures) {
		for (int i = 0; i < signatures.getLength(); i++) {
			final NodeList references = ((Element) signatures.item(i))
					.getElementsByTagNameNS(XMLConstants.DSIGNNS, REFERENCE);
			for (int j = 0; j < references.getLength(); j++) {
				if (("#" + parentSignatureValueId).equals( //$NON-NLS-1$
						((Element) references.item(j)).getAttribute(URI_ATTR))) {
					// Si una firma contiene una referencia a sí misma, rompemos
					// el ciclo para evitar bucle infinito.
					if (signatureValueIds[i].equals(parentSignatureValueId)) {
						break;
					}
					sortedSignatures.add((Element) signatures.item(i));
					addSubNodes(signatureValueIds[i], signatures, signatureValueIds, sortedSignatures);
					break;
				}
			}
		}
	}
}
