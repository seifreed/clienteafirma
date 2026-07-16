/* Copyright (C) 2026 [Gobierno de España] / Agencia Estatal de Administración Digital */

package es.gob.afirma.trust.tsl;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;

import javax.xml.XMLConstants;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;

import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.xml.sax.SAXException;

/**
 * Parser TSL (ETSI TS 119 612) — extrae proveedores y servicios.
 *
 * <p>Solo cubre los elementos necesarios para responder consultas de
 * confianza ({@link TrustServiceProvider}); la cabecera
 * {@code <SchemeInformation>} y los anexos legales se ignoran.</p>
 *
 * <p>El parser está endurecido contra XXE / billion-laughs: las funcionalidades
 * peligrosas del {@link DocumentBuilderFactory} se desactivan explícitamente.</p>
 */
public final class TslParser {

	private static final String TSL_NS = "http://uri.etsi.org/02231/v2#"; //$NON-NLS-1$
	private static final String DSIG_NS = "http://www.w3.org/2000/09/xmldsig#"; //$NON-NLS-1$

	/** Parsea bytes XML de una TSL en memoria. No verifica la firma —
	 *  para eso usar {@link TslVerifier}. */
	public TslDocument parse(final byte[] xml) throws TslException {
		if (xml == null || xml.length == 0) {
			throw new TslException("TSL vacía"); //$NON-NLS-1$
		}
		try {
			final Document doc = parseXml(xml);
			final Element root = doc.getDocumentElement();

			final String schemeOperator = textOrEmpty(root,
					TSL_NS, "SchemeOperatorName"); //$NON-NLS-1$
			final String territory = textOrEmpty(root,
					TSL_NS, "SchemeTerritory"); //$NON-NLS-1$
			if (schemeOperator.isEmpty()) {
				throw new TslException("TSL sin SchemeOperatorName"); //$NON-NLS-1$
			}
			if (territory.isEmpty()) {
				throw new TslException("TSL sin SchemeTerritory"); //$NON-NLS-1$
			}

			Instant nextUpdate = null;
			final NodeList nextUpdateNodes = root.getElementsByTagNameNS(TSL_NS, "NextUpdate"); //$NON-NLS-1$
			if (nextUpdateNodes.getLength() > 0) {
				final NodeList ts = ((Element) nextUpdateNodes.item(0))
						.getElementsByTagNameNS(TSL_NS, "dateTime"); //$NON-NLS-1$
				if (ts.getLength() > 0) {
					nextUpdate = Instant.parse(ts.item(0).getTextContent().trim());
				}
			}

			final List<TrustServiceProvider> providers = parseProviders(root, territory);
			final boolean signed = root.getElementsByTagNameNS(DSIG_NS, "Signature").getLength() > 0; //$NON-NLS-1$

			return new TslDocument(
					schemeOperator,
					territory,
					nextUpdate,
					providers,
					signed);
		}
		catch (final TslException e) {
			throw e;
		}
		catch (final Exception e) {
			throw new TslException("Error parseando TSL: " + e.getMessage(), e); //$NON-NLS-1$
		}
	}

	/** Construye los proveedores TSP. El {@code countryCode} se hereda del
	 *  {@code <SchemeTerritory>} del documento — ETSI TS 119 612 §5.3.4 garantiza
	 *  que todos los TSPs de una TSL pertenecen al territorio del scheme operator. */
	private List<TrustServiceProvider> parseProviders(final Element root, final String territory) throws Exception {
		final List<TrustServiceProvider> result = new ArrayList<>();
		final NodeList tspNodes = root.getElementsByTagNameNS(TSL_NS, "TrustServiceProvider"); //$NON-NLS-1$
		final CertificateFactory cf = CertificateFactory.getInstance("X.509"); //$NON-NLS-1$

		for (int i = 0; i < tspNodes.getLength(); i++) {
			final Element tsp = (Element) tspNodes.item(i);
			final String name = textOrEmpty(tsp, TSL_NS, "Name"); //$NON-NLS-1$
			final String tradeName = textOrEmpty(tsp, TSL_NS, "TradeName"); //$NON-NLS-1$

			final List<TrustServiceProvider.TrustService> services = new ArrayList<>();
			final NodeList serviceNodes = tsp.getElementsByTagNameNS(TSL_NS, "TSPService"); //$NON-NLS-1$
			for (int j = 0; j < serviceNodes.getLength(); j++) {
				final Element svc = (Element) serviceNodes.item(j);
				final String type = textOrEmpty(svc, TSL_NS, "ServiceTypeIdentifier"); //$NON-NLS-1$
				final String status = textOrEmpty(svc, TSL_NS, "ServiceStatus"); //$NON-NLS-1$
				final List<X509Certificate> certs = new ArrayList<>();
				final NodeList x509b64 = svc.getElementsByTagNameNS(DSIG_NS, "X509Certificate"); //$NON-NLS-1$
				for (int k = 0; k < x509b64.getLength(); k++) {
					final byte[] der = Base64.getMimeDecoder().decode(x509b64.item(k).getTextContent());
					certs.add((X509Certificate) cf.generateCertificate(new ByteArrayInputStream(der)));
				}
				services.add(new TrustServiceProvider.TrustService(type, status, certs));
			}

			result.add(new TrustServiceProvider(
					name.isEmpty() ? "?" : name, //$NON-NLS-1$
					tradeName,
					territory,
					services));
		}
		return result;
	}

	private static Document parseXml(final byte[] xml)
			throws ParserConfigurationException, IOException, SAXException {
		final DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
		dbf.setNamespaceAware(true);
		dbf.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
		dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true); //$NON-NLS-1$
		dbf.setFeature("http://xml.org/sax/features/external-general-entities", false); //$NON-NLS-1$
		dbf.setFeature("http://xml.org/sax/features/external-parameter-entities", false); //$NON-NLS-1$
		dbf.setFeature("http://apache.org/xml/features/nonvalidating/load-external-dtd", false); //$NON-NLS-1$
		dbf.setXIncludeAware(false);
		dbf.setExpandEntityReferences(false);
		final DocumentBuilder db = dbf.newDocumentBuilder();
		try (ByteArrayInputStream bais = new ByteArrayInputStream(xml)) {
			return db.parse(bais);
		}
	}

	private static String textOrEmpty(final Element parent, final String ns, final String localName) {
		final NodeList nl = parent.getElementsByTagNameNS(ns, localName);
		if (nl.getLength() == 0) {
			return ""; //$NON-NLS-1$
		}
		final Node first = nl.item(0);
		return first.getTextContent() == null ? "" : first.getTextContent().trim(); //$NON-NLS-1$
	}
}
