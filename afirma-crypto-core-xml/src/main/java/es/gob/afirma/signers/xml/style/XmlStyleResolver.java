/* Copyright (C) 2026 [Gobierno de España] / Agencia Estatal de Administración Digital
 * This file is part of "Cliente @Firma".
 * "Cliente @Firma" is free software; you can redistribute it and/or modify it under the terms of:
 *   - the GNU General Public License as published by the Free Software Foundation;
 *     either version 2 of the License, or (at your option) any later version.
 *   - or The European Software License; either version 1.1 or (at your option) any later version.
 */

package es.gob.afirma.signers.xml.style;

import java.util.logging.Logger;

/**
 * Resuelve la hoja de estilo XSL referenciada en un documento XML, capturando
 * las excepciones de dereferenciación con el mismo patrón que ya usaban
 * {@code AOXMLDSigSigner.sign()} y {@code XAdESSigner.sign()}: dos bloques
 * idénticos al 100% estructural — ver Fase C del plan Clean Code (2026-05-07).
 *
 * <p>Devuelve siempre un {@link XmlStyle} no-{@code null}: vacío si la
 * dereferenciación falla por cualquiera de las razones documentadas
 * ({@link IsInnerlException}, {@link ReferenceIsNotXmlException},
 * {@link CannotDereferenceException}) o por excepción inesperada.</p>
 */
public final class XmlStyleResolver {

	private static final Logger LOGGER = Logger.getLogger("es.gob.afirma"); //$NON-NLS-1$

	private XmlStyleResolver() {
		// Utility — no instanciable.
	}

	/**
	 * Carga la hoja de estilo del XML.
	 *
	 * @param data XML en formato binario.
	 * @param headless Si {@code true}, no se muestran diálogos al usuario.
	 * @param allowExternal Si {@code true}, se descargan hojas de estilo
	 *     referenciadas externamente (URI absoluta). El uso histórico:
	 *     <ul>
	 *       <li>{@code AOXMLDSigSigner} pasa {@code true}.</li>
	 *       <li>{@code XAdESSigner} pasa {@code false} (defensa contra
	 *           descargas externas no controladas).</li>
	 *     </ul>
	 * @return La hoja de estilo dereferenciada o un {@link XmlStyle} vacío
	 *     si falla cualquier paso (los errores se loggean al nivel apropiado:
	 *     INFO/WARNING/SEVERE según el tipo).
	 */
	public static XmlStyle resolve(final byte[] data, final boolean headless, final boolean allowExternal) {
		try {
			return new XmlStyle(data, headless, allowExternal);
		}
		catch (final IsInnerlException ex) {
			LOGGER.info(
				"La hoja de estilo esta referenciada internamente, por lo que no se necesita dereferenciar: " + ex //$NON-NLS-1$
			);
		}
		catch (final ReferenceIsNotXmlException ex) {
			LOGGER.warning(
				"La hoja de estilo referenciada no es XML o no se ha dereferenciado apropiadamente: " + ex //$NON-NLS-1$
			);
		}
		catch (final CannotDereferenceException ex) {
			LOGGER.warning(
				"La hoja de estilo no ha podido dereferenciar, probablemente sea un enlace relativo local: " + ex //$NON-NLS-1$
			);
		}
		catch (final Exception ex) {
			LOGGER.severe(
				"Error intentando dereferenciar la hoja de estilo: " + ex //$NON-NLS-1$
			);
		}
		return new XmlStyle();
	}
}
