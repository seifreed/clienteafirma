/* Copyright (C) 2011 [Gobierno de Espana]
 * This file is part of "Cliente @Firma".
 * "Cliente @Firma" is free software; you can redistribute it and/or modify it under the terms of:
 *   - the GNU General Public License as published by the Free Software Foundation;
 *     either version 2 of the License, or (at your option) any later version.
 *   - or The European Software License; either version 1.1 or (at your option) any later version.
 * You may contact the copyright holder at: soporte.afirma@seap.minhap.es
 */

package es.gob.afirma.core.misc.http;

/** Factor&iacute;a para la obtenci&oacute;n de un manejador para la lectura y env&iacute;o de datos a URL remotas.
 * @author Carlos Gamuci */
public abstract class UrlHttpManagerFactory {

	/** Recupera un manejador de conexiones por defecto.
	 * @return Manejador de conexi&oacute;nes. */
	public static UrlHttpManager getManager() {
		return new UrlHttpManagerImpl();
	}
}
