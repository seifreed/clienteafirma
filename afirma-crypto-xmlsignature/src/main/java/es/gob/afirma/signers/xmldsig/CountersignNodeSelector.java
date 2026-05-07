/* Copyright (C) 2026 [Gobierno de España] / Agencia Estatal de Administración Digital
 * This file is part of "Cliente @Firma".
 * "Cliente @Firma" is free software; you can redistribute it and/or modify it under the terms of:
 *   - the GNU General Public License as published by the Free Software Foundation;
 *     either version 2 of the License, or (at your option) any later version.
 *   - or The European Software License; either version 1.1 or (at your option) any later version.
 */

package es.gob.afirma.signers.xmldsig;

import java.util.List;

import org.w3c.dom.Element;

import es.gob.afirma.core.signers.CounterSignTarget;

/**
 * Estrategia de selección de nodos a contrafirmar dentro de un documento XML.
 * Reemplaza los 4 métodos privados {@code countersignTree/Leafs/Nodes/Signers}
 * de {@link AOXMLDSigSigner} (Fase D.1 del plan Clean Code, 2026-05-07): cada
 * destino de {@link CounterSignTarget} tiene su propia lógica de filtrado pero
 * el resto del flujo (instanciar el nuevo nodo de firma, calcular referencias,
 * añadirlo al árbol) es común y vive ahora una única vez en
 * {@code AOXMLDSigSigner.cs()}.
 *
 * <p>Implementaciones disponibles en este paquete:</p>
 * <ul>
 *   <li>{@link CountersignTreeNodeSelector} — todas las firmas del árbol.</li>
 *   <li>{@link CountersignLeafsNodeSelector} — solo las hojas (firmas cuyo
 *       SignatureValue no es referenciado por ninguna otra firma).</li>
 *   <li>{@link CountersignNodesNodeSelector} — firmas en posiciones concretas
 *       de un recorrido en preorden, dadas como índices en el array de targets.</li>
 *   <li>{@link CountersignSignersNodeSelector} — firmas cuyo CN del certificado
 *       firmante coincide con algún valor del array de targets.</li>
 * </ul>
 */
interface CountersignNodeSelector {

	/** Nombres de elementos / atributos XMLDSig usados por las 4 estrategias.
	 *  Constantes package-private para no exponerlas como API pública. */
	String REFERENCE = "Reference"; //$NON-NLS-1$
	String SIGNATURE_VALUE = "SignatureValue"; //$NON-NLS-1$
	String ID_ATTR = "Id"; //$NON-NLS-1$
	String URI_ATTR = "URI"; //$NON-NLS-1$
	/** {@code Type} URI que ETSI usa para identificar referencias a firmas
	 *  contrafirmadas — distingue una firma raíz de una contrafirma anidada. */
	String COUNTERSIGNATURE_TYPE_URI = "http://uri.etsi.org/01903#CountersignedSignature"; //$NON-NLS-1$

	/**
	 * @param root Elemento raíz del documento que contiene las firmas.
	 * @param targets Argumentos del destino — usados solo por NODES y SIGNERS;
	 *     puede ser {@code null} para TREE / LEAFS.
	 * @return Lista en orden de aparición de las firmas a contrafirmar. Puede
	 *     estar vacía si ningún destino aplica.
	 */
	List<Element> selectNodes(Element root, Object[] targets);

	/**
	 * Devuelve la estrategia correspondiente al destino dado. Lanza
	 * {@link IllegalArgumentException} si el destino no es uno de los 4
	 * miembros de {@link CounterSignTarget}.
	 */
	static CountersignNodeSelector forTarget(final CounterSignTarget targetType) {
		if (targetType == CounterSignTarget.TREE) {
			return new CountersignTreeNodeSelector();
		}
		if (targetType == CounterSignTarget.LEAFS) {
			return new CountersignLeafsNodeSelector();
		}
		if (targetType == CounterSignTarget.NODES) {
			return new CountersignNodesNodeSelector();
		}
		if (targetType == CounterSignTarget.SIGNERS) {
			return new CountersignSignersNodeSelector();
		}
		throw new IllegalArgumentException("CounterSignTarget no soportado: " + targetType); //$NON-NLS-1$
	}
}
