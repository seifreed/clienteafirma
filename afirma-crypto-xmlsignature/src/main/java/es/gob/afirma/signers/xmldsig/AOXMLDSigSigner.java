/* Copyright (C) 2011 [Gobierno de Espana]
 * This file is part of "Cliente @Firma".
 * "Cliente @Firma" is free software; you can redistribute it and/or modify it under the terms of:
 *   - the GNU General Public License as published by the Free Software Foundation,
 *     either version 2 of the License, or (at your option) any later version.
 *   - or The European Software License; either version 1.1 or (at your option) any later version.
 * You may contact the copyright holder at: soporte.afirma@seap.minhap.es
 */

package es.gob.afirma.signers.xmldsig;

import java.io.BufferedWriter;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.OutputStreamWriter;
import java.io.Writer;
import java.net.URI;
import java.security.InvalidAlgorithmParameterException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Hashtable;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.UUID;
import java.util.logging.Logger;

import javax.xml.crypto.XMLStructure;
import javax.xml.crypto.dom.DOMStructure;
import javax.xml.crypto.dsig.CanonicalizationMethod;
import javax.xml.crypto.dsig.DigestMethod;
import javax.xml.crypto.dsig.Reference;
import javax.xml.crypto.dsig.SignatureMethod;
import javax.xml.crypto.dsig.Transform;
import javax.xml.crypto.dsig.XMLObject;
import javax.xml.crypto.dsig.XMLSignature;
import javax.xml.crypto.dsig.XMLSignatureFactory;
import javax.xml.crypto.dsig.dom.DOMSignContext;
import javax.xml.crypto.dsig.keyinfo.KeyInfoFactory;
import javax.xml.crypto.dsig.spec.C14NMethodParameterSpec;
import javax.xml.crypto.dsig.spec.TransformParameterSpec;
import javax.xml.crypto.dsig.spec.XPathFilterParameterSpec;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.transform.OutputKeys;

import org.w3c.dom.Document;
import org.w3c.dom.DocumentType;
import org.w3c.dom.Element;
import org.w3c.dom.NamedNodeMap;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.w3c.dom.ls.DOMImplementationLS;
import org.w3c.dom.ls.LSSerializer;
import org.xml.sax.SAXException;

import es.gob.afirma.core.AOException;
import es.gob.afirma.core.AOInvalidSignatureFormatException;
import es.gob.afirma.core.ErrorCode;
import es.gob.afirma.core.misc.AOUtil;
import es.gob.afirma.core.misc.Base64;
import es.gob.afirma.core.misc.MimeHelper;
import es.gob.afirma.core.signers.AOSignConstants;
import es.gob.afirma.core.signers.AOSignInfo;
import es.gob.afirma.core.signers.AOSigner;
import es.gob.afirma.core.signers.CounterSignTarget;
import es.gob.afirma.core.util.tree.AOTreeModel;
import es.gob.afirma.core.util.tree.AOTreeNode;
import es.gob.afirma.signers.xml.InvalidXMLException;
import es.gob.afirma.signers.xml.Utils;
import es.gob.afirma.signers.xml.XMLConstants;
import es.gob.afirma.signers.xml.XMLErrorCode;
import es.gob.afirma.signers.xml.XmlDSigProviderHelper;
import es.gob.afirma.signers.xml.style.XmlStyle;
import es.gob.afirma.signers.xml.style.XmlStyleResolver;
import es.uji.crypto.xades.jxades.util.DOMOutputImpl;

/** Manejador de firmas XML en formato XMLDSig.
 * @version 0.2 */
public final class AOXMLDSigSigner implements AOSigner {

    private static final Logger LOGGER = Logger.getLogger("es.gob.afirma"); //$NON-NLS-1$

    /** URI que define la versi&oacute;n por defecto de XAdES. */
    private static final String XADESNS = "http://uri.etsi.org/01903#"; //$NON-NLS-1$

    private static final String MIMETYPE_STR = "MimeType"; //$NON-NLS-1$
    private static final String ENCODING_STR = "Encoding"; //$NON-NLS-1$
    private static final String REFERENCE_STR = "Reference"; //$NON-NLS-1$

    private static final String ID_IDENTIFIER = "Id"; //$NON-NLS-1$

    private static final String HTTP_PROTOCOL_PREFIX = "http://"; //$NON-NLS-1$
    private static final String HTTPS_PROTOCOL_PREFIX = "https://"; //$NON-NLS-1$

    private static final String STYLE_REFERENCE_PREFIX = "StyleReference-"; //$NON-NLS-1$

    private static final String CSURI = "http://uri.etsi.org/01903#CountersignedSignature"; //$NON-NLS-1$
    private static final String AFIRMA = "AFIRMA"; //$NON-NLS-1$
    private static final String XML_SIGNATURE_PREFIX = "ds"; //$NON-NLS-1$

    private static final String DETACHED_CONTENT_ELEMENT_NAME = "CONTENT"; //$NON-NLS-1$
    private static final String DETACHED_STYLE_ELEMENT_NAME = "STYLE"; //$NON-NLS-1$

    /** Algoritmo de huella digital por defecto para las referencias XML. */
    private static final String DIGEST_METHOD = DigestMethod.SHA1;

    private static final String SIGNATURE_VALUE = "SignatureValue"; //$NON-NLS-1$

    private static final String URI_STR = "URI"; //$NON-NLS-1$

    // Instalamos el proveedor de Apache. Esto es necesario para evitar problemas con los saltos de linea
    // de los Base 64
    static {
    	XmlDSigProviderHelper.configureXmlDSigProvider();
    }

    /** Firma datos en formato XMLDSig 1.0 (XML Digital Signature).
     * <p>
     *  En el caso de que se firma un fichero con formato XML que contenga hojas de estilo
     *  XSL, y siempre que no se haya establecido el par&aacute;metro <i>ignoreStyleSheets</i> a
     *  <i>true</i>, se sigue la siguiente convenci&oacute;n para la firma es estas:
     * </p>
     * <ul>
     *  <li>Firmas XML <i>Enveloped</i>
     *   <ul>
     *    <li>
     *     Hoja de estilo con ruta relativa
     *     <ul>
     *      <li>No se firma.</li>
     *     </ul>
     *    </li>
     *    <li>
     *     Hola de estilo remota con ruta absoluta
     *     <ul>
     *      <li>Se restaura la declaraci&oacute;n de hoja de estilo tal y como estaba en el XML original</li>
     *      <li>Se firma una referencia (<i>canonicalizada</i>) a esta hoja remota</li>
     *     </ul>
     *    </li>
     *    <li>
     *     Hoja de estilo empotrada
     *     <ul>
     *      <li>Se restaura la declaraci&oacute;n de hoja de estilo tal y como estaba en el XML original</li>
     *     </ul>
     *    </li>
     *   </ul>
     *  </li>
     *  <li>
     *   Firmas XML <i>Externally Detached</i>
     *   <ul>
     *    <li>
     *     Hoja de estilo con ruta relativa
     *     <ul>
     *      <li>No se firma.</li>
     *     </ul>
     *    </li>
     *    <li>
     *     Hola de estilo remota con ruta absoluta
     *     <ul>
     *      <li>Se firma una referencia (<i>canonicalizada</i>) a esta hoja remota</li>
     *     </ul>
     *    </li>
     *    <li>
     *     Hoja de estilo empotrada
     *     <ul>
     *      <li>No es necesaria ninguna acci&oacute;n</li>
     *     </ul>
     *    </li>
     *   </ul>
     *  </li>
     *  <li>
     *   Firmas XML <i>Enveloping</i>
     *   <ul>
     *    <li>
     *     Hoja de estilo con ruta relativa
     *     <ul>
     *      <li>No se firma.</li>
     *     </ul>
     *    </li>
     *    <li>
     *     Hola de estilo remota con ruta absoluta
     *     <ul>
     *      <li>Se firma una referencia (<i>canonicalizada</i>) a esta hoja remota</li>
     *     </ul>
     *    </li>
     *    <li>
     *     Hoja de estilo empotrada
     *     <ul>
     *      <li>No es necesaria ninguna acci&oacute;n</li>
     *     </ul>
     *    </li>
     *   </ul>
     *  </li>
     *  <li>
     *   Firmas XML <i>Internally Detached</i>
     *   <ul>
     *    <li>
     *     Hoja de estilo con ruta relativa
     *     <ul>
     *      <li>No se firma.</li>
     *     </ul>
     *    </li>
     *    <li>
     *     Hola de estilo remota con ruta absoluta
     *     <ul>
     *      <li>Se firma una referencia (<i>canonicalizada</i>) a esta hoja remota</li>
     *     </ul>
     *    </li>
     *    <li>
     *     Hoja de estilo empotrada
     *     <ul>
     *      <li>No es necesaria ninguna acci&oacute;n</li>
     *     </ul>
     *    </li>
     *   </ul>
     *  </li>
     * </ul>
     * @param data Datos que deseamos firmar.
     * @param algorithm Algoritmo a usar para la firma.
     * @param key Clave privada a usar para firmar
     * @param certChain Cadena de certificados del firmante
     * @param xParams Par&aacute;metros adicionales para la firma.
     * <p>Se aceptan los siguientes valores en el par&aacute;metro <code>xParams</code>:</p>
     * <dl>
     *  <dt><b><i>uri</i></b></dt>
     *   <dd>URI en la que se encuentra el documento, necesario en el caso de modo expl&iacute;cito y formato detached</dd>
     *  <dt><b><i>mode</i></b></dt>
     *   <dd>
     *    Modo de firma a usar. Se admiten los siguientes valores:
     *    <ul>
     *     <li>
     *      &nbsp;&nbsp;&nbsp;<i>explicit</i><br>(<code>AOSignConstants.SIGN_MODE_EXPLICIT</code>)<br>
     *      <b>
     *       <br>Importante: Las firmas XMLDSig expl&iacute;citas no se adec&uacute;an a ninguna normativa,
     *       y pueden ser rechazadas por sistemas de validaci&oacute;n de firmas.
     *      </b>
     *     </li>
     *     <li>&nbsp;&nbsp;&nbsp;<i>implicit</i><br>(<code>AOSignConstants.SIGN_MODE_IMPLICIT</code>)</li>
     *    </ul>
     *   </dd>
     *  <dt><b><i>xmlSignaturePrefix</i></b></dt>
     *   <dd>
     *    Prefijo de espacio de nombres XML para los nodos de firma. Si no se especifica este par&aacute;metro
     *    se usa el valor por defecto (<i>ds</i>).
     *   </dd>
     *  <dt><b><i>format</i></b></dt>
     *   <dd>
     *    Formato en que se realizar&aacute; la firma. Se admiten los siguientes valores:
     *    <ul>
     *     <li>&nbsp;&nbsp;&nbsp;<i>XMLDSig Detached</i><br>(<code>AOSignConstants.SIGN_FORMAT_XMLDSIG_DETACHED</code>)</li>
     *     <li>&nbsp;&nbsp;&nbsp;<i>XMLDSig Externally Detached</i><br>(<code>AOSignConstants.SIGN_FORMAT_XMLDSIG_EXTERNALLY_DETACHED</code>)</li>
     *     <li>&nbsp;&nbsp;&nbsp;<i>XMLDSig Enveloped</i><br>(<code>AOSignConstants.SIGN_FORMAT_XMLDSIG_ENVELOPED</code>)</li>
     *     <li>&nbsp;&nbsp;&nbsp;<i>XMLDSig Enveloping</i><br>(<code>AOSignConstants.SIGN_FORMAT_XMLDSIG_ENVELOPING</code>)</li>
     *    </ul>
     *   </dd>
     *  <dt><b><i>precalculatedHashAlgorithm</i></b></dt>
     *   <dd>Algoritmo de huella digital cuando esta se proporciona precalculada</dd>
     *  <dt><b><i>xmlTransforms</i></b></dt>
     *   <dd>N&uacute;mero de transformaciones a aplicar al XML antes de firmarlo</dd>
     *  <dt><b><i>xmlTransform</i>n<i>Type</i></b></dt>
     *   <dd>Tipo de la transformaci&oacute;n <i>n</i> (debe ser la URL del algoritmo segun define W3C)</dd>
     *  <dt><b><i>xmlTransform</i>n<i>Subtype</i></b></dt>
     *   <dd>Subtipo de la transformaci&oacute;n <i>n</i> (por ejemplo, "intersect", "subtract" o "union" para XPATH2)</dd>
     *  <dt><b><i>xmlTransform</i>n<i>Body</i></b></dt>
     *   <dd>Cuerpo de la transformaci&oacute;n <i>n</i></dd>
     *  <dt><b><i>referencesDigestMethod</i></b></dt>
     *   <dd>Algoritmo de huella digital a usar en las referencias XML</dd>
     *  <dt><b><i>canonicalizationAlgorithm</i></b></dt>
     *   <dd>Algoritmo de canonicalizaci&oacute;n<i>n</i></dd>
     *  <dt><b><i>ignoreStyleSheets</i></b></dt>
     *   <dd>Ignora las hojas de estilo externas de los XML (no las firma) si se establece a <code>true</code>, si se establece a <code>false</code> s&iacute; las firma</dd>
     *  <dt><b><i>mimeType</i></b></dt>
     *   <dd>MIME-Type de los datos a firmar</dd>
     *  <dt><b><i>encoding</i></b></dt>
     *   <dd>Codificaci&oacute;n de los datos a firmar</dd>
     *  <dt><b><i>avoidBase64Transforms</i></b></dt>
     *   <dd>
     *    No declara transformaciones Base64 incluso si son necesarias si se establece a <code>true</code>, si se establece a <code>false</code>
     *    act&uacute;a normalmente (s&iacute; las declara)
     *   </dd>
     *  <dt><b><i>headless</i></b></dt>
     *   <dd>
     *    Evita cualquier interacci&oacute;n con el usuraio si se establece a <code>true</code>, si se establece a <code>false</code> act&uacute;a
     *    normalmente (puede mostrar di&aacute;logos, por ejemplo, para la dereferenciaci&oacute;n de hojas de estilo enlazadas con rutas relativas).
     *    &Uacute;til para los procesos desatendidos y por lotes
     *   </dd>
     *  <dt><b><i>includeOnlySignningCertificate</i></b></dt>
	 *   <dd>Indica, mediante un {@code true} o {@code false}, que debe
	 *   incluirse en la firma &uacute;nicamente el certificado utilizado
	 *   para firmar y no su cadena de certificaci&oacute;n completa.
	 *   Por defecto, se incluir&aacute; toda la cadena de certificaci&oacute;n.
	 *   </dd>
     * </dl>
     * @return Firma en formato XMLDSig 1.0
     * @throws AOException Cuando ocurre cualquier problema durante el proceso */
    @Override
	public byte[] sign(final byte[] data,
                       final String algorithm,
                       final PrivateKey key,
                       final Certificate[] certChain,
                       final Properties xParams) throws AOException {

        final SignParams params = validateAndParseParams(data, algorithm, xParams);

        // Desempaqueta los parámetros para preservar el código posterior sin
        // tener que reescribir cada acceso como params.xxx().
        final String algoUri = params.algoUri();
        final Properties extraParams = params.extraParams();
        final String format = params.format();
        final String mode = params.mode();
        final String digestMethodAlgorithm = params.digestMethodAlgorithm();
        final String canonicalizationAlgorithm = params.canonicalizationAlgorithm();
        final boolean ignoreStyleSheets = params.ignoreStyleSheets();
        final boolean avoidBase64Transforms = params.avoidBase64Transforms();
        final boolean headless = params.headless();
        final boolean avoidXpathExtraTransformsOnEnveloped = params.avoidXpathExtraTransformsOnEnveloped();
        final String xmlSignaturePrefix = params.xmlSignaturePrefix();
        // uri es mutable porque el fallback a Base64 (IMPLICIT mode) lo resetea a null.
        URI uri = params.uri();
        final String precalculatedHashAlgorithm = params.precalculatedHashAlgorithm();
        final String contentId = params.contentId();
        final String styleId = params.styleId();

        // mimeType y encoding nacen del SignParams pero las fases IMPLICIT/
        // EXPLICIT pueden sobrescribirlos según los datos detectados.
        String mimeType = params.initialMimeType();
        String encoding = params.initialEncoding();

        // Propiedades del documento XML original
        final Map<String, String> originalXMLProperties = new Hashtable<>();

        // Elemento de datos
        Element dataElement;

        boolean isBase64 = false;
        boolean wasEncodedToBase64 = false;

		// Elemento de estilo
		XmlStyle xmlStyle = new XmlStyle();

        if (mode.equals(AOSignConstants.SIGN_MODE_IMPLICIT)) {
            final PreparedDataElement prepared = prepareDataElementImplicit(
                    data, params, originalXMLProperties, mimeType, encoding, uri);
            dataElement = prepared.dataElement();
            mimeType = prepared.mimeType();
            encoding = prepared.encoding();
            uri = prepared.uri();
            isBase64 = prepared.isBase64();
            wasEncodedToBase64 = prepared.wasEncodedToBase64();
            xmlStyle = prepared.xmlStyle();
        }

        // Firma Explicita
        else {
            // ESTE BLOQUE CONTIENE EL PROCESO A SEGUIR EN EL MODO EXPLICITO,
            // ESTO ES, NO FIRMAMOS LOS DATOS SINO SU HASH
            byte[] digestValue = null;
            // Si la URI no es nula recogemos los datos de fuera
            if (uri != null) {
                byte[] tmpData = null;
                try {
                    tmpData = AOUtil.getDataFromInputStream(AOUtil.loadFile(uri));
                }
                catch (final Exception e) {
                    throw new AOException("No se han podido obtener los datos de la URI externa", e, XMLErrorCode.Communication.DERREFERENCING_DATA_ERROR); //$NON-NLS-1$
                }
                // Vemos si hemos obtenido bien los datos de la URI
                if (tmpData != null && tmpData.length > 0) {
                    try {
                        digestValue = MessageDigest.getInstance("SHA1").digest(tmpData); //$NON-NLS-1$
                    }
                    catch (final Exception e) {
                        throw new AOException("No se ha podido obtener el SHA1 de los datos de la URI externa", e, ErrorCode.Internal.UNSUPPORTED_HASH_ALGORITHM); //$NON-NLS-1$
                    }
                }
            }
            // Si no tenemos URI y se nos inserto directamente el hash de los
            // datos
            else if (precalculatedHashAlgorithm != null) {
                digestValue = data;
            }
            // Si solo tenemos los datos
            else {
                try {
                    digestValue = MessageDigest.getInstance("SHA1").digest(data); //$NON-NLS-1$
                }
                catch (final Exception e) {
                    throw new AOException("No se ha podido obtener el SHA1 de los datos proporcionados: " + e, e, ErrorCode.Internal.UNSUPPORTED_HASH_ALGORITHM); //$NON-NLS-1$
                }
            }

            final Document docFile;
            try {
                docFile = Utils.getNewDocumentBuilder().newDocument();
            }
            catch (final Exception e) {
                throw new AOException("No se ha podido crear el documento XML contenedor: " + e, e, XMLErrorCode.Internal.INTERNAL_XML_SIGNING_ERROR); //$NON-NLS-1$
            }
            dataElement = docFile.createElement(DETACHED_CONTENT_ELEMENT_NAME);

            encoding = XMLConstants.BASE64_ENCODING;
            // En el caso de la firma explicita, se firma el Hash de los datos
            // en lugar de los propios datos.
            // En este caso, los indicaremos a traves del MimeType en donde
            // establecemos un tipo especial
            // que designa al hash. Independientemente del algoritmo de firma
            // utilizado, el Hash de las firmas
            // explicitas de datos siempre sera SHA1, salvo que el hash se haya
            // establecido desde fuera.
            if (precalculatedHashAlgorithm != null) {
                mimeType = "hash/" + precalculatedHashAlgorithm.toLowerCase(); //$NON-NLS-1$
            }
            else {
                mimeType = "hash/sha1"; //$NON-NLS-1$
            }

            dataElement.setAttributeNS(null, ID_IDENTIFIER, contentId);
            dataElement.setAttributeNS(null, MIMETYPE_STR, mimeType);
            dataElement.setAttributeNS(null, ENCODING_STR, encoding);

            dataElement.setTextContent(Base64.encode(digestValue));
            isBase64 = true;

            // FIN BLOQUE EXPLICITO
        }

        // ***************************************************
        // ***************************************************

        final String tmpUri = "#" + contentId; //$NON-NLS-1$
        final String tmpStyleUri = "#" + styleId; //$NON-NLS-1$

        // Crea el nuevo documento de firma
        Document docSignature = createSignatureDocument(format, mode, dataElement);

        final List<Reference> referenceList = new ArrayList<>();
        final XMLSignatureFactory fac = Utils.getDOMFactory();
        final DigestMethod digestMethod;
        try {
            digestMethod = fac.newDigestMethod(digestMethodAlgorithm, null);
        }
        catch (final Exception e) {
            throw new AOException("No se ha podido obtener un generador de huellas digitales para el algoritmo " + digestMethodAlgorithm, e, //$NON-NLS-1$
            		XMLErrorCode.Request.INVALID_REFERENCES_HASH_ALGORITHM_URI);
        }
        final String referenceId = "Reference-" + UUID.randomUUID().toString(); //$NON-NLS-1$
        final String referenceStyleId = STYLE_REFERENCE_PREFIX + UUID.randomUUID().toString();

        final List<Transform> transformList = new ArrayList<>();

        // Primero anadimos las transformaciones a medida
        Utils.addCustomTransforms(transformList, extraParams, xmlSignaturePrefix);

        final Transform canonicalizationTransform;
        if ("none".equalsIgnoreCase(canonicalizationAlgorithm)) { //$NON-NLS-1$
        	canonicalizationTransform = null;
        }
        else {
        	try {
				canonicalizationTransform = fac.newTransform(canonicalizationAlgorithm, (TransformParameterSpec) null);
			}
        	catch (final Exception e) {
				throw new AOException("No se ha podido crear la transformacion de canonicalizacion para el algoritmo " + canonicalizationAlgorithm, //$NON-NLS-1$
						e, XMLErrorCode.Request.INVALID_CANONICALIZATION_URI);
			}
        }

        // Solo canonicalizo si es XML y no me han declarado el algoritmo como "none"
        if (!isBase64) {
        	if (canonicalizationTransform != null) {
	            try {
	                // Transformada para la canonicalizacion inclusiva
	                transformList.add(canonicalizationTransform);
	            }
	            catch (final Exception e) {
	                LOGGER
	                      .severe("No se puede encontrar el algoritmo de canonicalizacion, la referencia no se canonicalizara: " + e); //$NON-NLS-1$
	            }
        	}
        }
        // Si no era XML y tuve que convertir a Base64 yo mismo declaro la
        // transformacion
        else if (wasEncodedToBase64 && !avoidBase64Transforms) {
            try {
                transformList.add(fac.newTransform(Transform.BASE64, (TransformParameterSpec) null));
            }
            catch (final Exception e) {
                LOGGER.severe("No se puede encontrar el algoritmo transformacion Base64, esta no se declarara: " + e); //$NON-NLS-1$
            }
        }

        final Phase4Result phase4 = buildReferences(params, data, dataElement, docSignature,
                referenceList, transformList, fac, digestMethod, canonicalizationTransform,
                xmlStyle, isBase64, wasEncodedToBase64, mimeType, encoding, uri,
                referenceId, referenceStyleId, tmpUri, tmpStyleUri);

        buildAndExecuteSignature(
            referenceList, phase4.envelopingObject(), phase4.envelopingStyleObject(), docSignature,
            new SignatureBuildContext(fac, digestMethod, transformList, canonicalizationTransform,
                canonicalizationAlgorithm, algoUri, xmlSignaturePrefix, format,
                xmlStyle, styleId, tmpStyleUri, referenceStyleId,
                key, certChain, extraParams));

        docSignature = postprocessEnvelopingDocument(docSignature, format, xmlSignaturePrefix);
        return serializeSignatureToBytes(docSignature, format, originalXMLProperties, xmlStyle);
    }

    /** Prepara el {@code dataElement} en modo IMPLICIT: parsea {@code data}
     * como XML, resuelve la hoja de estilo (vía {@link XmlStyleResolver}),
     * detecta encoding/version/DOCTYPE del XML original y construye el
     * {@link Element} según el formato (DETACHED inserta los datos en un
     * elemento contenedor; el resto usa la raíz del XML parseado).
     *
     * <p>Si el parseo falla y el formato no es ENVELOPED (que exige XML
     * estricto), aplica el fallback a Base64: re-empaqueta {@code data}
     * dentro de un {@code <CONTENT>} con encoding {@code base64}, detecta
     * el {@code MimeType} y anula la {@code uri} externa.</p>
     *
     * <p>Muta {@code xmlStyle} y {@code originalXMLProperties} en el
     * proceso. Los demás resultados se devuelven en el record retornado.</p>
     *
     * @throws AOException Si la conversión a Base64 falla.
     * @throws InvalidXMLException Si el formato es ENVELOPED y los datos
     *         no son XML válido. */
    private static PreparedDataElement prepareDataElementImplicit(
            final byte[] data,
            final SignParams params,
            final Map<String, String> originalXMLProperties,
            final String initialMimeType,
            final String initialEncoding,
            final URI initialUri) throws AOException {

        final String format = params.format();
        final String contentId = params.contentId();
        final String styleId = params.styleId();
        final boolean ignoreStyleSheets = params.ignoreStyleSheets();
        final boolean headless = params.headless();

        String mimeType = initialMimeType;
        String encoding = initialEncoding;
        URI uri = initialUri;
        Element dataElement;
        boolean isBase64 = false;
        boolean wasEncodedToBase64 = false;
        XmlStyle xmlStyle = new XmlStyle();

        try {
            // Obtenemos el objeto XML y su codificacion
            final Document docum = Utils.getNewDocumentBuilder().parse(new ByteArrayInputStream(data));

            // Obtenemos la hoja de estilo del XML. Resolución compartida
            // con XAdES — ver XmlStyleResolver (Fase C plan Clean Code).
            if (!ignoreStyleSheets) {
                xmlStyle = XmlStyleResolver.resolve(data, headless, true);
            }

            // Si no hay asignado un MimeType o es el por defecto
            // establecemos el de XML
            if (mimeType == null || MimeHelper.DEFAULT_MIMETYPE.equals(mimeType)) {
                mimeType = "text/xml"; //$NON-NLS-1$
            }

            if (encoding == null) {
                encoding = docum.getXmlEncoding();
            }

            // Ademas del encoding, sacamos otros datos del doc XML original
            // Hacemos la comprobacion del base64 por si se establecido desde fuera
            if (encoding != null && !XMLConstants.BASE64_ENCODING.equals(encoding)) {
                originalXMLProperties.put(OutputKeys.ENCODING, encoding);
            }
            String tmpXmlProp = docum.getXmlVersion();
            if (tmpXmlProp != null) {
                originalXMLProperties.put(OutputKeys.VERSION, tmpXmlProp);
            }
            final DocumentType dt = docum.getDoctype();
            if (dt != null) {
                tmpXmlProp = dt.getSystemId();
                if (tmpXmlProp != null) {
                    originalXMLProperties.put(OutputKeys.DOCTYPE_SYSTEM, tmpXmlProp);
                }
            }

            if (format.equals(AOSignConstants.SIGN_FORMAT_XMLDSIG_DETACHED)) {
                dataElement = docum.createElement(DETACHED_CONTENT_ELEMENT_NAME);
                dataElement.setAttributeNS(null, ID_IDENTIFIER, contentId);
                dataElement.setAttributeNS(null, MIMETYPE_STR, mimeType);
                dataElement.setAttributeNS(null, ENCODING_STR, encoding);
                dataElement.appendChild(docum.getDocumentElement());

                // Tambien el estilo
                if (xmlStyle.getStyleElement() != null) {
                    try {
                        final Element tmpStyleElement = docum.createElement(DETACHED_STYLE_ELEMENT_NAME);
                        tmpStyleElement.setAttributeNS(null, ID_IDENTIFIER, styleId);
                        if (xmlStyle.getStyleType() != null) {
                            tmpStyleElement.setAttributeNS(null, MIMETYPE_STR, xmlStyle.getStyleType());
                        }
                        tmpStyleElement.setAttributeNS(null, ENCODING_STR, xmlStyle.getStyleEncoding());
                        tmpStyleElement.appendChild(docum.adoptNode(xmlStyle.getStyleElement().cloneNode(true)));
                        xmlStyle.setStyleElement(tmpStyleElement);
                    }
                    catch (final Exception e) {
                        LOGGER.warning(
                            "No ha sido posible crear el elemento DOM para incluir la hoja de estilo del XML como Internally Detached: " + e //$NON-NLS-1$
                        );
                        xmlStyle.setStyleElement(null);
                    }
                }
            }
            else {
                dataElement = docum.getDocumentElement();
            }
        }
        // captura de error en caso de no ser un documento xml
        catch (final Exception e) {
            if (format.equals(AOSignConstants.SIGN_FORMAT_XMLDSIG_ENVELOPED)) {
                throw new InvalidXMLException(e);
            }
            // para los formatos de firma internally detached y enveloping
            // se trata de convertir el documento a base64
            try {
                LOGGER.info("El documento no es un XML valido. Se convertira a Base64: " + e); //$NON-NLS-1$

                // crea un nuevo nodo xml para contener los datos en base 64
                final Document docFile = Utils.getNewDocumentBuilder().newDocument();
                dataElement = docFile.createElement(DETACHED_CONTENT_ELEMENT_NAME);
                uri = null;
                encoding = XMLConstants.BASE64_ENCODING;
                if (mimeType == null) {
                    mimeType = MimeHelper.DEFAULT_MIMETYPE;
                }

                dataElement.setAttributeNS(null, ID_IDENTIFIER, contentId);

                // Si es base 64, lo firmamos indicando como contenido el
                // dato pero, ya que puede poseer un formato particular o
                // caracteres valido pero extranos para el XML, realizamos
                // una decodificacion y recodificacion para asi homogenizar
                // el formato.
                if (Base64.isBase64(data) && (XMLConstants.BASE64_ENCODING.equals(encoding) || encoding.toLowerCase().equals("base64"))) { //$NON-NLS-1$
                    LOGGER.info("El documento se ha indicado como Base64, se insertara como tal en el XML"); //$NON-NLS-1$

                    // Adicionalmente, si es un base 64 intentamos obtener
                    // el tipo del contenido decodificado para asi
                    // reestablecer el MimeType.
                    final byte[] decodedData = Base64.decode(data, 0, data.length, false);
                    final MimeHelper mimeTypeHelper = new MimeHelper(decodedData);
                    final String tempMimeType = mimeTypeHelper.getMimeType();
                    mimeType = tempMimeType != null ? tempMimeType : MimeHelper.DEFAULT_MIMETYPE;
                    dataElement.setAttributeNS(null, MIMETYPE_STR, mimeType);
                    dataElement.setTextContent(new String(data));
                }
                else {
                    if (XMLConstants.BASE64_ENCODING.equals(encoding)) {
                        LOGGER.info("El documento se ha indicado como Base64, pero no es un Base64 valido. Se convertira a Base64 antes de insertarlo en el XML y se declarara la transformacion"); //$NON-NLS-1$
                    }
                    else {
                        LOGGER.info("El documento se considera binario, se convertira a Base64 antes de insertarlo en el XML y se declarara la transformacion"); //$NON-NLS-1$
                    }

                    // Identificamos el MimeType
                    if (MimeHelper.DEFAULT_MIMETYPE.equals(mimeType)) {
                        final MimeHelper mimeTypeHelper = new MimeHelper(data);
                        final String tempMimeType = mimeTypeHelper.getMimeType();
                        mimeType = tempMimeType != null ? tempMimeType : MimeHelper.DEFAULT_MIMETYPE;
                    }
                    dataElement.setAttributeNS(null, MIMETYPE_STR, mimeType);
                    dataElement.setTextContent(Base64.encode(data));
                    wasEncodedToBase64 = true;
                }
                isBase64 = true;
                encoding = XMLConstants.BASE64_ENCODING;
                dataElement.setAttributeNS(null, ENCODING_STR, encoding);
            }
            catch (final Exception ex) {
                throw new AOException("Error al convertir los datos a base64", ex, XMLErrorCode.Internal.INTERNAL_XML_SIGNING_ERROR); //$NON-NLS-1$
            }
        }

        return new PreparedDataElement(dataElement, isBase64, wasEncodedToBase64,
                mimeType, encoding, uri, xmlStyle);
    }

    /** Valida los parámetros de entrada de {@link #sign} y empaqueta los
     * valores derivados de {@code xParams} en un {@link SignParams} inmutable.
     *
     * <p>Comprueba que el algoritmo de firma esté soportado (lanza
     * {@link AOException} con {@code UNSUPPORTED_SIGNATURE_ALGORITHM} si no),
     * que los datos no sean nulos o vacíos salvo en EXTERNALLY_DETACHED con
     * URI externa, y delega en {@link Utils#checkIllegalParams} para las
     * combinaciones inválidas de format/mode/URI/precalculatedHash.</p>
     *
     * @param data Bytes a firmar (puede ser nulo o vacío solo en
     *             EXTERNALLY_DETACHED con URI externa).
     * @param algorithm Algoritmo de firma (p. ej. SHA256withRSA).
     * @param xParams Parámetros adicionales o {@code null}.
     * @return {@link SignParams} con los valores parseados y validados.
     * @throws AOException Si el algoritmo no está soportado o falla la
     *                     validación cruzada de parámetros.
     * @throws IllegalArgumentException Si no hay datos a firmar. */
    private static SignParams validateAndParseParams(final byte[] data, final String algorithm,
            final Properties xParams) throws AOException {
        final String algoUri = XMLConstants.SIGN_ALGOS_URI.get(algorithm);
        if (algoUri == null) {
            throw new AOException(
                "Los formatos de firma XML no soportan el algoritmo de firma " + algorithm, //$NON-NLS-1$
                ErrorCode.Request.UNSUPPORTED_SIGNATURE_ALGORITHM);
        }

        final Properties extraParams = xParams != null ? xParams : new Properties();

        final String format = extraParams.getProperty(
                AOXMLDSigExtraParams.FORMAT, AOSignConstants.SIGN_FORMAT_XMLDSIG_ENVELOPING);
        final String mode = extraParams.getProperty(
                AOXMLDSigExtraParams.MODE, AOSignConstants.SIGN_MODE_IMPLICIT);
        final String digestMethodAlgorithm = extraParams.getProperty(
                AOXMLDSigExtraParams.REFERENCES_DIGEST_METHOD, DIGEST_METHOD);
        final String canonicalizationAlgorithm = extraParams.getProperty(
                AOXMLDSigExtraParams.CANONICALIZATION_ALGORITHM, CanonicalizationMethod.INCLUSIVE);
        final boolean ignoreStyleSheets = Boolean.parseBoolean(extraParams.getProperty(
                AOXMLDSigExtraParams.IGNORE_STYLE_SHEETS, Boolean.FALSE.toString()));
        final boolean avoidBase64Transforms = Boolean.parseBoolean(extraParams.getProperty(
                AOXMLDSigExtraParams.AVOID_BASE64_TRANSFORMS, Boolean.FALSE.toString()));
        final boolean headless = Boolean.parseBoolean(extraParams.getProperty(
                AOXMLDSigExtraParams.HEADLESS, Boolean.TRUE.toString()));
        final boolean avoidXpathExtraTransformsOnEnveloped = Boolean.parseBoolean(extraParams.getProperty(
                AOXMLDSigExtraParams.AVOID_XPATH_EXTRA_TRANSFORMS_ON_ENVELOPED, Boolean.FALSE.toString()));
        final String xmlSignaturePrefix = extraParams.getProperty(
                AOXMLDSigExtraParams.XML_SIGNATURE_PREFIX, XML_SIGNATURE_PREFIX);

        final String mimeTypeRaw = extraParams.getProperty(AOXMLDSigExtraParams.MIME_TYPE);
        String encoding = extraParams.getProperty(AOXMLDSigExtraParams.ENCODING);
        if ("base64".equalsIgnoreCase(encoding)) { //$NON-NLS-1$
            encoding = XMLConstants.BASE64_ENCODING;
        }

        URI uri = null;
        try {
            uri = AOUtil.createURI(extraParams.getProperty(AOXMLDSigExtraParams.URI));
        }
        catch (final Exception e) {
            // Se ignora, puede estar ausente
        }

        final String precalculatedHashAlgorithm = extraParams.getProperty(
                AOXMLDSigExtraParams.PRECALCULATED_HASH_ALGORITHM);

        Utils.checkIllegalParams(format, mode, false, uri, precalculatedHashAlgorithm, false);

        // Un externally detached con URL permite los datos nulos o vacios
        if ((data == null || data.length == 0)
                && !(format.equals(AOSignConstants.SIGN_FORMAT_XMLDSIG_EXTERNALLY_DETACHED) && uri != null)) {
            throw new IllegalArgumentException("No se han indicado los datos a firmar"); //$NON-NLS-1$
        }

        final String contentId = DETACHED_CONTENT_ELEMENT_NAME + "-" + UUID.randomUUID().toString() //$NON-NLS-1$
                + "-" + DETACHED_CONTENT_ELEMENT_NAME; //$NON-NLS-1$
        final String styleId = DETACHED_STYLE_ELEMENT_NAME + "-" + UUID.randomUUID().toString() //$NON-NLS-1$
                + "-" + DETACHED_STYLE_ELEMENT_NAME; //$NON-NLS-1$

        return new SignParams(algoUri, format, mode, digestMethodAlgorithm, canonicalizationAlgorithm,
                ignoreStyleSheets, avoidBase64Transforms, headless, avoidXpathExtraTransformsOnEnveloped,
                xmlSignaturePrefix, mimeTypeRaw, encoding, uri, precalculatedHashAlgorithm,
                contentId, styleId, extraParams);
    }

    /** Crea el {@link Document} contenedor de la firma. En modo <i>enveloped</i>
     * adopta el {@code dataElement} de entrada (que pasa a ser la raíz del
     * documento de firma); en el resto de formatos crea un {@code <AFIRMA>}
     * vacío que sirve como envoltorio temporal hasta el post-proceso.
     * @param format Formato XMLDSig.
     * @param mode Modo (IMPLICIT/EXPLICIT) — solo se usa en el mensaje de error.
     * @param dataElement Elemento adoptado en ENVELOPED; ignorado en otros formatos.
     * @return El {@link Document} listo para recibir la firma.
     * @throws AOException Si el {@link DocumentBuilder} no puede crear el documento. */
    private static Document createSignatureDocument(final String format, final String mode,
            final Element dataElement) throws AOException {
        try {
            final Document docSignature = Utils.getNewDocumentBuilder().newDocument();
            if (format.equals(AOSignConstants.SIGN_FORMAT_XMLDSIG_ENVELOPED)) {
                docSignature.appendChild(docSignature.adoptNode(dataElement));
            }
            else {
                docSignature.appendChild(docSignature.createElement(AFIRMA));
            }
            return docSignature;
        }
        catch (final Exception e) {
            throw new AOException(
                "Error al crear la firma en formato " + format + ", modo " + mode, //$NON-NLS-1$ //$NON-NLS-2$
                e, XMLErrorCode.Internal.INTERNAL_XML_SIGNING_ERROR);
        }
    }

    /** Salida de {@link #buildReferences}: los dos {@link XMLObject} que
     * solo se construyen en formato ENVELOPING. En el resto de formatos
     * ambos campos son {@code null}. */
    private static record Phase4Result(XMLObject envelopingObject, XMLObject envelopingStyleObject) { }

    /** Construye la lista de {@link Reference}s y los {@link XMLObject}s
     * específicos del formato XMLDSig solicitado. Dispatcher de las 4 ramas:
     * ENVELOPING (datos en {@code <Object>}), DETACHED (datos adoptados en
     * {@code <AFIRMA>}), EXTERNALLY_DETACHED (URI externa o hash
     * precalculado) y ENVELOPED (transformación ENVELOPED + XPATH opcional).
     *
     * <p>Esta extracción es solo el envoltorio; las 4 ramas siguen siendo
     * código inline. Pasos sucesivos del refactor las extraerán a métodos
     * dedicados ({@code buildReferencesFor{Enveloping,Detached,...}}).</p>
     *
     * @param params Parámetros parseados.
     * @param data Bytes a firmar (solo se consume en EXTERNALLY_DETACHED).
     * @param dataElement Elemento con los datos preparado por la fase 2.
     * @param docSignature Documento de la firma (mutado por la rama DETACHED).
     * @param referenceList Lista de referencias mutable a la que se añaden
     *                      las referencias de la rama elegida.
     * @param transformList Lista de transformaciones mutable (la rama
     *                      ENVELOPED añade ENVELOPED + XPATH).
     * @param fac Factory XML.
     * @param digestMethod Método de digest preparado.
     * @param canonicalizationTransform Transformación de canonicalización (puede ser {@code null}).
     * @param xmlStyle Hoja de estilo (puede estar vacía).
     * @param isBase64 {@code true} si {@code dataElement} contiene datos Base64.
     * @param wasEncodedToBase64 {@code true} si los datos se convirtieron a Base64 durante la fase IMPLICIT.
     * @param mimeType Tipo MIME del contenido (o {@code null}).
     * @param encoding Codificación del contenido (o {@code null}).
     * @param uri URI externa (solo EXTERNALLY_DETACHED).
     * @param referenceId Identificador único de la referencia principal.
     * @param referenceStyleId Identificador único de la referencia a la hoja de estilo.
     * @param tmpUri URI relativa al {@code contentId} (formato {@code "#id"}).
     * @param tmpStyleUri URI relativa al {@code styleId}.
     * @return Los {@link XMLObject}s de la rama ENVELOPING (o {@code null}s
     *         en el resto de formatos).
     * @throws AOException Si la generación de la firma para el formato falla. */
    private static Phase4Result buildReferences(
            final SignParams params,
            final byte[] data,
            final Element dataElement,
            final Document docSignature,
            final List<Reference> referenceList,
            final List<Transform> transformList,
            final XMLSignatureFactory fac,
            final DigestMethod digestMethod,
            final Transform canonicalizationTransform,
            final XmlStyle xmlStyle,
            final boolean isBase64,
            final boolean wasEncodedToBase64,
            final String mimeType,
            final String encoding,
            final URI uri,
            final String referenceId,
            final String referenceStyleId,
            final String tmpUri,
            final String tmpStyleUri) throws AOException {

        final String format = params.format();
        final String canonicalizationAlgorithm = params.canonicalizationAlgorithm();
        final String precalculatedHashAlgorithm = params.precalculatedHashAlgorithm();
        final String digestMethodAlgorithm = params.digestMethodAlgorithm();
        final boolean avoidXpathExtraTransformsOnEnveloped = params.avoidXpathExtraTransformsOnEnveloped();
        final String xmlSignaturePrefix = params.xmlSignaturePrefix();

        // crea una referencia al documento insertado en un nodo Object para la
        // firma enveloping y a el estilo
        XMLObject envelopingObject = null;
        XMLObject envelopingStyleObject = null;

        if (format.equals(AOSignConstants.SIGN_FORMAT_XMLDSIG_ENVELOPING)) {
            final Phase4Result envelopingResult = buildReferencesForEnveloping(
                    dataElement, isBase64, mimeType, encoding,
                    fac, digestMethod, transformList, canonicalizationTransform,
                    xmlStyle, referenceList, referenceId, referenceStyleId);
            envelopingObject = envelopingResult.envelopingObject();
            envelopingStyleObject = envelopingResult.envelopingStyleObject();
        }

        // crea una referencia al documento mediante la URI hacia el
        // identificador del nodo CONTENT
        else if (format.equals(AOSignConstants.SIGN_FORMAT_XMLDSIG_DETACHED)) {
            buildReferencesForDetached(dataElement, docSignature, xmlStyle,
                    fac, digestMethod, transformList, canonicalizationTransform,
                    canonicalizationAlgorithm, referenceList,
                    tmpUri, tmpStyleUri, referenceId, referenceStyleId);
        }

        // Crea una referencia al documento mediante la URI externa si la
        // tenemos o usando un Message Digest
        // precalculado si no tenemos otro remedio
        else if (format.equals(AOSignConstants.SIGN_FORMAT_XMLDSIG_EXTERNALLY_DETACHED)) {
            buildReferencesForExternallyDetached(data, uri,
                    precalculatedHashAlgorithm, digestMethodAlgorithm,
                    fac, digestMethod, canonicalizationTransform,
                    xmlStyle, referenceList, referenceId, referenceStyleId);
        }

        // crea una referencia indicando que se trata de una firma enveloped
        else if (format.equals(AOSignConstants.SIGN_FORMAT_XMLDSIG_ENVELOPED)) {
            buildReferencesForEnveloped(fac, digestMethod, transformList,
                    canonicalizationTransform, xmlStyle,
                    avoidXpathExtraTransformsOnEnveloped, xmlSignaturePrefix,
                    referenceList, referenceId, referenceStyleId);
        }

        return new Phase4Result(envelopingObject, envelopingStyleObject);
    }

    /** Construye las referencias y los {@link XMLObject}s específicos del
     * formato XMLDSig ENVELOPING. Empaqueta los datos a firmar en un
     * {@code <Object>} (con la hoja de estilo opcional en un segundo
     * {@code <Object>}) y añade las referencias correspondientes.
     * @return Los dos {@link XMLObject}s construidos (el de estilo es
     *         {@code null} si no hay hoja de estilo). */
    private static Phase4Result buildReferencesForEnveloping(
            final Element dataElement,
            final boolean isBase64,
            final String mimeType,
            final String encoding,
            final XMLSignatureFactory fac,
            final DigestMethod digestMethod,
            final List<Transform> transformList,
            final Transform canonicalizationTransform,
            final XmlStyle xmlStyle,
            final List<Reference> referenceList,
            final String referenceId,
            final String referenceStyleId) throws AOException {

        XMLObject envelopingObject = null;
        XMLObject envelopingStyleObject = null;

        try {
            // crea el nuevo elemento Object que contiene el documento a firmar
            final List<XMLStructure> structures = new ArrayList<>(1);

            // Si los datos se han convertido a base64, bien por ser
            // binarios o explicitos
            if (isBase64) {
                structures.add(new DOMStructure(dataElement.getFirstChild()));
            }
            else {
                structures.add(new DOMStructure(dataElement));
            }

            final String objectId = "Object-" + UUID.randomUUID().toString(); //$NON-NLS-1$
            envelopingObject = fac.newXMLObject(structures, objectId, mimeType, encoding);

            // crea la referencia al nuevo elemento Object
            referenceList.add(
                fac.newReference(
                    "#" + objectId, //$NON-NLS-1$
                    digestMethod,
                    transformList,
                    XMLConstants.OBJURI,
                    referenceId
                )
            );

            // Vamos con la hoja de estilo
            if (xmlStyle.getStyleElement() != null) {
                final String objectStyleId = "StyleObject-" + UUID.randomUUID().toString(); //$NON-NLS-1$
                envelopingStyleObject = fac.newXMLObject(
                    Collections.singletonList(new DOMStructure(xmlStyle.getStyleElement())),
                    objectStyleId,
                    xmlStyle.getStyleType(),
                    xmlStyle.getStyleEncoding()
                );
                referenceList.add(
                    fac.newReference(
                        "#" + objectStyleId, //$NON-NLS-1$
                        digestMethod,
                        canonicalizationTransform != null
                            ? Collections.singletonList(canonicalizationTransform)
                            : null,
                        XMLConstants.OBJURI,
                        referenceStyleId
                    )
                );
            }
        }
        catch (final Exception e) {
            throw new AOException("Error al generar la firma en formato enveloping", e, XMLErrorCode.Internal.UNKWNON_XML_SIGNING_ERROR); //$NON-NLS-1$
        }

        addRemoteStyleSheetReference(xmlStyle, referenceList, fac, digestMethod,
                canonicalizationTransform, referenceStyleId, "Enveloping"); //$NON-NLS-1$

        return new Phase4Result(envelopingObject, envelopingStyleObject);
    }

    /** Construye las referencias específicas del formato XMLDSig DETACHED.
     * Adopta el {@code dataElement} y, opcionalmente, la hoja de estilo
     * dentro del documento de firma; añade las referencias internas hacia
     * ellos por URI {@code #id}. Si hay hoja de estilo remota
     * (http(s)://...), añade una referencia adicional a la URL externa
     * con la transformación de canonicalización configurada. */
    private static void buildReferencesForDetached(
            final Element dataElement,
            final Document docSignature,
            final XmlStyle xmlStyle,
            final XMLSignatureFactory fac,
            final DigestMethod digestMethod,
            final List<Transform> transformList,
            final Transform canonicalizationTransform,
            final String canonicalizationAlgorithm,
            final List<Reference> referenceList,
            final String tmpUri,
            final String tmpStyleUri,
            final String referenceId,
            final String referenceStyleId) throws AOException {

        try {
            if (dataElement != null) {
                // inserta en el nuevo documento de firma el documento a firmar
                docSignature.getDocumentElement().appendChild(docSignature.adoptNode(dataElement));
                referenceList.add(
                    fac.newReference(
                        tmpUri,
                        digestMethod,
                        transformList,
                        XMLConstants.OBJURI,
                        referenceId
                    )
                );
            }
            if (xmlStyle.getStyleElement() != null) {
                // inserta en el nuevo documento de firma la hoja de estilo
                docSignature.getDocumentElement().appendChild(docSignature.adoptNode(xmlStyle.getStyleElement()));
                referenceList.add(
                    fac.newReference(
                        tmpStyleUri,
                        digestMethod,
                        canonicalizationTransform != null
                            ? Collections.singletonList(canonicalizationTransform)
                            : null,
                        XMLConstants.OBJURI,
                        referenceStyleId
                    )
                );
            }
        }
        catch (final Exception e) {
            throw new AOException("Error al generar la firma en formato detached implicito", e, XMLErrorCode.Internal.UNKWNON_XML_SIGNING_ERROR); //$NON-NLS-1$
        }

        // Hojas de estilo remotas para detached. Comprobamos si la referencia al estilo es externa
        if (xmlStyle.getStyleHref() != null && xmlStyle.getStyleElement() == null
                && (xmlStyle.getStyleHref().startsWith(HTTP_PROTOCOL_PREFIX) || xmlStyle.getStyleHref().startsWith(HTTPS_PROTOCOL_PREFIX))) {
            try {
                referenceList.add(
                    fac.newReference(
                        xmlStyle.getStyleHref(),
                        digestMethod,
                        Collections.singletonList(fac.newTransform(canonicalizationAlgorithm, (TransformParameterSpec) null)),
                        XMLConstants.OBJURI,
                        referenceStyleId
                    )
                );
            }
            catch (final Exception e) {
                LOGGER.severe(
                    "No ha sido posible anadir la referencia a la hoja de estilo del XML en la firma Detached Implicita, esta no se firmara: " + e //$NON-NLS-1$
                );
            }
        }
    }

    /** Construye la referencia específica del formato XMLDSig
     * EXTERNALLY_DETACHED. La referencia puede construirse a partir de
     * (a) un hash precalculado (si {@code precalculatedHashAlgorithm} y
     * los datos están presentes y no hay URI válida no-file), (b) una URI
     * {@code file://} (calculando el digest del fichero local), o (c) una
     * URI dereferenciable (dejando que Java resuelva la dereferenciación).
     * Si hay hoja de estilo remota http(s)://, añade una referencia
     * adicional. */
    private static void buildReferencesForExternallyDetached(
            final byte[] data,
            final URI uri,
            final String precalculatedHashAlgorithm,
            final String digestMethodAlgorithm,
            final XMLSignatureFactory fac,
            final DigestMethod digestMethod,
            final Transform canonicalizationTransform,
            final XmlStyle xmlStyle,
            final List<Reference> referenceList,
            final String referenceId,
            final String referenceStyleId) throws AOException {

        Reference ref = null;
        // No tenemos uri, suponemos que los datos son el message digest
        if (precalculatedHashAlgorithm != null && (uri == null || uri.getScheme().equals("") || uri.getScheme().equals("file"))) { //$NON-NLS-1$ //$NON-NLS-2$
            DigestMethod dm = null;
            try {
                // Convertimos el algoritmo del Message Digest externo a la
                // nomenclatura XML
                if (AOSignConstants.getDigestAlgorithmName(precalculatedHashAlgorithm).equalsIgnoreCase("SHA1")) { //$NON-NLS-1$
                    dm = fac.newDigestMethod(DigestMethod.SHA1, null);
                }
                else if (AOSignConstants.getDigestAlgorithmName(precalculatedHashAlgorithm).equalsIgnoreCase("SHA-256")) { //$NON-NLS-1$
                    dm = fac.newDigestMethod(DigestMethod.SHA256, null);
                }
                else if (AOSignConstants.getDigestAlgorithmName(precalculatedHashAlgorithm).equalsIgnoreCase("SHA-512")) { //$NON-NLS-1$
                    dm = fac.newDigestMethod(DigestMethod.SHA512, null);
                }
                else if (AOSignConstants.getDigestAlgorithmName(precalculatedHashAlgorithm).equalsIgnoreCase("RIPEMD160")) { //$NON-NLS-1$
                    dm = fac.newDigestMethod(DigestMethod.RIPEMD160, null);
                }
            }
            catch (final Exception e) {
                throw new AOException("No se ha podido crear el metodo de huella digital para la referencia Externally Detached", e, XMLErrorCode.Request.INVALID_PRECALCULATED_DATA_HASH_ALGORITHM); //$NON-NLS-1$
            }
            if (dm == null) {
                throw new AOException("Metodo de Message Digest para la referencia Externally Detached no soportado: " + precalculatedHashAlgorithm, XMLErrorCode.Request.INVALID_PRECALCULATED_DATA_HASH_ALGORITHM); //$NON-NLS-1$
            }
            ref = fac.newReference(
                "", //$NON-NLS-1$
                dm,
                null,
                XMLConstants.OBJURI, // Es un nodo a firmar
                referenceId,
                data
            );
        }
        else if (uri != null && uri.getScheme().equals("file")) { //$NON-NLS-1$
            // Si es una referencia de tipo file:// obtenemos el fichero y
            // creamos una referencia solo con el message digest
            try {
                ref = fac.newReference(
                    "", //$NON-NLS-1$
                    digestMethod,
                    null,
                    XMLConstants.OBJURI,
                    referenceId,
                    MessageDigest.getInstance(
                        AOSignConstants.getDigestAlgorithmName(digestMethodAlgorithm)
                    ).digest(AOUtil.getDataFromInputStream(AOUtil.loadFile(uri)))
                );
            }
            catch (final Exception e) {
                throw new AOException("No se ha podido crear la referencia XML a partir de la URI local " + uri.toASCIIString(), e, //$NON-NLS-1$
                        XMLErrorCode.Communication.DERREFERENCING_DATA_ERROR);
            }
        }
        else if (uri != null) {
            // Si es una referencia distinta de file:// suponemos que es
            // dereferenciable de forma universal, por lo que dejamos que
            // Java lo haga todo
            try {
                ref = fac.newReference(uri.toASCIIString(), digestMethod);
            }
            catch (final Exception e) {
                throw new AOException(
                    "No se ha podido crear la referencia Externally Detached, probablemente por no obtenerse el metodo de digest", //$NON-NLS-1$
                    e, XMLErrorCode.Internal.INTERNAL_XML_SIGNING_ERROR
                );
            }
        }
        if (ref == null) {
            throw new AOException("Error al generar la firma Externally Detached, no se ha podido crear la referencia externa", XMLErrorCode.Internal.INTERNAL_XML_SIGNING_ERROR); //$NON-NLS-1$
        }
        referenceList.add(ref);

        // Hojas de estilo remotas en Externally Detached
        if (xmlStyle.getStyleHref() != null && xmlStyle.getStyleElement() == null) {
            // Comprobamos que la URL es valida
            if (xmlStyle.getStyleHref().startsWith(HTTP_PROTOCOL_PREFIX) || xmlStyle.getStyleHref().startsWith(HTTPS_PROTOCOL_PREFIX)) {
                try {
                    referenceList.add(
                        fac.newReference(
                            xmlStyle.getStyleHref(),
                            digestMethod,
                            canonicalizationTransform != null
                                ? Collections.singletonList(canonicalizationTransform)
                                : null,
                            XMLConstants.OBJURI,
                            referenceStyleId
                        )
                    );
                }
                catch (final Exception e) {
                    LOGGER.severe(
                        "No ha sido posible anadir la referencia a la hoja de estilo remota del XML en la firma Externally Detached, esta no se firmara: " + e //$NON-NLS-1$
                    );
                }
            }
            else {
                LOGGER.warning("Se necesita una referencia externa HTTP o HTTPS a la hoja de estilo para referenciarla en firmas XML Externally Detached"); //$NON-NLS-1$
            }
        }
    }

    /** Construye la referencia específica del formato XMLDSig ENVELOPED.
     * Añade a {@code transformList} la transformación ENVELOPED (siempre
     * la primera para evitar firmar nodos Signature previos) y,
     * opcionalmente, una transformación XPATH que excluye cualquier nodo
     * {@code Signature} ya presente en el documento. La referencia apunta
     * al elemento raíz (URI {@code ""}). Si hay hoja de estilo remota,
     * añade una referencia adicional vía {@link #addRemoteStyleSheetReference}. */
    private static void buildReferencesForEnveloped(
            final XMLSignatureFactory fac,
            final DigestMethod digestMethod,
            final List<Transform> transformList,
            final Transform canonicalizationTransform,
            final XmlStyle xmlStyle,
            final boolean avoidXpathExtraTransformsOnEnveloped,
            final String xmlSignaturePrefix,
            final List<Reference> referenceList,
            final String referenceId,
            final String referenceStyleId) throws AOException {

        try {
            // Transformacion enveloped: siempre la primera, para que no se
            // quede sin nodos Signature por haber ejecutado antes otra
            // transformacion
            transformList.add(fac.newTransform(Transform.ENVELOPED, (TransformParameterSpec) null));

            if (!avoidXpathExtraTransformsOnEnveloped) {
                // Transformacion XPATH para eliminar el resto de firmas del documento
                transformList.add(
                    fac.newTransform(
                        Transform.XPATH,
                        new XPathFilterParameterSpec("not(ancestor-or-self::" + xmlSignaturePrefix + ":Signature)", //$NON-NLS-1$ //$NON-NLS-2$
                        Collections.singletonMap(xmlSignaturePrefix, XMLSignature.XMLNS))
                    )
                );
            }

            // crea la referencia
            referenceList.add(
                fac.newReference(
                    "", //$NON-NLS-1$
                    digestMethod,
                    transformList,
                    XMLConstants.OBJURI, // Aunque sea Enveloped, es un nodo a firmar
                    referenceId
                )
            );
        }
        catch (final Exception e) {
            throw new AOException("Error al generar la firma en formato enveloped", e, XMLErrorCode.Internal.INTERNAL_XML_SIGNING_ERROR); //$NON-NLS-1$
        }

        addRemoteStyleSheetReference(xmlStyle, referenceList, fac, digestMethod,
                canonicalizationTransform, referenceStyleId, "Enveloped"); //$NON-NLS-1$
    }

    /** Contexto inmutable con todos los datos de configuración que necesita
     * {@link #buildAndExecuteSignature} para construir la firma XML. Agrupa
     * los 15 parámetros que de otro modo tendría que recibir el método y los
     * mantiene ocultos al ojo externo (el record es {@code private static}).
     */
    private static record SignatureBuildContext(
            XMLSignatureFactory fac,
            DigestMethod digestMethod,
            List<Transform> transformList,
            Transform canonicalizationTransform,
            String canonicalizationAlgorithm,
            String algoUri,
            String xmlSignaturePrefix,
            String format,
            XmlStyle xmlStyle,
            String styleId,
            String tmpStyleUri,
            String referenceStyleId,
            PrivateKey key,
            Certificate[] certChain,
            Properties extraParams) { }

    /** Construye el {@link XMLSignature} y ejecuta la firma. Engloba la
     * preparación del {@code KeyInfo} (con la cadena de certificados o solo
     * el firmante, según {@code includeOnlySignningCertificate}), la
     * construcción del {@code objectList} (con el {@code envelopingObject} en
     * formato ENVELOPING o la hoja de estilo en formato ENVELOPED), la
     * {@code CanonicalizationMethod}, el {@link XMLSignature} y el
     * {@link DOMSignContext} con el {@link CustomUriDereferencer}, y la
     * llamada final a {@code signature.sign()}.
     *
     * @param referenceList Lista mutable de referencias a la que se añade la
     *                      referencia al {@code KeyInfo} (y opcionalmente a la
     *                      hoja de estilo en ENVELOPED).
     * @param envelopingObject {@link XMLObject} con los datos a firmar en
     *                         formato ENVELOPING (o {@code null}).
     * @param envelopingStyleObject {@link XMLObject} con la hoja de estilo en
     *                              formato ENVELOPING (o {@code null}).
     * @param docSignature Documento donde se va a insertar la firma.
     * @param ctx Contexto inmutable con el resto de parámetros de configuración.
     * @throws AOException Si falla la canonicalización, el algoritmo no está
     *                     soportado o cualquier error durante el firmado. */
    private static void buildAndExecuteSignature(
            final List<Reference> referenceList,
            final XMLObject envelopingObject,
            final XMLObject envelopingStyleObject,
            final Document docSignature,
            final SignatureBuildContext ctx) throws AOException {

        // definicion de identificadores
        final String id = UUID.randomUUID().toString();
        final String keyInfoId = "KeyInfo-" + id; //$NON-NLS-1$

        try {
            // se anade una referencia a KeyInfo
            referenceList.add(ctx.fac().newReference("#" + keyInfoId, ctx.digestMethod(), ctx.transformList(), null, null)); //$NON-NLS-1$

            // KeyInfo
            final KeyInfoFactory kif = ctx.fac().getKeyInfoFactory();
            final List<XMLStructure> content = new ArrayList<>();
            final X509Certificate cert = (X509Certificate) ctx.certChain()[0];
            content.add(kif.newKeyValue(cert.getPublicKey()));

            // Si se nos ha pedido expresamente que no insertemos la cadena de certificacion,
            // insertamos unicamente el certificado firmante. Tambien lo haremos cuando al
            // recuperar la cadena nos devuelva null
            Certificate[] certs = null;
            final boolean onlySignningCert = Boolean.parseBoolean(
                    ctx.extraParams().getProperty(
                            AOXMLDSigExtraParams.INCLUDE_ONLY_SIGNNING_CERTIFICATE, Boolean.FALSE.toString()));
            if (!onlySignningCert) {
                certs = ctx.certChain();
            }
            if (certs == null) {
                certs = new Certificate[] { cert };
            }
            content.add(kif.newX509Data(Arrays.asList(certs)));

            // Object
            final List<XMLObject> objectList = new ArrayList<>();

            // en el caso de formato enveloping se inserta el elemento Object
            // con el documento a firmar
            if (ctx.format().equals(AOSignConstants.SIGN_FORMAT_XMLDSIG_ENVELOPING) && envelopingObject != null) {
                objectList.add(envelopingObject);
                if (envelopingStyleObject != null) {
                    objectList.add(envelopingStyleObject);
                }
            }

            // Si es enveloped hay que anadir la hoja de estilo dentro de la
            // firma y referenciarla
            if (ctx.format().equals(AOSignConstants.SIGN_FORMAT_XMLDSIG_ENVELOPED) && ctx.xmlStyle().getStyleElement() != null) {
                objectList.add(
                    ctx.fac().newXMLObject(
                        Collections.singletonList(new DOMStructure(ctx.xmlStyle().getStyleElement())),
                        ctx.styleId(),
                        ctx.xmlStyle().getStyleType(),
                        ctx.xmlStyle().getStyleEncoding()
                    )
                );
                try {
                    referenceList.add(
                        ctx.fac().newReference(
                            ctx.tmpStyleUri(),
                            ctx.digestMethod(),
                            ctx.canonicalizationTransform() != null
                                ? Collections.singletonList(ctx.canonicalizationTransform())
                                : null,
                            XMLConstants.OBJURI,
                            ctx.referenceStyleId()
                        )
                    );
                }
                catch (final Exception e) {
                    LOGGER.severe("No se ha podido anadir una referencia a la hoja de estilo, esta se incluira dentro de la firma, pero no estara firmada: " + e); //$NON-NLS-1$
                }
            }

            final CanonicalizationMethod cm;
            try {
                cm = ctx.fac().newCanonicalizationMethod(
                    ctx.canonicalizationTransform() != null
                        ? ctx.canonicalizationAlgorithm()
                        : CanonicalizationMethod.INCLUSIVE,
                    (C14NMethodParameterSpec) null);
            }
            catch (final NoSuchAlgorithmException e) {
                throw new AOException(
                    "No se ha podido crear la transformacion de canonicalizacion para el algoritmo " + ctx.canonicalizationAlgorithm(), //$NON-NLS-1$
                    e, XMLErrorCode.Request.INVALID_CANONICALIZATION_URI);
            }

            // genera la firma
            final XMLSignature signature = ctx.fac().newXMLSignature(
                ctx.fac().newSignedInfo(
                    cm,
                    ctx.fac().newSignatureMethod(ctx.algoUri(), null),
                    XmlDSigUtil.cleanReferencesList(referenceList)),
                kif.newKeyInfo(content, keyInfoId),
                objectList,
                "Signature-" + id, //$NON-NLS-1$
                "SignatureValue-" + id //$NON-NLS-1$
            );

            final DOMSignContext signContext = new DOMSignContext(
                ctx.key(), docSignature.getDocumentElement());
            signContext.putNamespacePrefix(XMLConstants.DSIGNNS, ctx.xmlSignaturePrefix());

            try {
                // Instalamos un dereferenciador nuevo que solo actua cuando falla el por defecto
                signContext.setURIDereferencer(
                    new CustomUriDereferencer(CustomUriDereferencer.getDefaultDereferencer()));
            }
            catch (final Exception e) {
                LOGGER.warning("No se ha podido instalar un dereferenciador a medida, es posible que fallen las firmas de nodos concretos: " + e); //$NON-NLS-1$
            }

            signature.sign(signContext);
        }
        catch (final NoSuchAlgorithmException e) {
            throw new UnsupportedOperationException(
                "Hay al menos un algoritmo no soportado: " + e, e); //$NON-NLS-1$
        }
        catch (final AOException e) {
            throw e;
        }
        catch (final Exception e) {
            throw new AOException("Error al generar la firma XMLdSig: " + e, e, XMLErrorCode.Internal.INTERNAL_XML_SIGNING_ERROR); //$NON-NLS-1$
        }
    }

    /** Extrae el nodo {@code <Signature>} a un Document nuevo cuando la firma es
     * <i>enveloping</i>, eliminando el envoltorio {@code <AFIRMA>} que no aporta
     * valor estructural. Para los demás formatos devuelve el documento sin
     * modificar.
     * @param docSignature Documento con la firma generada.
     * @param format Formato XMLDSig (ENVELOPING/ENVELOPED/DETACHED/EXTERNALLY_DETACHED).
     * @param xmlSignaturePrefix Prefijo XML del elemento {@code Signature} (puede ser vacío).
     * @return El documento listo para serializar. */
    private static Document postprocessEnvelopingDocument(final Document docSignature,
            final String format, final String xmlSignaturePrefix) {
        if (!format.equals(AOSignConstants.SIGN_FORMAT_XMLDSIG_ENVELOPING)) {
            return docSignature;
        }
        final String signatureNodeName = (xmlSignaturePrefix == null || xmlSignaturePrefix.isEmpty()
                ? "" : xmlSignaturePrefix + ":") + XMLConstants.TAG_SIGNATURE; //$NON-NLS-1$ //$NON-NLS-2$
        try {
            if (docSignature.getElementsByTagName(signatureNodeName).getLength() == 1) {
                final Document newdoc = Utils.getNewDocumentBuilder().newDocument();
                newdoc.appendChild(newdoc.adoptNode(docSignature.getElementsByTagName(signatureNodeName).item(0)));
                return newdoc;
            }
        }
        catch (final Exception e) {
            LOGGER.info("No se ha eliminado el nodo padre '<AFIRMA>': " + e); //$NON-NLS-1$
        }
        return docSignature;
    }

    /** Serializa el documento de firma a bytes. Si el formato es <i>enveloped</i>
     * propaga la cabecera de hoja de estilo del XML original; en cualquier otro
     * formato se omite para no contaminar la salida.
     * @param docSignature Documento con la firma.
     * @param format Formato XMLDSig.
     * @param originalXMLProperties Propiedades XML del documento original (encoding, version, doctype).
     * @param xmlStyle Hoja de estilo asociada al XML original (puede estar vacía).
     * @return La firma serializada como {@code byte[]}. */
    private static byte[] serializeSignatureToBytes(final Document docSignature, final String format,
            final Map<String, String> originalXMLProperties, final XmlStyle xmlStyle) {
        final boolean isEnveloped = format.equals(AOSignConstants.SIGN_FORMAT_XMLDSIG_ENVELOPED);
        return Utils.writeXML(
            docSignature.getDocumentElement(),
            originalXMLProperties,
            isEnveloped ? xmlStyle.getStyleHref() : null,
            isEnveloped ? xmlStyle.getStyleType() : null
        );
    }

    /** Comprueba si la firma es detached.
     * @param element
     *        Elemento que contiene el nodo ra&iacute;z del documento que se
     *        quiere comprobar
     * @return Valor booleano, siendo verdadero cuando la firma es detached */
    private static boolean isDetached(final Element element) {
        if (element == null) {
            return false;
        }
        if (element.getFirstChild().getLocalName() != null && element.getFirstChild().getLocalName().equals(DETACHED_CONTENT_ELEMENT_NAME)) {
            return true;
        }
        return false;
    }

    /** Comprueba si la firma es <i>enveloped</i>.
     * @param element Elemento que contiene el nodo ra&iacute;z del documento que se
     *                quiere comprobar.
     * @return Valor booleano, siendo verdadero cuando la firma es <i>enveloped</i>. */
    private static boolean isEnveloped(final Element element) {
        final NodeList transformList = element.getElementsByTagNameNS(XMLConstants.DSIGNNS, "Transform"); //$NON-NLS-1$
        for (int i = 0; i < transformList.getLength(); i++) {
            if (((Element) transformList.item(i)).getAttribute("Algorithm").equals(Transform.ENVELOPED)){ //$NON-NLS-1$
                return true;
            }
        }
        return false;
    }

    /** Comprueba si la firma es <i>enveloping</i>.
     * @param element Elemento que contiene el nodo ra&iacute;z del documento que se quiere comprobar.
     * @return Valor booleano, siendo verdadero cuando la firma es <i>enveloping</i>. */
    private static boolean isEnveloping(final Element element) {
        if (element == null) {
            return false;
        }
        return XMLConstants.TAG_SIGNATURE.equals(element.getLocalName()) ||
        		AFIRMA.equals(element.getNodeName()) && XMLConstants.TAG_SIGNATURE.equals(element.getFirstChild().getLocalName());
    }

    /** {@inheritDoc} */
	@Override
	public byte[] getData(final byte[] sign) throws AOInvalidSignatureFormatException {
		return getData(sign, null);
	}

    /** {@inheritDoc} */
    @Override
	public byte[] getData(final byte[] sign, final Properties params) throws AOInvalidSignatureFormatException {

        final Element rootSig;
        Element elementRes = null;
        try {
            // comprueba que sea una documento de firma valido
            if (!isSign(sign)) {
                throw new AOInvalidSignatureFormatException("El documento no es un documento de firmas valido."); //$NON-NLS-1$
            }

            // obtiene la raiz del documento de firmas
            rootSig = Utils.getNewDocumentBuilder().parse(new ByteArrayInputStream(sign)).getDocumentElement();

            // si es detached
            if (AOXMLDSigSigner.isDetached(rootSig)) {
                final Element firstChild = (Element) rootSig.getFirstChild();
                // si el documento es un xml se extrae como tal
                if (firstChild.getAttribute(MIMETYPE_STR).equals("text/xml")) { //$NON-NLS-1$
                    elementRes = (Element) firstChild.getFirstChild();
                }
                // si el documento es binario se deshace la codificacion en Base64
                else {
                    return Base64.decode(firstChild.getTextContent());
                }
            }

            // si es enveloped
            else if (AOXMLDSigSigner.isEnveloped(rootSig)) {
                // obtiene las firmas y las elimina
                final NodeList signatures = rootSig.getElementsByTagNameNS(XMLConstants.DSIGNNS, XMLConstants.TAG_SIGNATURE);
                final int numSignatures = signatures.getLength();
                for (int i = 0; i < numSignatures; i++) {
                	// Comprobamos que no sean nulas, ya que las contrafirmas
                	// han podido eliminarse al eliminar alguna otra firma
                	if (signatures.item(i) != null) {
                		rootSig.removeChild(signatures.item(i));
                	}
                }
                elementRes = rootSig;
            }

            // si es enveloping
            else if (AOXMLDSigSigner.isEnveloping(rootSig)) {
                // obtiene el nodo Object de la primera firma
                final Element object = (Element) rootSig.getElementsByTagNameNS(XMLConstants.DSIGNNS, "Object").item(0); //$NON-NLS-1$
                // si el documento es un xml se extrae como tal
                if (object.getAttribute(MIMETYPE_STR).equals("text/xml")) { //$NON-NLS-1$
                    elementRes = (Element) object.getFirstChild();
                }
                else {
                    return Base64.decode(object.getTextContent());
                }
            }
        }
        catch (final Exception ex) {
            throw new AOInvalidSignatureFormatException("Error al leer el fichero de firmas", ex); //$NON-NLS-1$
        }

        // si no se ha recuperado ningun dato se devuelve null
        if (elementRes == null) {
            return null;
        }

        // convierte el documento obtenido en un array de bytes
        final ByteArrayOutputStream baosSig = new ByteArrayOutputStream();
        writeXML(new BufferedWriter(new OutputStreamWriter(baosSig)), elementRes);
        return baosSig.toByteArray();
    }

    /** Cofirma una firma en formato XMLdSig.
     * <p>
     *  Este m&eacute;todo firma todas las referencias a datos declaradas en la firma original,
     *  ya apunten estas a datos, hojas de estilo o cualquier otro elemento. En cada referencia
     *  firmada se introduciran las mismas transformaciones que existiesen en la firma original.
     * </p>
     * <p>
     *  A nivel de formato interno, cuando cofirmamos un documento ya firmado previamente, esta
     *  firma previa no se modifica. Si tenemos en cuenta que XAdES es en realidad un subconjunto
     *  de XMLDSig, el resultado de una cofirma XMLdSig sobre un documento firmado previamente con
     *  XAdES (o viceversa), son dos firmas independientes, una en XAdES y otra en XMLDSig.<br>
     *  Dado que todas las firmas XAdES son XMLDSig pero no todas las firmas XMLDSig son XAdES,
     *  el resultado global de la firma se adec&uacute;a al estandar mas amplio, XMLDSig en este caso.
     * </p>
     * @param data No se utiliza.
     * @param sign Firma que se desea cofirmar.
     * @param algorithm Algoritmo a usar para la firma.
     * @param key Clave privada a usar para firmar
     * @param certChain Cadena de certificados del firmante
     * @param xParams Par&aacute;metros adicionales para la firma.
     * <p>Se aceptan los siguientes valores en el par&aacute;metro <code>xParams</code>:</p>
     * <dl>
     *  <dt><b><i>xmlSignaturePrefix</i></b></dt>
     *   <dd>
     *    Prefijo de espacio de nombres XML para los nodos de firma. Si no se especifica este par&aacute;metro
     *    se usa el valor por defecto (<i>ds</i>).
     *   </dd>
     *  <dt><b><i>referencesDigestMethod</i></b></dt>
     *   <dd>Algoritmo de huella digital a usar en las referencias XML</dd>
     *  <dt><b><i>canonicalizationAlgorithm</i></b></dt>
     *   <dd>Algoritmo de canonicalizaci&oacute;n<i>n</i></dd>
     *  <dt><b><i>includeOnlySignningCertificate</i></b></dt>
	 *   <dd>Indica, mediante un {@code true} o {@code false}, que debe
	 *   incluirse en la firma &uacute;nicamente el certificado utilizado
	 *   para firmar y no su cadena de certificaci&oacute;n completa.
	 *   Por defecto, se incluir&aacute; toda la cadena de certificaci&oacute;n.
	 *   </dd>
     * </dl>
     * @return Firma en formato XMLDSig 1.0
     * @throws AOException Cuando ocurre cualquier problema durante el proceso */
    @Override
	public byte[] cosign(final byte[] data,
                         final byte[] sign,
                         final String algorithm,
                         final PrivateKey key,
                         final Certificate[] certChain,
                         final Properties xParams) throws AOException {

        final String algoUri = XMLConstants.SIGN_ALGOS_URI.get(algorithm);
        if (algoUri == null) {
        	throw new AOException(
    				"Los formatos de firma XML no soportan el algoritmo de firma " + algorithm, ErrorCode.Request.UNSUPPORTED_SIGNATURE_ALGORITHM); //$NON-NLS-1$
        }

        final Properties extraParams = xParams != null ? xParams : new Properties();

        final String digestMethodAlgorithm = extraParams.getProperty(AOXMLDSigExtraParams.REFERENCES_DIGEST_METHOD, DIGEST_METHOD);
        final String canonicalizationAlgorithm = extraParams.getProperty(AOXMLDSigExtraParams.CANONICALIZATION_ALGORITHM, CanonicalizationMethod.INCLUSIVE);
        final String xmlSignaturePrefix = extraParams.getProperty(AOXMLDSigExtraParams.XML_SIGNATURE_PREFIX, XML_SIGNATURE_PREFIX);

        // Propiedades del documento XML original
        final Map<String, String> originalXMLProperties = new Hashtable<>();

        // carga el documento XML de firmas y su raiz
        Document docSig;
        Element rootSig;
        try {
        	final DocumentBuilder docBuilder = Utils.getNewDocumentBuilder();
            docSig = docBuilder.parse(new ByteArrayInputStream(sign));
            rootSig = docSig.getDocumentElement();

            // si el documento contiene una firma simple se inserta como raiz el
            // nodo AFIRMA
            if (XMLConstants.TAG_SIGNATURE.equals(rootSig.getLocalName()) && XMLConstants.DSIGNNS.equals(rootSig.getNamespaceURI())) {
                docSig = insertarNodoAfirma(docSig, docBuilder);
                rootSig = docSig.getDocumentElement();
            }
        }
        catch (final ParserConfigurationException pcex) {
            throw new AOException("Error en el analizador XML: " + pcex, pcex, XMLErrorCode.Internal.INTERNAL_XML_SIGNING_ERROR); //$NON-NLS-1$
        }
        catch (final SAXException saxex) {
            throw new AOInvalidSignatureFormatException("Formato de documento de firmas (XML firmado de entrada) incorrecto: " + saxex, saxex); //$NON-NLS-1$
        }
        catch (final Exception e) {
            throw new AOException("No se ha podido leer el documento XML de firmas", e, XMLErrorCode.Internal.INTERNAL_XML_SIGNING_ERROR); //$NON-NLS-1$
        }

        final List<Reference> referenceList = new ArrayList<>();
        final XMLSignatureFactory fac = Utils.getDOMFactory();
        final DigestMethod digestMethod;
        try {
            digestMethod = fac.newDigestMethod(digestMethodAlgorithm, null);
        }
        catch (final Exception e) {
            throw new AOException("No se ha podido obtener un generador de huellas digitales para el algoritmo " + digestMethodAlgorithm, //$NON-NLS-1$
            		e, XMLErrorCode.Request.INVALID_REFERENCES_HASH_ALGORITHM_URI);
        }

        // Localizamos la primera firma (primer nodo XMLConstants.TAG_SIGNATURE) en profundidad
        // en el arbol de firma.
        // Se considera que todos los objetos XMLConstants.TAG_SIGNATURE del documento firman
        // (referencian) los mismos
        // objetos, por lo que podemos extraerlos de cualquiera de las firmas
        // actuales.
        // Buscamos dentro de ese Signature todas las referencias que apunten a
        // datos para firmarlas
        final ArrayList<String> referencesIds = new ArrayList<>();
        Node currentReference;
        final NodeList nl = ((Element) docSig.getElementsByTagNameNS(XMLConstants.DSIGNNS, XMLConstants.TAG_SIGNATURE).item(0)).getElementsByTagNameNS(XMLConstants.DSIGNNS, REFERENCE_STR);

        // Se considera que la primera referencia de la firma son los datos que
        // debemos firmar, ademas
        // de varias referencias especiales
        XMLObject envelopingObject = null;
        for (int i = 0; i < nl.getLength(); i++) {
            currentReference = nl.item(i);

            // Firmamos la primera referencia (que seran los datos firmados) y
            // las hojas de estilo que
            // tenga asignadas. Las hojas de estilo tendran un identificador que
            // comience por STYLE_REFERENCE_PREFIX.
            // TODO: Identificar las hojas de estilo de un modo generico.
            final NamedNodeMap currentNodeAttributes = currentReference.getAttributes();
            if (i == 0 || currentNodeAttributes.getNamedItem(ID_IDENTIFIER) != null &&
            		currentNodeAttributes.getNamedItem(ID_IDENTIFIER).getNodeValue().startsWith(STYLE_REFERENCE_PREFIX)) {

                // Buscamos las transformaciones declaradas en la Referencia,
                // para anadirlas
                // tambien en la nueva
                List<Transform> currentTransformList;
                try {
                    currentTransformList = Utils.getObjectReferenceTransforms(currentReference, xmlSignaturePrefix);
                }
                catch (final NoSuchAlgorithmException e) {
                    Logger.getLogger("Se ha declarado una transformacion personalizada de un tipo no soportado: " + e); //$NON-NLS-1$
                    throw new AOException("Se ha declarado una transformacion personalizada de un tipo no soportado", e, XMLErrorCode.Internal.UNSUPPORTED_TRANSFORMATION_ALGORITHM); //$NON-NLS-1$
                }
                catch (final InvalidAlgorithmParameterException e) {
                    Logger.getLogger("Se han especificado parametros erroneos para una transformacion personalizada: " + e); //$NON-NLS-1$
                    throw new AOException("Se han especificado parametros erroneos para una transformacion personalizada", e, XMLErrorCode.Request.INVALID_TRANSFORMATION); //$NON-NLS-1$
                }

                // Creamos un identificador de referencia para el objeto a
                // firmar y la almacenamos
                // para mantener un listado con todas. En el caso de las hojas
                // de estilo lo creamos con un
                // identificador descriptivo
                String referenceId = null;
                if (currentNodeAttributes.getNamedItem(ID_IDENTIFIER) != null &&
                		currentNodeAttributes.getNamedItem(ID_IDENTIFIER).getNodeValue().startsWith(STYLE_REFERENCE_PREFIX)) {
                    referenceId = STYLE_REFERENCE_PREFIX + UUID.randomUUID().toString();
                }
                else {
                    referenceId = "Reference-" + UUID.randomUUID().toString(); //$NON-NLS-1$
                }
                referencesIds.add(referenceId);

                // Creamos la propia referencia con las transformaciones de la original
                // TODO: Copiar el nodo para enveloping
                final String referenceUri = ((Element) currentReference).getAttribute(URI_STR);
                if (isEnveloping(rootSig) && referenceUri != null) {

                	final Node dataNode = searchDataElement(referenceUri, rootSig);
                	if (dataNode == null) {
                		LOGGER.severe("No se ha identificado el nodo de datos a firmar"); //$NON-NLS-1$
                		throw new AOException("No se ha identificado el nodo de datos a firmar", XMLErrorCode.Internal.INTERNAL_XML_SIGNING_ERROR); //$NON-NLS-1$
                	}

                	// crea el nuevo elemento Object que con el documento afirmar
					final List<XMLStructure> structures = new ArrayList<>(1);
					structures.add(new DOMStructure(dataNode.getFirstChild().cloneNode(true)));

					final String mimeType = ((Element) dataNode).getAttribute(MIMETYPE_STR);
					final String encoding = ((Element) dataNode).getAttribute(ENCODING_STR);

					final String newObjectId = "Object-" + UUID.randomUUID().toString(); //$NON-NLS-1$
					envelopingObject = fac.newXMLObject(structures, newObjectId, mimeType, encoding);

					// Agregamos la referencia al nuevo objeto de datos
					referenceList.add(
						fac.newReference(
							"#" + newObjectId, //$NON-NLS-1$
							digestMethod,
							currentTransformList,
							XMLConstants.OBJURI,
							referenceId
						)
					);
                }
                else {
                	referenceList.add(
            			fac.newReference(
                			((Element) currentReference).getAttribute(URI_STR),
                			digestMethod,
                			currentTransformList, // Lista de transformaciones
                			XMLConstants.OBJURI,
                			referenceId
            			)
        			);
                }
            }
        }

        // definicion de identificadores
        final String id = UUID.randomUUID().toString();
        final String signatureId = "Signature-" + id; //$NON-NLS-1$
        final String signatureValueId = "SignatureValue-" + id; //$NON-NLS-1$
        final String keyInfoId = "KeyInfo-" + id; //$NON-NLS-1$

        try {
        	// CanonicalizationMethod
            final CanonicalizationMethod cm = fac.newCanonicalizationMethod(canonicalizationAlgorithm, (C14NMethodParameterSpec) null);

            // se anade una referencia a KeyInfo
            final List<Transform> transformList = new ArrayList<>();
            final Transform trCanonicalization = fac.newTransform(canonicalizationAlgorithm, (TransformParameterSpec) null);
            transformList.add(trCanonicalization);
            referenceList.add(fac.newReference("#" + keyInfoId, digestMethod, transformList, null, null)); //$NON-NLS-1$

            // SignatureMethod
            final SignatureMethod sm = fac.newSignatureMethod(algoUri, null);

            // KeyInfo
            final KeyInfoFactory kif = fac.getKeyInfoFactory();
            final X509Certificate cert = (X509Certificate) certChain[0];

            final List<XMLStructure> content = new ArrayList<>();
            content.add(kif.newKeyValue(cert.getPublicKey()));

            // Si se nos ha pedido expresamente que no insertemos la cadena de certificacion,
            // insertamos unicamente el certificado firmante. Tambien lo haremos cuando al
            // recuperar la cadena nos devuelva null
            Certificate[] certs = null;
            final boolean onlySignningCert = Boolean.parseBoolean(
        		extraParams.getProperty(
        		        AOXMLDSigExtraParams.INCLUDE_ONLY_SIGNNING_CERTIFICATE,
    				Boolean.FALSE.toString()
				)
    		);
			if (!onlySignningCert) {
				certs = certChain;
			}
            if (certs == null) {
                certs = new Certificate[] {
                    cert
                };
            }
            content.add(kif.newX509Data(Arrays.asList(certs)));

            final DOMSignContext signContext = new DOMSignContext(key, rootSig);
            signContext.putNamespacePrefix(XMLConstants.DSIGNNS, xmlSignaturePrefix);
            try {
            	// Instalamos un dereferenciador nuevo que solo actua cuando falla el por defecto
            	signContext.setURIDereferencer(
        			new CustomUriDereferencer(CustomUriDereferencer.getDefaultDereferencer())
    			);
            }
            catch (final Exception e) {
            	LOGGER.warning("No se ha podido instalar un dereferenciador a medida, es posible que fallen las firmas de nodos concretos: " + e); //$NON-NLS-1$
            }

            // en el caso de formato enveloping se inserta el elemento Object
            // con el documento a firmar
            final List<XMLObject> objectList = new ArrayList<>();
            if (isEnveloping(rootSig) && envelopingObject != null) {
                objectList.add(envelopingObject);
            }

            fac.newXMLSignature(
        		fac.newSignedInfo(cm, sm, referenceList), // SignedInfo
                kif.newKeyInfo(content, keyInfoId), // KeyInfo
                objectList,
                signatureId,
                signatureValueId
            ).sign(signContext);

        }
        catch (final NoSuchAlgorithmException e) {
            throw new UnsupportedOperationException(
        		"Hay al menos un algoritmo no soportado: " + e, e //$NON-NLS-1$
    		);
        }
        catch (final Exception e) {
            throw new AOException("Error al generar la cofirma XMLdSig: " + e, e, XMLErrorCode.Internal.INTERNAL_XML_SIGNING_ERROR); //$NON-NLS-1$
        }

        return Utils.writeXML(rootSig, originalXMLProperties, null, null);
    }

    /** Cofirma una firma en formato XMLdSig.
     * <p>
     *  Este m&eacute;todo firma todas las referencias a datos declaradas en la firma original,
     *  ya apunten estas a datos, hojas de estilo o cualquier otro elemento. En cada referencia
     *  firmada se introduciran las mismas transformaciones que existiesen en la firma original.
     * </p>
     * <p>
     *  A nivel de formato interno, cuando cofirmamos un documento ya firmado previamente, esta
     *  firma previa no se modifica. Si tenemos en cuenta que XAdES es en realidad un subconjunto
     *  de XMLDSig, el resultado de una cofirma XMLdSig sobre un documento firmado previamente con
     *  XAdES (o viceversa), son dos firmas independientes, una en XAdES y otra en XMLDSig.<br>
     *  Dado que todas las firmas XAdES son XMLDSig pero no todas las firmas XMLDSig son XAdES,
     *  el resultado global de la firma se adec&uacute;a al estandar mas amplio, XMLDSig en este caso.
     * </p>
     * @param sign Firma que se desea cofirmar.
     * @param algorithm Algoritmo a usar para la firma.
     * @param key Clave privada a usar para firmar
     * @param certChain Cadena de certificados del firmante
     * @param xParams Par&aacute;metros adicionales para la firma.
     * <p>Se aceptan los siguientes valores en el par&aacute;metro <code>xParams</code>:</p>
     * <dl>
     *  <dt><b><i>xmlSignaturePrefix</i></b></dt>
     *   <dd>
     *    Prefijo de espacio de nombres XML para los nodos de firma. Si no se especifica este par&aacute;metro
     *    se usa el valor por defecto (<i>ds</i>).
     *   </dd>
     *  <dt><b><i>referencesDigestMethod</i></b></dt>
     *   <dd>Algoritmo de huella digital a usar en las referencias XML</dd>
     *  <dt><b><i>canonicalizationAlgorithm</i></b></dt>
     *   <dd>Algoritmo de canonicalizaci&oacute;n<i>n</i></dd>
     *  <dt><b><i>includeOnlySignningCertificate</i></b></dt>
	 *   <dd>Indica, mediante un {@code true} o {@code false}, que debe
	 *   incluirse en la firma &uacute;nicamente el certificado utilizado
	 *   para firmar y no su cadena de certificaci&oacute;n completa.
	 *   Por defecto, se incluir&aacute; toda la cadena de certificaci&oacute;n.
	 *   </dd>
     * </dl>
     * @return Firma en formato XMLDSig 1.0
     * @throws AOException Cuando ocurre cualquier problema durante el proceso */
    @Override
	public byte[] cosign(final byte[] sign,
			             final String algorithm,
			             final PrivateKey key,
			             final Certificate[] certChain,
			             final Properties xParams) throws AOException {

        // carga la raiz del documento XML de firmas
        // y crea un nuevo documento que contendra solo los datos sin firmar
        Element rootSig;
        Element rootData;
        try {
        	final DocumentBuilder docBuilder = Utils.getNewDocumentBuilder();
            rootSig = docBuilder.parse(new ByteArrayInputStream(sign)).getDocumentElement();

            final Document docData = docBuilder.newDocument();
            rootData = (Element) docData.adoptNode(rootSig.cloneNode(true));

            // Obtiene las firmas y las elimina. Para evitar eliminar firmas de
            // las que cuelgan otras
            // y despues intentar eliminar estas, las buscamos y eliminamos de
            // una en una
            NodeList signatures = rootData.getElementsByTagNameNS(XMLConstants.DSIGNNS, XMLConstants.TAG_SIGNATURE);
            while (signatures.getLength() > 0) {
                rootData.removeChild(signatures.item(0));
                signatures = rootData.getElementsByTagNameNS(XMLConstants.DSIGNNS, XMLConstants.TAG_SIGNATURE);
            }

            docData.appendChild(rootData);
        }
        catch (final ParserConfigurationException pcex)
        {
            throw new AOException("Error en el analizador XML: " + pcex, pcex, XMLErrorCode.Internal.INTERNAL_XML_SIGNING_ERROR); //$NON-NLS-1$
        }
        catch (final SAXException saxex) {
            throw new AOInvalidSignatureFormatException("Formato de documento de firmas (XML firmado de entrada) incorrecto: " + saxex, saxex); //$NON-NLS-1$
        }
        catch (final Exception e) {
            throw new AOException("No se ha podido leer el documento XML de firmas", e, XMLErrorCode.Internal.INTERNAL_XML_SIGNING_ERROR); //$NON-NLS-1$
        }

        // convierte el documento de firmas en un InputStream
        final ByteArrayOutputStream baosSig = new ByteArrayOutputStream();
        writeXML(new BufferedWriter(new OutputStreamWriter(baosSig)), rootSig);

        // convierte el documento a firmar en un InputStream
        final ByteArrayOutputStream baosData = new ByteArrayOutputStream();
        writeXML(new BufferedWriter(new OutputStreamWriter(baosData)), rootData);

        return cosign(baosData.toByteArray(), baosSig.toByteArray(), algorithm, key, certChain, xParams);
    }

    /** Contrafirma firmas en formato XMLdSig.
     * <p>
     * Este m&eacute;todo contrafirma los nodos de firma indicados de un documento de firma.
     * </p>
     * @param sign Documento con las firmas iniciales.
     * @param algorithm Algoritmo a usar para la firma.
     * @param targetType Mecanismo de selecci&oacute;n de los nodos de firma que se deben
     * contrafirmar.
     * <p>Las distintas opciones son:</p>
     * <ul>
     * <li>Todos los nodos del &aacute;rbol de firma</li>
     * <li>Los nodos hoja del &aacute;rbol de firma</li>
     * <li>Los nodos de firma cuyas posiciones se especifican en <code>target</code></li>
     * <li>Los nodos de firma realizados por los firmantes cuyo <i>Common Name</i> se indica en <code>target</code></li>
     * </ul>
     * <p>Cada uno de estos tipos se define en {@link es.gob.afirma.core.signers.CounterSignTarget}.
     * @param targets Listado de nodos o firmantes que se deben contrafirmar seg&uacute;n el
     * {@code targetType} seleccionado.
     * @param key Clave privada a usar para firmar.
     * @param certChain Cadena de certificados del firmante.
     * @param xParams Par&aacute;metros adicionales para la firma.
     * <p>Se aceptan los siguientes valores en el par&aacute;metro <code>xParams</code>:</p>
     * <dl>
     *  <dt><b><i>encoding</i></b></dt>
     *   <dd>Fuerza la codificaci&oacute;n del XML de salida (utf-8, iso-8859-1,...)</dd>
     *  <dt><b><i>xmlSignaturePrefix</i></b></dt>
     *   <dd>
     *    Prefijo de espacio de nombres XML para los nodos de firma. Si no se especifica este par&aacute;metro
     *    se usa el valor por defecto (<i>ds</i>).
     *   </dd>
     *  <dt><b><i>referencesDigestMethod</i></b></dt>
     *   <dd>Algoritmo de huella digital a usar en las referencias XML</dd>
     *  <dt><b><i>canonicalizationAlgorithm</i></b></dt>
     *   <dd>Algoritmo de canonicalizaci&oacute;n<i>n</i></dd>
     *  <dt><b><i>includeOnlySignningCertificate</i></b></dt>
	 *   <dd>Indica, mediante un {@code true} o {@code false}, que debe
	 *   incluirse en la firma &uacute;nicamente el certificado utilizado
	 *   para firmar y no su cadena de certificaci&oacute;n completa.
	 *   Por defecto, se incluir&aacute; toda la cadena de certificaci&oacute;n.</dd>
     * </dl>
     * @return Contrafirma en formato XMLdSig.
     * @throws AOException Cuando ocurre cualquier problema durante el proceso */
    @Override
	public byte[] countersign(final byte[] sign,
                              final String algorithm,
                              final CounterSignTarget targetType,
                              final Object[] targets,
                              final PrivateKey key,
                              final Certificate[] certChain,
                              final Properties xParams) throws AOException {

        final String algoUri = XMLConstants.SIGN_ALGOS_URI.get(algorithm);
        if (algoUri == null) {
        	throw new AOException(
    				"Los formatos de firma XML no soportan el algoritmo de firma " + algorithm, ErrorCode.Request.UNSUPPORTED_SIGNATURE_ALGORITHM); //$NON-NLS-1$
        }

        final Properties extraParams = xParams != null ? xParams : new Properties();

        final String digestMethodAlgorithm = extraParams.getProperty(AOXMLDSigExtraParams.REFERENCES_DIGEST_METHOD, DIGEST_METHOD);
        final String canonicalizationAlgorithm = extraParams.getProperty(AOXMLDSigExtraParams.CANONICALIZATION_ALGORITHM, CanonicalizationMethod.INCLUSIVE);
        String encoding = extraParams.getProperty(AOXMLDSigExtraParams.ENCODING);
        if ("base64".equalsIgnoreCase(encoding)) { //$NON-NLS-1$
            encoding = XMLConstants.BASE64_ENCODING;
        }
        final String xmlSignaturePrefix = extraParams.getProperty(AOXMLDSigExtraParams.XML_SIGNATURE_PREFIX, XML_SIGNATURE_PREFIX);
        final boolean onlySignningCert = Boolean.parseBoolean(
        		extraParams.getProperty(AOXMLDSigExtraParams.INCLUDE_ONLY_SIGNNING_CERTIFICATE, Boolean.FALSE.toString()));

        // se carga el documento XML y su raiz
        final Map<String, String> originalXMLProperties = new Hashtable<>();
        final Document doc;
        Element root;
        try {
        	final DocumentBuilder docBuilder = Utils.getNewDocumentBuilder();
            Document parsedDoc = docBuilder.parse(new ByteArrayInputStream(sign));

            // Tomamos la configuracion del XML que contrafirmamos
            if (encoding == null) {
                encoding = parsedDoc.getXmlEncoding();
            }

            // Ademas del encoding, sacamos otros datos del doc XML original
            // Hacemos la comprobacion del base64 por si se establecido desde
            // fuera
            if (encoding != null && !XMLConstants.BASE64_ENCODING.equalsIgnoreCase(encoding)) {
                originalXMLProperties.put(OutputKeys.ENCODING, encoding);
            }
            String tmpXmlProp = parsedDoc.getXmlVersion();
            if (tmpXmlProp != null) {
                originalXMLProperties.put(OutputKeys.VERSION, tmpXmlProp);
            }
            final DocumentType dt = parsedDoc.getDoctype();
            if (dt != null) {
                tmpXmlProp = dt.getSystemId();
                if (tmpXmlProp != null) {
                    originalXMLProperties.put(OutputKeys.DOCTYPE_SYSTEM, tmpXmlProp);
                }
            }

            root = parsedDoc.getDocumentElement();

            // si el nodo raiz del documento es una firma simple, se inserta como raiz el
            // nodo AFIRMA

            if (XMLConstants.TAG_SIGNATURE.equals(root.getLocalName()) && XMLConstants.DSIGNNS.equals(root.getNamespaceURI())) {
                parsedDoc = insertarNodoAfirma(parsedDoc, docBuilder);
                root = parsedDoc.getDocumentElement();
            }
            doc = parsedDoc;

            // Selección de nodos vía Strategy (Fase D.1) + creación de la
            // contrafirma vía XmlSignatureCountersigner (Fase D.2). Cada
            // CounterSignTarget tiene su propio CountersignNodeSelector que
            // filtra el conjunto de firmas; la creación del nodo de
            // contrafirma es la misma para los 4 destinos.
            final List<Element> nodesToCountersign =
                    CountersignNodeSelector.forTarget(targetType).selectNodes(root, targets);
            final XmlSignatureCountersigner countersigner = new XmlSignatureCountersigner();
            for (final Element node : nodesToCountersign) {
                try {
                    countersigner.countersignNode(node, algorithm, key, certChain,
                            onlySignningCert, digestMethodAlgorithm,
                            canonicalizationAlgorithm, xmlSignaturePrefix);
                }
                catch (final AOException e) {
                    throw e;
                }
                catch (final Exception e) {
                    throw new AOException("No se ha podido realizar la contrafirma del nodo '" //$NON-NLS-1$
                            + (node != null ? node.getNodeName() : "nulo") + "': " + e, e, //$NON-NLS-1$ //$NON-NLS-2$
                            XMLErrorCode.Internal.UNKWNON_XML_SIGNING_ERROR);
                }
            }

        }
        catch (final AOException e) {
        	throw e;
        }
        catch (final Exception e) {
            throw new AOException("No se ha podido realizar la contrafirma: " + e, e, XMLErrorCode.Internal.INTERNAL_XML_SIGNING_ERROR); //$NON-NLS-1$
        }

        // convierte el xml resultante para devolverlo como byte[]
        return Utils.writeXML(doc.getDocumentElement(), originalXMLProperties, null, null);
    }

    /** {@inheritDoc} */
	@Override
	public AOTreeModel getSignersStructure(final byte[] sign, final boolean asSimpleSignInfo) {
		return getSignersStructure(sign, null, asSimpleSignInfo);
	}

    /** {@inheritDoc} */
    @Override
	public AOTreeModel getSignersStructure(final byte[] sign, final Properties params, final boolean asSimpleSignInfo) {

        // recupera la raiz del documento de firmas
        Element root;
        final String completePrefix;
        try {
        	final DocumentBuilder docBuilder = Utils.getNewDocumentBuilder();
            Document doc = docBuilder.parse(new ByteArrayInputStream(sign));
            root = doc.getDocumentElement();

            // Identificamos el prefijo que se utiliza en los nodos de firma
            final String xmlDSigNSPrefix = XmlDSigUtil.guessXmlDSigNamespacePrefix(root);
            completePrefix = "".equals(xmlDSigNSPrefix) ? "" : xmlDSigNSPrefix + ":"; //$NON-NLS-1$ //$NON-NLS-2$ //$NON-NLS-3$

            // Si el documento tiene como nodo raiz el nodo de firma, se agrega
            // un nodo raiz previo para que la lectura de las firmas del
            // documento
            // se haga correctamente
            if (root.getNodeName().equals(completePrefix + XMLConstants.TAG_SIGNATURE)) {
                doc = insertarNodoAfirma(doc, docBuilder);
                root = doc.getDocumentElement();
            }
        }
        catch (final Exception e) {
            LOGGER.warning("Se ha producido un error al obtener la estructura de firmas: " + e); //$NON-NLS-1$
            return null;
        }

        final AOTreeNode tree = new AOTreeNode("Datos"); //$NON-NLS-1$

        // Obtenemos todas las firmas y los signature value
        final NodeList signatures = root.getElementsByTagName(completePrefix + XMLConstants.TAG_SIGNATURE);
        final NodeList signatureValues = root.getElementsByTagName(completePrefix + SIGNATURE_VALUE);

        final int numSignatures = signatures.getLength();
        final String[] arrayIds = new String[numSignatures];
        final String[] arrayRef = new String[numSignatures];
        final AOTreeNode[] arrayNodes = new AOTreeNode[numSignatures];

        for (int i = 0; i < numSignatures; i++) {

            final Element signature = (Element) signatures.item(i);

            arrayIds[i] = signature.getAttribute(ID_IDENTIFIER);

            arrayNodes[i] = new AOTreeNode(asSimpleSignInfo ? Utils.getSimpleSignInfoNode(XADESNS, signature) : Utils.getStringInfoNode(signature));

            // Recogemos el identificador de la firma a la que se referencia (si
            // no es contrafirma sera cadena vacia)
            final String typeReference = ((Element) signature.getElementsByTagNameNS(XMLConstants.DSIGNNS, REFERENCE_STR).item(0)).getAttribute("Type"); //$NON-NLS-1$
            if (typeReference.equals(CSURI)) {
                arrayRef[i] = Utils.getCounterSignerReferenceId(signature, signatureValues);
            }
            else {
                arrayRef[i] = ""; //$NON-NLS-1$
            }
        }

        // Se buscan las contrafirmas de cada firma o cofirma
        for (int i = 0; i < numSignatures; i++) {
            if ("".equals(arrayRef[i])) { //$NON-NLS-1$
                tree.add(generaArbol(i, numSignatures - 1, arrayNodes, arrayIds, arrayRef)[i]);
            }
        }

        return new AOTreeModel(tree);
    }

    /** M&eacute;todo recursivo para la obtenci&oacute;n de la estructura de
     * &aacute;rbol.
     * @param i Inicio de lectura del array de identificadores
     * @param j Inicio de lectura inversa del array de referencias
     * @param arrayNodes Array de objetos AOTreeNode
     * @param arrayIds Array de identificadores
     * @param arrayRef Array de referencias
     * @return Array de objetos AOTreeNode */
    private AOTreeNode[] generaArbol(final int i, final int j, final AOTreeNode arrayNodes[], final String arrayIds[], final String arrayRef[]) {
        final int max = arrayIds.length;
        if (i < max && j > 0) {
            if (arrayIds[i].equals(arrayRef[j])) {
                generaArbol(i + 1, j - 1, arrayNodes, arrayIds, arrayRef);
            }
            if (i < j) {
                generaArbol(i, j - 1, arrayNodes, arrayIds, arrayRef);
            }
            if (!arrayIds[i].equals(arrayRef[j])) {
                return arrayNodes;
            }
            generaArbol(j, max - 1, arrayNodes, arrayIds, arrayRef);
            arrayNodes[i].add(arrayNodes[j]);
        }
        return arrayNodes;
    }

    /** {@inheritDoc} */
	@Override
	public boolean isSign(final byte[] sign){
		return isSign(sign, null);
	}

    /** {@inheritDoc} */
    @Override
	public boolean isSign(final byte[] sign, final Properties params) {

        if (sign == null) {
            LOGGER.warning("Se han introducido datos nulos para su comprobacion"); //$NON-NLS-1$
            return false;
        }

        try {
            // Carga el documento a validar
            final Document signDoc = Utils.getNewDocumentBuilder().parse(new ByteArrayInputStream(sign));
            final Element rootNode = signDoc.getDocumentElement();

            final ArrayList<Node> signNodes = new ArrayList<>();
            if (XMLConstants.TAG_SIGNATURE.equals(rootNode.getLocalName())
            		&& XMLConstants.DSIGNNS.equals(rootNode.getNamespaceURI())) {
                signNodes.add(rootNode);
            }

            final NodeList signatures = rootNode.getElementsByTagNameNS(XMLConstants.DSIGNNS, XMLConstants.TAG_SIGNATURE);
            for (int i = 0; i < signatures.getLength(); i++) {
                signNodes.add(signatures.item(i));
            }

            // Si no se encuentran firmas, no es un documento de firma
            if (signNodes.size() == 0) {
                return false;
            }

        }
        catch (final Exception e) {
            return false;
        }
        return true;
    }

    /** {@inheritDoc} */
    @Override
	public boolean isValidDataFile(final byte[] data) {
        if (data == null) {
            LOGGER.warning("Se han introducido datos nulos para su comprobacion"); //$NON-NLS-1$
            return false;
        }
        return true;
    }

    /** {@inheritDoc} */
    @Override
	public String getSignedName(final String originalName, final String inText) {
        return originalName + (inText != null ? inText : "") + ".xsig"; //$NON-NLS-1$ //$NON-NLS-2$
    }

    /**
     * Devuelve un nuevo documento con ra&iacute;z "AFIRMA" y conteniendo al
     * documento pasado por par&aacute;metro.
     * @param docu Documento que estar&aacute; contenido en el nuevo documento
     * @param docBuilder Constructor de documentos XML.
     * @return Documento con ra&iacute;z "AFIRMA"
     */
    private static Document insertarNodoAfirma(final Document docu, final DocumentBuilder docBuilder) {

        // Crea un nuevo documento con la raiz "AFIRMA"
        final Document docAfirma = docBuilder.newDocument();
        final Element rootAfirma = docAfirma.createElement(AFIRMA);

        // Inserta el documento pasado por parametro en el nuevo documento
        rootAfirma.appendChild(docAfirma.adoptNode(docu.getDocumentElement()));
        docAfirma.appendChild(rootAfirma);

        return docAfirma;
    }

	@Override
	public AOSignInfo getSignInfo(final byte[] data) throws AOException {
		return getSignInfo(data, null);
	}

    /** {@inheritDoc} */
    @Override
	public AOSignInfo getSignInfo(final byte[] data, final Properties params) throws AOException {
        if (data == null) {
            throw new IllegalArgumentException("No se han introducido datos para analizar"); //$NON-NLS-1$
        }

        if (!isSign(data)) {
            throw new AOInvalidSignatureFormatException("Los datos introducidos no se corresponden con un objeto de firma"); //$NON-NLS-1$
        }

        final AOSignInfo signInfo = new AOSignInfo(AOSignConstants.SIGN_FORMAT_XMLDSIG);

        // Analizamos mas en profundidad la firma para obtener el resto de datos

        // Tomamos la raiz del documento
        Element rootSig = null;
        try {
            rootSig = Utils.getNewDocumentBuilder().parse(new ByteArrayInputStream(data)).getDocumentElement();
        }
        catch (final Exception e) {
            LOGGER.warning("Error al analizar la firma: " + e); //$NON-NLS-1$
            rootSig = null;
        }

        // Establecemos la variante de firma
        if (rootSig != null) {
            if (isDetached(rootSig)) {
                signInfo.setVariant(AOSignConstants.SIGN_FORMAT_XMLDSIG_DETACHED);
            }
            else if (isEnveloped(rootSig)) {
                signInfo.setVariant(AOSignConstants.SIGN_FORMAT_XMLDSIG_ENVELOPED);
            }
            else if (isEnveloping(rootSig)) {
                signInfo.setVariant(AOSignConstants.SIGN_FORMAT_XMLDSIG_ENVELOPING);
            }
        }

        // Aqui vendria el analisis de la firma buscando alguno de los otros
        // datos de relevancia
        // que se almacenan en el objeto AOSignInfo

        return signInfo;
    }

    /** Escribe el documento especificado al documento dado. La codificaci&oacute;n por
     * defecto es UTF-8.
     * @param writer Clase para la escritura.
     * @param node Nodo ra&iacute;z del XML. */
    private static void writeXML(final Writer writer, final Node node) {
        final Document document = node.getOwnerDocument();
        final DOMImplementationLS domImplLS = (DOMImplementationLS) document.getImplementation();
        final LSSerializer serializer = domImplLS.createLSSerializer();
        serializer.getDomConfig().setParameter("namespaces", Boolean.FALSE); //$NON-NLS-1$
        final DOMOutputImpl output = new DOMOutputImpl();
        output.setCharacterStream(writer);
        serializer.write(node, output);
    }

    /**
     * Busca en un elemento XML el nodo de datos con un ID concreto.
     * @param dataElementIdReference Referencia al elemento que se busca.
     * @param rootElement Elemento XML a partir del cual buscar.
     * @return Elemento XML con los datos o {@code null} si no se encuentra.
     */
    private static Element searchDataElement(final String dataElementIdReference, final Element rootElement) {

    	final String dataElementId = dataElementIdReference.substring(dataElementIdReference.startsWith("#") ? 1 : 0); //$NON-NLS-1$
		Element dataObjectElement = null;

		// Comprobamos si el nodo raiz o sus hijos inmediatos son el nodo de datos
		Node nodeAttributeId = rootElement.getAttributes() != null ? rootElement.getAttributes().getNamedItem(ID_IDENTIFIER) : null;
		if (nodeAttributeId != null && dataElementId.equals(nodeAttributeId.getNodeValue())) {
			dataObjectElement = rootElement;
		}
		else {
			// Recorremos los hijos al reves para acceder antes a los datos y las firmas
			final NodeList rootChildNodes = rootElement.getChildNodes();
			for (int j = rootChildNodes.getLength() - 1; j >= 0; j--) {

				nodeAttributeId = rootChildNodes.item(j).getAttributes() != null ? rootChildNodes.item(j).getAttributes().getNamedItem(ID_IDENTIFIER) : null;
				if (nodeAttributeId != null && dataElementId.equals(nodeAttributeId.getNodeValue())) {
					dataObjectElement = (Element) rootChildNodes.item(j);
					break;
				}

				// Si es un nodo de firma tambien miramos en sus nodos hijos
				if (XMLConstants.TAG_SIGNATURE.equals(rootChildNodes.item(j).getLocalName())) {
					final NodeList subChildsNodes = rootChildNodes.item(j).getChildNodes();
					for (int k = subChildsNodes.getLength() - 1; k >= 0; k--) {
						nodeAttributeId = subChildsNodes.item(k).getAttributes() != null ? subChildsNodes.item(k).getAttributes().getNamedItem(ID_IDENTIFIER) : null;
						if (nodeAttributeId != null && dataElementId.equals(nodeAttributeId.getNodeValue())) {
							dataObjectElement = (Element) subChildsNodes.item(k);
							break;
						}
					}
					if (dataObjectElement != null) {
						break;
					}
				}
			}
		}
    	return dataObjectElement;
    }

	/**
	 * A&ntilde;ade a {@code referenceList} la referencia a una hoja de estilo
	 * remota (HTTP/HTTPS) cuando el estilo XML est&aacute; declarado externamente
	 * y no se ha empotrado como elemento. Si la hoja no es remota o ya viene
	 * empotrada, este m&eacute;todo no hace nada.
	 *
	 * <p>Centraliza un bloque que aparec&iacute;a duplicado en los branches
	 * Enveloping y Enveloped del m&eacute;todo {@code sign()} (las dos copias
	 * son sem&aacute;nticamente id&eacute;nticas salvo por el formato citado en
	 * el mensaje de log).</p>
	 *
	 * @param xmlStyle Informaci&oacute;n de la hoja de estilo asociada al XML.
	 * @param referenceList Lista de referencias de firma sobre la que se a&ntilde;ade.
	 * @param fac Factor&iacute;a XMLSig usada para construir la referencia.
	 * @param digestMethod Algoritmo de huella para la referencia.
	 * @param canonicalizationTransform Transformaci&oacute;n de canonicalizaci&oacute;n a aplicar (puede ser {@code null}).
	 * @param referenceStyleId Identificador a asignar a la referencia.
	 * @param signatureFormat Nombre del formato (solo para mensajes de log: Enveloping / Enveloped).
	 */
	private static void addRemoteStyleSheetReference(final XmlStyle xmlStyle,
			final java.util.List<javax.xml.crypto.dsig.Reference> referenceList,
			final javax.xml.crypto.dsig.XMLSignatureFactory fac,
			final javax.xml.crypto.dsig.DigestMethod digestMethod,
			final javax.xml.crypto.dsig.Transform canonicalizationTransform,
			final String referenceStyleId,
			final String signatureFormat) {
		if (xmlStyle.getStyleHref() == null
				|| xmlStyle.getStyleElement() != null
				|| !xmlStyle.getStyleHref().startsWith(HTTP_PROTOCOL_PREFIX)
				&& !xmlStyle.getStyleHref().startsWith(HTTPS_PROTOCOL_PREFIX)) {
			return;
		}
		try {
			referenceList.add(
				fac.newReference(
					xmlStyle.getStyleHref(),
					digestMethod,
					canonicalizationTransform != null
						? Collections.singletonList(canonicalizationTransform)
						: null,
					XMLConstants.OBJURI,
					referenceStyleId
				)
			);
		}
		catch (final Exception e) {
			LOGGER.severe(
				"No ha sido posible anadir la referencia a la hoja de estilo remota del XML en la firma " //$NON-NLS-1$
					+ signatureFormat + ", esta no se firmara: " + e //$NON-NLS-1$
			);
		}
	}

}
