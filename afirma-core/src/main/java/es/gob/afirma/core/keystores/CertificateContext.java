package es.gob.afirma.core.keystores;

import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableEntryException;

import javax.security.auth.callback.PasswordCallback;

/**
 * Contexto de un certificado consistente en el almac&eacute;n al que pertenece
 * y el alias con el cual obtenerlo.
 */
public interface CertificateContext {

	/**
	 * Obtiene la clave privada asociada al certificado seleccionado.
	 * @return Entrada de clave privada del certificado.
	 * @throws KeyStoreException Cuando ocurren errores en el tratamiento del almac&eacute;n de claves.
	 * @throws NoSuchAlgorithmException Cuando no se puede identificar el algoritmo para recuperar la clave.
	 * @throws UnrecoverableEntryException Si la contrase&ntilde;a proporcionada no es v&aacute;lida.
	 */
	KeyStore.PrivateKeyEntry getKeyEntry() throws KeyStoreException, NoSuchAlgorithmException, UnrecoverableEntryException;

	/**
	 * Establece el callback de contrase&ntilde;a para recuperar la entrada seleccionada.
	 * @param passwordCallback Callback de contrase&ntilde;a.
	 */
	void setEntryPasswordCallBack(PasswordCallback passwordCallback);

	/**
	 * Establece el componente padre para los di&aacute;logos asociados al almac&eacute;n.
	 * @param parent Componente padre.
	 */
	void setParentComponent(Object parent);

	/**
	 * Alias del certificado dentro del almac&eacute;n.
	 * @return Alias del certificado.
	 */
	String getAlias();
}
