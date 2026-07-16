package es.gob.afirma.standalone.ui.preferences;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import javax.swing.SwingUtilities;

import org.junit.jupiter.api.Test;

import es.gob.afirma.standalone.ProxyConfig;
import es.gob.afirma.standalone.ProxyConfig.ConfigType;

/** Pruebas locales del panel de proxy. */
final class TestProxyPanelContracts {

	/** Comprueba radios, filtro de puerto y extraccion de configuracion sin red. */
	@Test
	void proxyPanelBuildsCustomConfigFromFields() throws Exception {
		Thread.sleep(200);
		SwingUtilities.invokeAndWait(() -> {
			final ProxyPanel panel = new ProxyPanel();
			try {
				Thread.sleep(200);
			}
			catch (final InterruptedException e) {
				Thread.currentThread().interrupt();
			}
			panel.getManualProxyRb().setSelected(true);
			panel.getHostField().setText("proxy.local"); //$NON-NLS-1$
			panel.getPortField().setText("8080"); //$NON-NLS-1$
			panel.getPortField().setText("8080x"); //$NON-NLS-1$
			panel.getUsernameField().setText("usuario"); //$NON-NLS-1$
			panel.getPasswordField().setText("clave"); //$NON-NLS-1$
			panel.getExcludedUrlsField().setText("localhost,127.0.0.1"); //$NON-NLS-1$

			assertTrue(panel.getManualProxyRb().isSelected());
			assertTrue(panel.getHostField().isEnabled());
			assertEquals("8080", panel.getPortField().getText()); //$NON-NLS-1$

			final ProxyConfig config = new ProxyPanelHandler(panel).getProxyConfig();
			assertEquals(ConfigType.CUSTOM, config.getConfigType());
			assertEquals("proxy.local", config.getHost()); //$NON-NLS-1$
			assertEquals("8080", config.getPort()); //$NON-NLS-1$
			assertEquals("usuario", config.getUsername()); //$NON-NLS-1$
			assertEquals("clave", String.valueOf(config.getPassword())); //$NON-NLS-1$
			assertEquals("localhost,127.0.0.1", config.getExcludedUrls()); //$NON-NLS-1$

			panel.getNoProxyRb().setSelected(true);
			assertFalse(panel.getHostField().isEnabled());
			assertEquals(ConfigType.NONE, new ProxyPanelHandler(panel).getProxyConfig().getConfigType());
		});
	}
}
