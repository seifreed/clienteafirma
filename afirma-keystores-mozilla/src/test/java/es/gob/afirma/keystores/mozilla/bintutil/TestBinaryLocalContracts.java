package es.gob.afirma.keystores.mozilla.bintutil;

import java.io.File;

import org.junit.Assert;
import org.junit.Test;

/** Pruebas de utilidades locales de an&aacute;lisis binario. */
public final class TestBinaryLocalContracts {

	/** Comprueba lectura de enteros little-endian y mapeos PE. */
	@Test
	public void testPeHelpersAndParser() throws Exception {
		Assert.assertEquals(0x0201, AOBinUtil.getU2(new byte[] { 0x01, 0x02 }, 0));
		Assert.assertEquals(0x04030201, AOBinUtil.getInt(new byte[] { 0x01, 0x02, 0x03, 0x04 }, 0));
		Assert.assertEquals(PeMachineType.X64, PeMachineType.getPeMachineType("86-64")); //$NON-NLS-1$
		Assert.assertNull(PeMachineType.getPeMachineType("FF-FF")); //$NON-NLS-1$
		Assert.assertEquals("x64", PeMachineType.X64.toString()); //$NON-NLS-1$

		final MsPortableExecutable pe = new MsPortableExecutable(minimalPe());
		Assert.assertEquals(PeMachineType.X64, pe.getPeMachineType());
		Assert.assertTrue(pe.toString().contains("Fichero Microsoft PE")); //$NON-NLS-1$
		Assert.assertThrows(PEParserException.class, () -> new MsPortableExecutable(new byte[160]));
	}

	/** Comprueba mapeos ELF sobre recursos reales y entradas inv&aacute;lidas. */
	@Test
	public void testElfParserContracts() throws Exception {
		Assert.assertEquals(ElfMachineType.AMD64, ElfParser.getMachineType(resourceFile("/elf_x64"))); //$NON-NLS-1$
		Assert.assertEquals(ElfMachineType.X86, ElfParser.getMachineType(resourceFile("/elf_x86"))); //$NON-NLS-1$
		Assert.assertEquals(ElfMachineType.ARM64, ElfParser.getMachineType(resourceFile("/elf_arm64"))); //$NON-NLS-1$
		Assert.assertEquals(ElfMachineType.RISCV, ElfParser.getMachineType(elfWithMachine((byte) 0xF3)));
		Assert.assertEquals(ElfMachineType.UNKNOWN, ElfParser.getMachineType(elfWithMachine((byte) 0x7F)));
		Assert.assertEquals("AMD64", ElfMachineType.AMD64.toString()); //$NON-NLS-1$

		Assert.assertThrows(IllegalArgumentException.class, () -> ElfParser.getMachineType((byte[]) null));
		Assert.assertThrows(IllegalArgumentException.class, () -> ElfParser.getMachineType(new byte[2]));
		Assert.assertThrows(IllegalArgumentException.class, () -> ElfParser.getMachineType((String) null));
		Assert.assertFalse(ElfParser.archMatches(null));
	}

	private static byte[] minimalPe() {
		final byte[] pe = new byte[160];
		pe[0x3c] = (byte) 0x80;
		pe[0x80] = 'P';
		pe[0x81] = 'E';
		pe[0x82] = 0;
		pe[0x83] = 0;
		pe[0x84] = 0x64;
		pe[0x85] = (byte) 0x86;
		return pe;
	}

	private static byte[] elfWithMachine(final byte machine) {
		final byte[] elf = new byte[0x13];
		elf[0x12] = machine;
		return elf;
	}

	private static File resourceFile(final String resource) throws Exception {
		return new File(TestBinaryLocalContracts.class.getResource(resource).toURI());
	}
}
