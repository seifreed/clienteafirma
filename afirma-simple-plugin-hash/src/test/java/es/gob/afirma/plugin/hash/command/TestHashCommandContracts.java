package es.gob.afirma.plugin.hash.command;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;

import org.junit.jupiter.api.Test;

import es.gob.afirma.core.misc.AOUtil;
import es.gob.afirma.plugin.hash.Messages;

/** Pruebas de contratos de los comandos del plugin de huellas. */
final class TestHashCommandContracts {

	/** Comprueba parseo de comandos y parametros. */
	@Test
	void hashParametersParseOptionsAndDefaults() throws Exception {
		final File input = File.createTempFile("hash-command", ".txt"); //$NON-NLS-1$ //$NON-NLS-2$
		final File hashFile = File.createTempFile("hash-command", ".hash"); //$NON-NLS-1$ //$NON-NLS-2$
		final File output = new File(input.getParentFile(), "hash-command-out.bin"); //$NON-NLS-1$
		try {
			Files.write(input.toPath(), "abc".getBytes(StandardCharsets.UTF_8)); //$NON-NLS-1$
			Files.write(hashFile.toPath(), "hash".getBytes(StandardCharsets.UTF_8)); //$NON-NLS-1$

			assertEquals(HashCommands.CREATEHASH, HashCommands.parse("createdigest")); //$NON-NLS-1$
			assertEquals(HashCommands.CHECKHASH, HashCommands.parse("checkdigest")); //$NON-NLS-1$
			assertNull(HashCommands.parse("missing")); //$NON-NLS-1$
			assertTrue(HashCommands.CREATEHASH.isMainFileNeeded());
			assertFalse(HashCommands.CHECKHASH.isMainFileNeeded());

			final HashParameters createParams = new HashParameters(
				HashCommands.CREATEHASH,
				new String[] {
					input.getAbsolutePath(),
					"-o", output.getAbsolutePath(), //$NON-NLS-1$
					"-hformat", "B64", //$NON-NLS-1$ //$NON-NLS-2$
					"-halgorithm", "SHA-384", //$NON-NLS-1$ //$NON-NLS-2$
					"-xml", //$NON-NLS-1$
					"-gui", //$NON-NLS-1$
					"-r", //$NON-NLS-1$
					"-d" //$NON-NLS-1$
				}
			);
			assertEquals(input.getCanonicalFile(), createParams.getMainFile().getCanonicalFile());
			assertEquals(output.getCanonicalFile(), createParams.getOutputFile().getCanonicalFile());
			assertEquals(HashParameters.FORMAT_HASH_FILE_BASE64, createParams.getHashFileFormat());
			assertThrows(IllegalArgumentException.class, createParams::getHashDirectoryFormat);
			assertEquals("SHA-384", createParams.getHashAlgorithm()); //$NON-NLS-1$
			assertTrue(createParams.isXml());
			assertTrue(createParams.isGui());
			assertTrue(createParams.isRecursive());
			assertTrue(createParams.isDirectory());

			final HashParameters checkParams = new HashParameters(
				HashCommands.CHECKHASH,
				new String[] {
					input.getAbsolutePath(),
					"-i", hashFile.getAbsolutePath(), //$NON-NLS-1$
					"-hformat", "txt" //$NON-NLS-1$ //$NON-NLS-2$
				}
			);
			assertEquals(input.getCanonicalFile(), checkParams.getMainFile().getCanonicalFile());
			assertEquals(hashFile.getCanonicalFile(), checkParams.getInputFile().getCanonicalFile());
			assertEquals(HashParameters.FORMAT_HASH_DIR_PLAIN, checkParams.getHashDirectoryFormat());
			assertThrows(IllegalArgumentException.class, checkParams::getHashFileFormat);

			assertTrue(HashParameters.buildSyntaxError(HashCommands.CREATEHASH, "error").contains("createdigest")); //$NON-NLS-1$ //$NON-NLS-2$
			assertTrue(HashParameters.buildSyntaxError(HashCommands.CHECKHASH, "error").contains("checkdigest")); //$NON-NLS-1$ //$NON-NLS-2$
			assertThrows(IllegalArgumentException.class, () -> new HashParameters(HashCommands.CREATEHASH, new String[0]));
			assertThrows(IllegalArgumentException.class, () -> new HashParameters(HashCommands.CHECKHASH, new String[] { "-unknown" })); //$NON-NLS-1$
			assertThrows(IllegalArgumentException.class, () -> new HashParameters(HashCommands.CREATEHASH, new String[] { input.getAbsolutePath(), "-hformat", "bad" })); //$NON-NLS-1$ //$NON-NLS-2$
			assertThrows(IllegalArgumentException.class, () -> new HashParameters(HashCommands.CHECKHASH, new String[] { input.getAbsolutePath(), "-i" })); //$NON-NLS-1$
			assertThrows(IllegalArgumentException.class, () -> new HashParameters(HashCommands.CHECKHASH, new String[] { input.getAbsolutePath(), "-i", hashFile.getAbsolutePath(), "-i", hashFile.getAbsolutePath() })); //$NON-NLS-1$ //$NON-NLS-2$ //$NON-NLS-3$
			assertThrows(IllegalArgumentException.class, () -> new HashParameters(HashCommands.CHECKHASH, new String[] { input.getAbsolutePath(), "-o" })); //$NON-NLS-1$
			assertThrows(IllegalArgumentException.class, () -> new HashParameters(HashCommands.CHECKHASH, new String[] { input.getAbsolutePath(), "-hformat", "hex", "-hformat", "hex" })); //$NON-NLS-1$ //$NON-NLS-2$ //$NON-NLS-3$ //$NON-NLS-4$
			assertThrows(IllegalArgumentException.class, () -> new HashParameters(HashCommands.CHECKHASH, new String[] { input.getAbsolutePath(), "-halgorithm", "SHA-256", "-halgorithm", "SHA-256" })); //$NON-NLS-1$ //$NON-NLS-2$ //$NON-NLS-3$ //$NON-NLS-4$
		}
		finally {
			Files.deleteIfExists(input.toPath());
			Files.deleteIfExists(hashFile.toPath());
			Files.deleteIfExists(output.toPath());
		}
	}

	/** Comprueba ejecucion por consola con ficheros reales. */
	@Test
	void createAndCheckHashCommandsUseRealFiles() throws Exception {
		final File input = File.createTempFile("hash-command-data", ".txt"); //$NON-NLS-1$ //$NON-NLS-2$
		final File hashFile = File.createTempFile("hash-command-data", ".hash"); //$NON-NLS-1$ //$NON-NLS-2$
		final File output = new File(input.getParentFile(), "hash-command-data-out.hash"); //$NON-NLS-1$
		try {
			Files.write(input.toPath(), "abc".getBytes(StandardCharsets.UTF_8)); //$NON-NLS-1$
			final byte[] expectedHash = MessageDigest.getInstance("SHA-256").digest("abc".getBytes(StandardCharsets.UTF_8)); //$NON-NLS-1$ //$NON-NLS-2$

			final CreateHashCommand createHashCommand = new CreateHashCommand();
			final String generatedHash = createHashCommand.process(new String[] {
				input.getAbsolutePath(),
				"-hformat", "hex" //$NON-NLS-1$ //$NON-NLS-2$
			});
			assertEquals(AOUtil.hexify(expectedHash, false) + "h", generatedHash); //$NON-NLS-1$

			final String outputMessage = createHashCommand.process(new String[] {
				input.getAbsolutePath(),
				"-o", output.getAbsolutePath(), //$NON-NLS-1$
				"-hformat", "bin" //$NON-NLS-1$ //$NON-NLS-2$
			});
			assertEquals(Messages.getString("CommandLine.22"), outputMessage); //$NON-NLS-1$
			assertArrayEquals(expectedHash, Files.readAllBytes(output.toPath()));

			Files.write(hashFile.toPath(), expectedHash);
			final CheckHashCommand checkHashCommand = new CheckHashCommand();
			assertEquals(
				Messages.getString("CommandLine.123"), //$NON-NLS-1$
				checkHashCommand.process(new String[] { input.getAbsolutePath(), "-i", hashFile.getAbsolutePath() }) //$NON-NLS-1$
			);
			final byte[] badHash = expectedHash.clone();
			badHash[0]++;
			Files.write(hashFile.toPath(), badHash);
			assertEquals(
				Messages.getString("CommandLine.124"), //$NON-NLS-1$
				checkHashCommand.process(new String[] { input.getAbsolutePath(), "-i", hashFile.getAbsolutePath() }) //$NON-NLS-1$
			);

			assertNotNull(new CreateHashCommand("createdigest").getHelpText()); //$NON-NLS-1$
			assertNotNull(new CheckHashCommand("checkdigest").getHelpText()); //$NON-NLS-1$
			assertTrue(createHashCommand.process(new String[] { "-help" }).contains("createdigest")); //$NON-NLS-1$ //$NON-NLS-2$
			assertTrue(checkHashCommand.process(null).contains("checkdigest")); //$NON-NLS-1$
			assertTrue(checkHashCommand.process(new String[0]).contains("checkdigest")); //$NON-NLS-1$
			assertThrows(IllegalArgumentException.class, () -> checkHashCommand.process(new String[] { input.getAbsolutePath() }));
		}
		finally {
			Files.deleteIfExists(input.toPath());
			Files.deleteIfExists(hashFile.toPath());
			Files.deleteIfExists(output.toPath());
		}
	}

	/** Comprueba ejecucion por consola con directorios reales. */
	@Test
	void createAndCheckHashCommandsUseRealDirectories() throws Exception {
		final Path dir = Files.createTempDirectory("hash-command-dir"); //$NON-NLS-1$
		final Path nested = Files.createDirectory(dir.resolve("subdir")); //$NON-NLS-1$
		final Path file = dir.resolve("a.txt"); //$NON-NLS-1$
		final Path nestedFile = nested.resolve("b.txt"); //$NON-NLS-1$
		final File hashFile = new File(dir.toFile().getParentFile(), "hash-command-dir.hashfiles"); //$NON-NLS-1$
		final File reportFile = new File(dir.toFile().getParentFile(), "hash-command-dir-report.xml"); //$NON-NLS-1$
		try {
			Files.write(file, "abc".getBytes(StandardCharsets.UTF_8)); //$NON-NLS-1$
			Files.write(nestedFile, "def".getBytes(StandardCharsets.UTF_8)); //$NON-NLS-1$

			final CreateHashCommand createHashCommand = new CreateHashCommand();
			assertEquals(
				Messages.getString("CommandLine.22"), //$NON-NLS-1$
				createHashCommand.process(new String[] {
					dir.toFile().getAbsolutePath(),
					"-o", hashFile.getAbsolutePath(), //$NON-NLS-1$
					"-hformat", "txt", //$NON-NLS-1$ //$NON-NLS-2$
					"-r" //$NON-NLS-1$
				})
			);
			final String hashDocument = Files.readString(hashFile.toPath(), StandardCharsets.UTF_8);
			assertTrue(hashDocument.contains("SHA-256")); //$NON-NLS-1$
			assertTrue(hashDocument.contains("subdir")); //$NON-NLS-1$

			final CheckHashCommand checkHashCommand = new CheckHashCommand();
			assertEquals(
				Messages.getString("CommandLine.124"), //$NON-NLS-1$
				checkHashCommand.process(new String[] {
					dir.toFile().getAbsolutePath(),
					"-i", hashFile.getAbsolutePath(), //$NON-NLS-1$
					"-o", reportFile.getAbsolutePath() //$NON-NLS-1$
				})
			);
			final String report = Files.readString(reportFile.toPath(), StandardCharsets.UTF_8);
			assertTrue(report.contains("file_without_hash")); //$NON-NLS-1$
		}
		finally {
			Files.deleteIfExists(reportFile.toPath());
			Files.deleteIfExists(hashFile.toPath());
			Files.deleteIfExists(nestedFile);
			Files.deleteIfExists(file);
			Files.deleteIfExists(nested);
			Files.deleteIfExists(dir);
		}
	}
}
