package es.gob.afirma.core.util.tree;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotSame;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

/** Pruebas del &aacute;rbol ligero sin dependencias Swing. */
final class TestAOTreeNode {

	/** Comprueba inserci&oacute;n, copia y validaciones estructurales. */
	@Test
	void treeNodesKeepParentChildInvariants() {
		final AOTreeNode root = new AOTreeNode("raiz"); //$NON-NLS-1$
		final AOTreeNode first = new AOTreeNode("primero"); //$NON-NLS-1$
		final AOTreeNode second = new AOTreeNode("segundo"); //$NON-NLS-1$
		final AOTreeNode otherRoot = new AOTreeNode("otra"); //$NON-NLS-1$

		assertTrue(root.isLeaf());
		assertEquals("raiz", root.toString()); //$NON-NLS-1$
		assertEquals("null", new AOTreeNode(null).toString()); //$NON-NLS-1$
		assertThrows(ArrayIndexOutOfBoundsException.class, () -> root.getChildAt(0));
		assertThrows(IllegalArgumentException.class, () -> root.add(null));

		root.add(first);
		root.add(second);
		assertEquals(2, root.getChildCount());
		assertSame(first, root.getChildAt(0));
		assertSame(second, root.getChildAt(1));
		assertEquals("primero", first.getUserObject()); //$NON-NLS-1$

		otherRoot.add(first);
		assertEquals(1, root.getChildCount());
		assertSame(second, root.getChildAt(0));
		assertSame(first, otherRoot.getChildAt(0));

		assertThrows(IllegalArgumentException.class, () -> second.add(root));

		final AOTreeNode copy = AOTreeNode.copyOf(otherRoot);
		assertNotSame(otherRoot, copy);
		assertEquals(otherRoot.toString(), copy.toString());
		assertEquals(1, copy.getChildCount());
		assertNotSame(first, copy.getChildAt(0));
		assertEquals(first.toString(), copy.getChildAt(0).toString());
		assertNull(AOTreeNode.copyOf(null));
	}
}
