/*******************************************************************************
 * Copyright (c) 2014 IBM Corporation.
 *
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * and Eclipse Distribution License v. 1.0 which accompanies this distribution.
 *
 * The Eclipse Public License is available at http://www.eclipse.org/legal/epl-v10.html
 * and the Eclipse Distribution License is available at
 * http://www.eclipse.org/org/documents/edl-v10.php.
 *
 * Contributors:
 *
 *     Samuel Padgett - initial implementation
 *******************************************************************************/
package org.eclipse.lyo.server.jenkins.auto;

import hudson.model.AllView;
import hudson.model.Hudson;

/**
 * An OSLC job selection dialog based off of {@link AllView}, except without the
 * banner and sidebar.
 *
 * @author Samuel Padgett <spadgett@us.ibm.com>
 */
public class BaseDialog extends AllView {
	private String baseURI;

	public BaseDialog(String baseURI, String title) {
	    super(title, Hudson.getInstance());
		this.baseURI = baseURI;
    }

	/**
	 * Get the base URI. (It is difficult to calculate from Jelly scripts.)
	 *
	 * @return the abosulte URI
	 */
	public String getBaseURI() {
		return baseURI;
	}
}

