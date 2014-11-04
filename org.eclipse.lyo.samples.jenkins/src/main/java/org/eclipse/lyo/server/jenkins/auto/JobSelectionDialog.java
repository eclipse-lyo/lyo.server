/*******************************************************************************
 * Copyright (c) 2013, 2014 IBM Corporation.
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

/**
 * An OSLC job selection dialog based off of {@link AllView}, except without the
 * banner and sidebar.
 *
 * @author Samuel Padgett <spadgett@us.ibm.com>
 */
public class JobSelectionDialog extends BaseDialog {
	public JobSelectionDialog(String baseURI) {
	    super(baseURI, "Job Selection");
    }

	/*
	 * See /jenkins-oslc-auto/src/main/resources/org/eclipse/lyo/server/jenkins/auto/JobSelectionDialog/dialog.jelly
	 */
}
