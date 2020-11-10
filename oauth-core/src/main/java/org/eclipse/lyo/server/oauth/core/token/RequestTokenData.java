/*
 * Copyright (c) 2012-2019 IBM Corporation and others
 *
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * and Eclipse Distribution License v. 1.0 which accompanies this distribution.
 *
 * The Eclipse Public License is available at http://www.eclipse.org/legal/epl-v10.html
 * and the Eclipse Distribution License is available at
 * http://www.eclipse.org/org/documents/edl-v10.php.
 */
package org.eclipse.lyo.server.oauth.core.token;

/**
 * Holds information associated with a request token such as the callback
 * URL and OAuth verification code.
 *
 * @author Samuel Padgett
 */
class RequestTokenData {
    private String consumerKey;
    private boolean authorized;
    private String callback;
    private String verificationCode;

    public RequestTokenData(String consumerKey) {
        this.consumerKey = consumerKey;
        this.authorized = false;
        this.callback = null;
    }

    public RequestTokenData(String consumerKey, String callback) {
        this.consumerKey = consumerKey;
        this.authorized = false;
        this.callback = callback;
    }

    public String getConsumerKey() {
        return consumerKey;
    }

    public void setConsumerKey(String consumerKey) {
        this.consumerKey = consumerKey;
    }

    public boolean isAuthorized() {
        return authorized;
    }

    public void setAuthorized(boolean authorized) {
        this.authorized = authorized;
    }

    public String getCallback() {
        return callback;
    }

    public void setCallback(String callback) {
        this.callback = callback;
    }

    public String getVerificationCode() {
        return verificationCode;
    }

    public void setVerificationCode(String verificationCode) {
        this.verificationCode = verificationCode;
    }
}
