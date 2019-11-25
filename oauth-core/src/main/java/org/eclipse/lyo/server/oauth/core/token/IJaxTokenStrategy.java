/*
 * Copyright (c) 2019 KTH Royal Institute of Technology and others
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

import net.oauth.OAuthMessage;
import net.oauth.OAuthProblemException;
import org.eclipse.lyo.server.oauth.core.OAuthRequest;

import javax.servlet.http.HttpServletRequest;
import java.io.IOException;

public interface IJaxTokenStrategy {
    void generateRequestToken(OAuthRequest oAuthRequest) throws IOException;
    void validateVerificationCode(OAuthRequest oAuthRequest) throws IOException, OAuthProblemException;
    void generateAccessToken(OAuthRequest oAuthRequest) throws OAuthProblemException, IOException;

    String validateRequestToken(OAuthMessage message) throws IOException, OAuthProblemException;
    String getCallback(String requestToken) throws OAuthProblemException;
    void markRequestTokenAuthorized(HttpServletRequest httpRequest, String requestToken) throws OAuthProblemException;
    String generateVerificationCode(String requestToken) throws OAuthProblemException;
    String getTokenSecret(String secretToken) throws OAuthProblemException;

    void validateAccessToken(OAuthRequest oAuthRequest) throws IOException, OAuthProblemException;
}
