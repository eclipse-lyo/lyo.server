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

import net.oauth.OAuth;
import net.oauth.OAuthAccessor;
import net.oauth.OAuthMessage;
import net.oauth.OAuthProblemException;
import org.eclipse.lyo.server.oauth.core.OAuthRequest;

import javax.servlet.http.HttpServletRequest;
import java.io.IOException;
import java.util.Map;

public class JaxTokenStrategy implements IJaxTokenStrategy {
    // key is request token string, value is RequestTokenData
    private final Map<String, RequestTokenData> requestTokens;

    // key is access token, value is consumer key
    private final Map<String, String> accessTokens;

    // key is token, value is token secret
    private final Map<String, String> tokenSecrets;

    public JaxTokenStrategy(int requestTokenMaxCount, int accessTokenMaxCount) {
        requestTokens = new LRUCache<>(requestTokenMaxCount);
        accessTokens = new LRUCache<>(accessTokenMaxCount);
        tokenSecrets = new LRUCache<>(requestTokenMaxCount + accessTokenMaxCount);
    }

    @Override
    public void generateRequestToken(OAuthRequest oAuthRequest) throws IOException {
        OAuthAccessor accessor = oAuthRequest.getAccessor();
        accessor.requestToken = StrategyUtil.generateTokenString();
        accessor.tokenSecret = StrategyUtil.generateTokenString();
        String callback = oAuthRequest.getMessage()
                .getParameter(OAuth.OAUTH_CALLBACK);
        synchronized (requestTokens) {
            requestTokens.put(accessor.requestToken, new RequestTokenData(
                    accessor.consumer.consumerKey, callback));
        }
        synchronized (tokenSecrets) {
            tokenSecrets.put(accessor.requestToken, accessor.tokenSecret);
        }
    }

    @Override
    public void validateVerificationCode(OAuthRequest oAuthRequest) throws IOException, OAuthProblemException {
        String verificationCode = oAuthRequest.getMessage().getParameter(
                OAuth.OAUTH_VERIFIER);
        if (verificationCode == null) {
            throw new OAuthProblemException(
                    OAuth.Problems.OAUTH_PARAMETERS_ABSENT);
        }

        RequestTokenData tokenData = getRequestTokenData(oAuthRequest);
        if (!verificationCode.equals(tokenData.getVerificationCode())) {
            throw new OAuthProblemException(
                    OAuth.Problems.OAUTH_PARAMETERS_REJECTED);
        }

    }

    @Override
    public void generateAccessToken(OAuthRequest oAuthRequest) throws OAuthProblemException, IOException {
        // Remove the old request token.
        OAuthAccessor accessor = oAuthRequest.getAccessor();
        String requestToken = oAuthRequest.getMessage().getToken();
        synchronized (requestTokens) {
            if (!isRequestTokenAuthorized(requestToken)) {
                throw new OAuthProblemException(
                        OAuth.Problems.ADDITIONAL_AUTHORIZATION_REQUIRED);
            }

            requestTokens.remove(requestToken);
        }

        // Generate a new access token.
        accessor.accessToken = StrategyUtil.generateTokenString();
        synchronized (accessTokens) {
            accessTokens.put(accessor.accessToken,
                    accessor.consumer.consumerKey);
        }

        // Remove the old token secret and create a new one for this access
        // token.
        accessor.tokenSecret = StrategyUtil.generateTokenString();
        synchronized (tokenSecrets) {
            tokenSecrets.remove(requestToken);
            tokenSecrets.put(accessor.accessToken, accessor.tokenSecret);
        }

        accessor.requestToken = null;

    }

    private boolean isRequestTokenAuthorized(String requestToken) throws OAuthProblemException {
        return getRequestTokenData(requestToken).isAuthorized();
    }


    @Override
    public String validateRequestToken(OAuthMessage message) throws IOException, OAuthProblemException {
        return getRequestTokenData(message.getToken()).getConsumerKey();
    }

    @Override
    public String getCallback(String requestToken) throws OAuthProblemException {
        return getRequestTokenData(requestToken).getCallback();
    }

    @Override
    public void markRequestTokenAuthorized(HttpServletRequest httpRequest, String requestToken)
            throws OAuthProblemException {
        getRequestTokenData(requestToken).setAuthorized(true);
    }

    @Override
    public String generateVerificationCode(String requestToken) throws OAuthProblemException {
        String verificationCode = StrategyUtil.generateTokenString();
        getRequestTokenData(requestToken).setVerificationCode(verificationCode);

        return verificationCode;
    }

    @Override
    public String getTokenSecret(String token) throws OAuthProblemException {
        synchronized (tokenSecrets) {
            String tokenSecret = tokenSecrets.get(token);
            if (tokenSecret == null) {
                // It's possible the token secret was purged from the LRU cache,
                // or the token is just not recognized. Either way, we can
                // consider the token rejected.
                throw new OAuthProblemException(OAuth.Problems.TOKEN_REJECTED);
            }
            return tokenSecret;
        }
    }

    @Override
    public void validateAccessToken(OAuthRequest oAuthRequest) throws IOException, OAuthProblemException {
        synchronized (accessTokens) {
            String actualValue = accessTokens.get(oAuthRequest.getMessage().getToken());
            if (!oAuthRequest.getConsumer().consumerKey.equals(actualValue)) {
                throw new OAuthProblemException(OAuth.Problems.TOKEN_REJECTED);
            }
        }
    }

    /**
     * Gets the request token data from this OAuth request.
     *
     * @param oAuthRequest
     *            the OAuth request
     * @return the request token data
     * @throws OAuthProblemException
     *             if the request token is invalid
     * @throws IOException
     *             on reading OAuth parameters
     */
    protected RequestTokenData getRequestTokenData(OAuthRequest oAuthRequest)
            throws OAuthProblemException, IOException {
        return getRequestTokenData(oAuthRequest.getMessage().getToken());
    }

    /**
     * Gets the request token data for this request token.
     *
     * @param requestToken
     *            the request token string
     * @return the request token data
     * @throws OAuthProblemException
     *             if the request token is invalid
     */
    protected RequestTokenData getRequestTokenData(String requestToken)
            throws OAuthProblemException {
        synchronized (requestTokens) {
            RequestTokenData tokenData = requestTokens.get(requestToken);
            if (tokenData == null) {
                throw new OAuthProblemException(OAuth.Problems.TOKEN_REJECTED);
            }
            return tokenData;
        }
    }
}
