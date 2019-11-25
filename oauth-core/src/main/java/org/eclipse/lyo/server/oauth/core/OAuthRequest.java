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
package org.eclipse.lyo.server.oauth.core;

import java.io.IOException;
import java.net.URISyntaxException;
import java.util.Collections;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.Map;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletRequestWrapper;
import javax.ws.rs.core.MultivaluedMap;

import net.oauth.OAuth;
import net.oauth.OAuthAccessor;
import net.oauth.OAuthException;
import net.oauth.OAuthMessage;
import net.oauth.OAuthProblemException;
import net.oauth.OAuthValidator;
import net.oauth.server.OAuthServlet;

import org.eclipse.lyo.server.oauth.core.consumer.LyoOAuthConsumer;

/**
 * Validates that a request is authorized. The request must contain a valid
 * access token and pass {@link OAuthValidator} tests. To change the validator
 * used, call {@link OAuthConfiguration#setValidator(OAuthValidator)}.
 * 
 * <p>
 * Usage:
 * 
 * <pre>
 * try {
 * 	OAuthRequest request = new OAuthRequest(httpRequest);
 * 	request.validate();
 * } catch (OAuthException e) {
 * 	// Request failed validation. Send an unauthorized response.
 * 	OAuthServlet.handleException(httpResponse, e, OAuthConfiguration
 * 			.getInstance().getRealm());
 * }
 * </pre>
 * 
 * @author Samuel Padgett
 */
public class OAuthRequest {
	private HttpServletRequest httpRequest;
	private OAuthMessage message;
	private OAuthAccessor accessor;
	
	public OAuthRequest(HttpServletRequest request)
			throws OAuthException, IOException {
		this.httpRequest = request;
		this.message = OAuthServlet.getMessage(httpRequest, null);

		LyoOAuthConsumer consumer = OAuthConfiguration.getInstance()
				.getConsumerStore().getConsumer(message);
		if (consumer == null) {
			throw new OAuthProblemException(
					OAuth.Problems.CONSUMER_KEY_REJECTED);
		}

		this.accessor = new OAuthAccessor(consumer);

		// Fill in the token secret if it's there.
		String token = this.message.getToken();
		if (token != null) {
			this.accessor.tokenSecret = OAuthConfiguration.getInstance()
					.getJaxTokenStrategy().getTokenSecret(token);
		}
	}

	public static class OAuthServletRequestWrapper extends HttpServletRequestWrapper {

		private final Map<String, String[]> formParams;

		/**
		 * Constructs a request object wrapping the given request.
		 *
		 * @param request
		 * @throws IllegalArgumentException if the request is null
		 */
		public OAuthServletRequestWrapper(HttpServletRequest request,
										  MultivaluedMap<String, String> formParams) {
			super(request);
			this.formParams = aggregateMultimap(formParams);
		}

		private Map<String, String[]> aggregateMultimap(MultivaluedMap<String, String> multimap) {
			HashMap<String, String[]> map = new HashMap<>();
			multimap.forEach((key, strings) -> map.put(key, strings.toArray(new String[0])));
			return map;
		}

		@Override
		public String getParameter(String name) {
			String[] values = formParams.get(name);
			if (values == null || values.length == 0) {
				return null;
			}
			return values[0];
		}

		@Override
		public Map<String, String[]> getParameterMap() {
			return formParams;
		}

		@Override
		public Enumeration<String> getParameterNames() {
			return Collections.enumeration(formParams.keySet());
		}

		@Override
		public String[] getParameterValues(String name) {
			return formParams.get(name);
		}
	}

	public HttpServletRequest getHttpRequest() {
		return httpRequest;
	}

	private void setHttpRequest(HttpServletRequest httpRequest) {
		this.httpRequest = httpRequest;
	}

	public OAuthMessage getMessage() {
		return message;
	}

	public OAuthAccessor getAccessor() {
		return accessor;
	}

	public LyoOAuthConsumer getConsumer() {
		return (LyoOAuthConsumer) accessor.consumer;
	}

	/**
	 * Validates that the request is authorized and throws an OAuth exception if
	 * not. The request must contain a valid access token and pass
	 * {@link OAuthValidator#validateMessage(OAuthMessage, OAuthAccessor)}
	 * checks using the validator set in the {@link OAuthConfiguration}.
	 * <p>
	 * If the request fails validation, you can use
	 * {@link OAuthServlet#handleException(javax.servlet.http.HttpServletResponse, Exception, String)}
	 * to send an unauthorized response.
	 * 
	 * @throws OAuthException
	 *             if the request fails validation
	 */
	public void validate() throws OAuthException, IOException, ServletException {
		try {
			OAuthConfiguration config = OAuthConfiguration.getInstance();
			config.getValidator().validateMessage(message, accessor);
			config.getJaxTokenStrategy().validateAccessToken(this);
		} catch (URISyntaxException e) {
			throw new ServletException(e);
		}
	}
}
