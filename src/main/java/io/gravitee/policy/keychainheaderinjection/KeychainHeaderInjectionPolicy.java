/**
 * Copyright (C) 2015 The Gravitee team (http://gravitee.io)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *         http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package io.gravitee.policy.keychainheaderinjection;

import io.gravitee.common.http.GraviteeHttpHeader;
import io.gravitee.common.http.HttpStatusCode;
import io.gravitee.gateway.api.ExecutionContext;
import io.gravitee.gateway.api.Request;
import io.gravitee.gateway.api.Response;
import io.gravitee.policy.api.PolicyChain;
import io.gravitee.policy.api.PolicyResult;
import io.gravitee.policy.api.annotations.OnRequest;
import io.gravitee.policy.keychainheaderinjection.configuration.KeychainHeaderInjectionPolicyConfiguration;
import io.gravitee.repository.exceptions.TechnicalException;
import io.gravitee.repository.management.api.ApiKeyRepository;
import io.gravitee.repository.management.model.ApiKey;
import org.json.JSONArray;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.core.env.Environment;

import java.util.Date;
import java.util.Optional;
import java.util.jar.JarException;

import org.json.JSONObject;
import org.json.JSONException;

/**
 * @author David BRASSELY (david.brassely at graviteesource.com)
 * @author GraviteeSource Team
 */
@SuppressWarnings("unused")
public class KeychainHeaderInjectionPolicy {

    private static final Logger LOGGER = LoggerFactory.getLogger(KeychainHeaderInjectionPolicy.class);

    static final String ATTR_AUTHORIZATION_KEY = "Authorization";
    static final String KEYCHAIN_STRING = "keychain";
    static final String USER_STRING = "user";
    static final String PASS_STRING = "pass";
    static final String METHOD_STRING = "method";
    static final String BASICAUTH = "basicauth";

    /**
     * Policy configuration
     */
    private final KeychainHeaderInjectionPolicyConfiguration keychainHeaderInjectionPolicyConfiguration;

    public KeychainHeaderInjectionPolicy(KeychainHeaderInjectionPolicyConfiguration keychainHeaderInjectionPolicyConfiguration) {
        this.keychainHeaderInjectionPolicyConfiguration = keychainHeaderInjectionPolicyConfiguration;
    }

    @OnRequest
    public void onRequest(Request request, Response response, ExecutionContext executionContext, PolicyChain policyChain) {
        String requestKeychain = lookForKeychain(executionContext, request);

        KeychainHeaderInjectionPolicy.LOGGER.warn(requestKeychain);

        if (requestKeychain == null || requestKeychain.isEmpty()) {
            policyChain.failWith(PolicyResult.failure(
                    HttpStatusCode.FORBIDDEN_403,
                    "Couldn't find keychain data inside context."));
            return;
        }

        try
        {
            JSONArray apiList = new JSONArray(requestKeychain);
            JSONObject apiData=null;
            for(int i=0;i<apiList.length();i++)
            {
                JSONObject elem = apiList.getJSONObject(i);
                if(elem.getString(METHOD_STRING).equals(BASICAUTH))
                    apiData = elem;
            }
            if(apiData==null) {
                policyChain.failWith(PolicyResult.failure(HttpStatusCode.NOT_IMPLEMENTED_501, "Method not supported yet. "));
                return;
            }
            String user = apiData.getString(USER_STRING);
            String pass = apiData.getString(PASS_STRING);
            String userPass = String.format("%s:%s", user, pass);
            String encodedHeader = java.util.Base64.getEncoder().encodeToString(userPass.getBytes());
            request.headers().add("Authorization", String.format("Basic %s", encodedHeader));
            //request.headers().remove("")
        }
        catch (JSONException e)
        {
            policyChain.failWith(PolicyResult.failure(HttpStatusCode.FORBIDDEN_403, e.getMessage()));
            return;
        }

        policyChain.doNext(request,response);
    }

    private String lookForKeychain(ExecutionContext executionContext, Request request) {

        Object attrib = executionContext.getAttribute(KEYCHAIN_STRING);
        String keychainResponse = null;

        if(attrib!=null)
            keychainResponse = (String)attrib;

        // clean auth request
        String authorization = request.headers().getFirst(ATTR_AUTHORIZATION_KEY);
        if(authorization != null)
            request.headers().remove(ATTR_AUTHORIZATION_KEY);

        return keychainResponse;
    }
}
