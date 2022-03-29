// Copyright (c) 2021 Red Hat, Inc.
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package controllers

import (
	"context"
	"fmt"
	"net/http"
	"strings"

	"github.com/redhat-appstudio/service-provider-integration-operator/api/v1beta1"
	"github.com/redhat-appstudio/service-provider-integration-operator/pkg/spi-shared/config"
	"github.com/redhat-appstudio/service-provider-integration-operator/pkg/spi-shared/oauthstate"
	"github.com/redhat-appstudio/service-provider-integration-operator/pkg/spi-shared/tokenstorage"
	"go.uber.org/zap"
	"golang.org/x/oauth2"
	"k8s.io/apiserver/pkg/authentication/authenticator"
	"k8s.io/apiserver/pkg/authentication/user"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// commonController is the implementation of the Controller interface that assumes typical OAuth flow.
type commonController struct {
	Config               config.ServiceProviderConfiguration
	JwtSigningSecret     []byte
	Authenticator        authenticator.Request
	K8sClient            client.Client
	TokenStorage         tokenstorage.TokenStorage
	Endpoint             oauth2.Endpoint
	BaseUrl              string
}

// newOAuth2Config returns a new instance of the oauth2.Config struct with the clientId, clientSecret and redirect URL
// specific to this controller.
func (c *commonController) newOAuth2Config() oauth2.Config {
	return oauth2.Config{
		ClientID:     c.Config.ClientId,
		ClientSecret: c.Config.ClientSecret,
		RedirectURL:  c.redirectUrl(),
	}
}

// redirectUrl constructs the URL to the callback endpoint so that it can be handled by this controller.
func (c *commonController) redirectUrl() string {
	return strings.TrimSuffix(c.BaseUrl, "/") + "/" + strings.ToLower(string(c.Config.ServiceProviderType)) + "/callback"
}

func (c commonController) Authenticate(w http.ResponseWriter, r *http.Request) {
	stateString := r.FormValue("state")
	codec, err := oauthstate.NewCodec(c.JwtSigningSecret)
	if err != nil {
		logAndWriteResponse(w, http.StatusInternalServerError, "failed to instantiate OAuth stateString codec", err)
		return
	}

	state, err := codec.ParseAnonymous(stateString)
	if err != nil {
		logAndWriteResponse(w, http.StatusBadRequest, "failed to decode the OAuth state", err)
		return
	}

	// TODO we're not checking the user authorization as of now. We need to review the whole security model first.
	identity := user.DefaultInfo{}
	authorizationHeader := ""
	//
	//// needs to be obtained before AuthenticateRequest call that removes it from the request!
	//authorizationHeader = r.Header.Get("Authorization")
	//
	//authResponse, result, err := c.Authenticator.AuthenticateRequest(r)
	//if err != nil {
	//	logAndWriteResponse(w, http.StatusUnauthorized, "failed to authenticate the request in Kubernetes", err)
	//	return
	//}
	//if !result {
	//	w.WriteHeader(http.StatusUnauthorized)
	//	_, _ = fmt.Fprintf(w, "failed to authenticate the request in Kubernetes")
	//	return
	//}
	//
	//identity = user.DefaultInfo{
	//	Name:   authResponse.User.GetName(),
	//	UID:    authResponse.User.GetUID(),
	//	Groups: authResponse.User.GetGroups(),
	//	Extra:  authResponse.User.GetExtra(),
	//}

	authedState := oauthstate.AuthenticatedOAuthState{
		AnonymousOAuthState: state,
		KubernetesIdentity:  identity,
		AuthorizationHeader: authorizationHeader,
	}

	oauthCfg := c.newOAuth2Config()
	oauthCfg.Endpoint = c.Endpoint
	oauthCfg.Scopes = authedState.Scopes

	stateString, err = codec.EncodeAuthenticated(&authedState)
	if err != nil {
		logAndWriteResponse(w, http.StatusInternalServerError, "failed to encode OAuth state", err)
	}

	url := oauthCfg.AuthCodeURL(stateString)

	http.Redirect(w, r, url, http.StatusFound)
}

func (c commonController) Callback(ctx context.Context, w http.ResponseWriter, r *http.Request) {

	token, state, result, err := c.finishOAuthExchange(ctx, r, c.Endpoint)
	if err != nil {
		logAndWriteResponse(w, http.StatusBadRequest, "error in Service Provider token exchange", err)
		return
	}

	if result == oauthFinishK8sAuthRequired {
		logAndWriteResponse(w, http.StatusUnauthorized, "could not authenticate to Kubernetes", err)
		return
	}

	err = c.syncTokenData(ctx, token, state)
	if err != nil {
		logAndWriteResponse(w, http.StatusInternalServerError, "failed to store token data to cluster", err)
		return
	}

	redirectLocation := r.FormValue("redirect_after_login")
	if redirectLocation == "" {
		redirectLocation = strings.TrimSuffix(c.BaseUrl, "/") + "/" + "callback_success"
	}
	http.Redirect(w, r, redirectLocation, http.StatusFound)
}

// finishOAuthExchange implements the bulk of the Callback function. It returns the token, if obtained, the decoded
// state from the oauth flow, if available, and the result of the authentication.
func (c commonController) finishOAuthExchange(ctx context.Context, r *http.Request, endpoint oauth2.Endpoint) (*oauth2.Token, *oauthstate.AuthenticatedOAuthState, oauthFinishResult, error) {
	// TODO support the implicit flow here, too?

	// check that the state is correct
	stateString := r.FormValue("state")
	codec, err := oauthstate.NewCodec(c.JwtSigningSecret)
	if err != nil {
		return nil, nil, oauthFinishError, err
	}

	state, err := codec.ParseAuthenticated(stateString)
	if err != nil {
		return nil, nil, oauthFinishError, err
	}

	// TODO we're not checking the user authorization as of now. We need to review the whole security model first.
	//r.Header.Set("Authorization", state.AuthorizationHeader)
	//
	//authResponse, _, err := c.Authenticator.AuthenticateRequest(r)
	//if err != nil {
	//	return nil, nil, oauthFinishError, err
	//}
	//
	//if state.KubernetesIdentity.Name != authResponse.User.GetName() ||
	//	!equalMapOfSlicesUnordered(state.KubernetesIdentity.Extra, authResponse.User.GetExtra()) ||
	//	state.KubernetesIdentity.UID != authResponse.User.GetUID() ||
	//	!equalSliceUnOrdered(state.KubernetesIdentity.Groups, authResponse.User.GetGroups()) {
	//
	//	return nil, nil, oauthFinishK8sAuthRequired, fmt.Errorf("kubernetes identity doesn't match after completing the OAuth flow")
	//}

	// the state is ok, let's retrieve the token from the service provider
	oauthCfg := c.newOAuth2Config()
	oauthCfg.Endpoint = endpoint

	code := r.FormValue("code")

	// adding scopes to code exchange request is little out of spec, but quay wants them,
	// while other providers will just ignore this parameter
	scopeOption := oauth2.SetAuthURLParam("scope", r.FormValue("scope"))
	token, err := oauthCfg.Exchange(ctx, code, scopeOption)
	if err != nil {
		return nil, nil, oauthFinishError, err
	}
	return token, &state, oauthFinishAuthenticated, nil
}

// syncTokenData stores the data of the token to the configured TokenStorage.
func (c commonController) syncTokenData(ctx context.Context, token *oauth2.Token, state *oauthstate.AuthenticatedOAuthState) error {
	// TODO if we decide to use the kubernetes identity of the user that initiated the OAuth flow, we need to use a
	// different kubernetes client to do the creation/update here...
	accessToken := &v1beta1.SPIAccessToken{}
	if err := c.K8sClient.Get(ctx, client.ObjectKey{Name: state.TokenName, Namespace: state.TokenNamespace}, accessToken); err != nil {
		return err
	}

	apiToken := v1beta1.Token{
		AccessToken:  token.AccessToken,
		TokenType:    token.TokenType,
		RefreshToken: token.RefreshToken,
		Expiry:       uint64(token.Expiry.Unix()),
	}

	return c.TokenStorage.Store(ctx, accessToken, &apiToken)
}

func logAndWriteResponse(w http.ResponseWriter, status int, msg string, err error) {
	w.WriteHeader(status)
	_, _ = fmt.Fprintf(w, msg+": ", err.Error())
	zap.L().Error(msg, zap.Error(err))
}

// TODO we're not checking the user authorization as of now. We need to review the whole security model first.
// These functions were only needed in the authorization checking code.
//func equalMapOfSlicesUnordered(a map[string][]string, b map[string][]string) bool {
//	for k, v := range a {
//		if !equalSliceUnOrdered(v, b[k]) {
//			return false
//		}
//	}
//
//	return true
//}
//
//func equalSliceUnOrdered(as []string, bs []string) bool {
//	if len(as) != len(bs) {
//		return false
//	}
//
//as:
//	for _, a := range as {
//		for _, b := range bs {
//			if a == b {
//				continue as
//			}
//		}
//
//		return false
//	}
//
//	return true
//}

// getOauth2HttpClient tries to find the HTTP client used by the OAuth2 library in the context.
// This is useful mainly in tests where we can use mocked responses even for our own calls.
func getOauth2HttpClient(ctx context.Context) *http.Client {
	cl, _ := ctx.Value(oauth2.HTTPClient).(*http.Client)
	if cl != nil {
		return cl
	}

	return &http.Client{}
}
