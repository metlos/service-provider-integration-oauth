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
	"bytes"
	"context"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"time"

	"github.com/alexedwards/scs"
	"github.com/alexedwards/scs/stores/memstore"

	"github.com/redhat-appstudio/service-provider-integration-operator/api/v1beta1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/redhat-appstudio/service-provider-integration-operator/pkg/spi-shared/oauthstate"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	"github.com/go-jose/go-jose/v3/json"
	"github.com/redhat-appstudio/service-provider-integration-oauth/authentication"
	"github.com/redhat-appstudio/service-provider-integration-operator/pkg/spi-shared/config"
	"golang.org/x/oauth2"
)

var _ = Describe("Controller", func() {

	prepareAnonymousState := func() string {
		codec, err := oauthstate.NewCodec([]byte("secret"))
		Expect(err).NotTo(HaveOccurred())

		ret, err := codec.Encode(&oauthstate.AnonymousOAuthState{
			TokenName:           "mytoken",
			TokenNamespace:      IT.Namespace,
			IssuedAt:            time.Now().Unix(),
			Scopes:              []string{"a", "b"},
			ServiceProviderType: "My_Special_SP",
			ServiceProviderUrl:  "https://special.sp",
		})
		Expect(err).NotTo(HaveOccurred())
		return ret
	}

	grabK8sToken := func() string {
		var secrets *corev1.SecretList

		Eventually(func(g Gomega) {
			var err error
			secrets, err = IT.Clientset.CoreV1().Secrets(IT.Namespace).List(context.TODO(), metav1.ListOptions{})
			g.Expect(err).NotTo(HaveOccurred())
			g.Expect(secrets.Items).NotTo(BeEmpty())
		}).Should(Succeed())

		for _, s := range secrets.Items {
			if s.Annotations["kubernetes.io/service-account.name"] == "default" {
				return string(s.Data["token"])
			}
		}

		Fail("Could not find the token of the default service account in the test namespace", 1)
		return ""
	}

	prepareController := func() *commonController {
		auth, err := authentication.New(IT.Clientset, []string{})
		Expect(err).NotTo(HaveOccurred())

		return &commonController{
			Config: config.ServiceProviderConfiguration{
				ClientId:            "clientId",
				ClientSecret:        "clientSecret",
				ServiceProviderType: config.ServiceProviderTypeGitHub,
			},
			JwtSigningSecret: []byte("secret"),
			Authenticator:    auth,
			K8sClient:        IT.Client,
			TokenStorage:     IT.TokenStorage,
			Endpoint: oauth2.Endpoint{
				AuthURL:   "https://special.sp/login",
				TokenURL:  "https://special.sp/toekn",
				AuthStyle: oauth2.AuthStyleAutoDetect,
			},
			BaseUrl:        "https://spi.on.my.machine",
			SessionManager: scs.NewManager(memstore.New(1000000 * time.Hour)),
		}
	}

	authenticateFlow := func() (*commonController, *httptest.ResponseRecorder) {
		token := grabK8sToken()

		// This is the setup for the HTTP call to /github/authenticate
		req := httptest.NewRequest("GET", fmt.Sprintf("/?state=%s&scopes=a,b", prepareAnonymousState()), nil)
		req.Header.Set("Authorization", "Bearer "+token)
		res := httptest.NewRecorder()

		g := prepareController()

		g.Authenticate(res, req)

		return g, res
	}

	It("redirects to SP OAuth URL with state and scopes", func() {
		_, res := authenticateFlow()

		Expect(res.Code).To(Equal(http.StatusFound))

		redirect, err := url.Parse(res.Header().Get("Location"))
		Expect(err).NotTo(HaveOccurred())
		Expect(redirect.Scheme).To(Equal("https"))
		Expect(redirect.Host).To(Equal("special.sp"))
		Expect(redirect.Path).To(Equal("/login"))
		Expect(redirect.Query().Get("client_id")).To(Equal("clientId"))
		Expect(redirect.Query().Get("redirect_uri")).To(Equal("https://spi.on.my.machine/github/callback"))
		Expect(redirect.Query().Get("response_type")).To(Equal("code"))
		Expect(redirect.Query().Get("state")).NotTo(BeEmpty())
		Expect(redirect.Query().Get("scope")).To(Equal("a b"))
		Expect(res.Result().Cookies()).NotTo(BeEmpty())
	})

	When("OAuth initiated", func() {
		BeforeEach(func() {
			Expect(IT.Client.Create(IT.Context, &v1beta1.SPIAccessToken{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "mytoken",
					Namespace: IT.Namespace,
				},
				Spec: v1beta1.SPIAccessTokenSpec{
					ServiceProviderUrl: "https://special.sp",
				},
			})).To(Succeed())

			t := &v1beta1.SPIAccessToken{}
			Eventually(func() error {
				return IT.Client.Get(IT.Context, client.ObjectKey{Name: "mytoken", Namespace: IT.Namespace}, t)
			}).Should(Succeed())
		})

		AfterEach(func() {
			t := &v1beta1.SPIAccessToken{}
			Expect(IT.Client.Get(IT.Context, client.ObjectKey{Name: "mytoken", Namespace: IT.Namespace}, t)).To(Succeed())
			Expect(IT.Client.Delete(IT.Context, t)).To(Succeed())
			Eventually(func() error {
				return IT.Client.Get(IT.Context, client.ObjectKey{Name: "mytoken", Namespace: IT.Namespace}, t)
			}).ShouldNot(Succeed())
		})

		It("exchanges the code for token", func() {
			g, res := authenticateFlow()

			// grab the encoded state
			redirect, err := url.Parse(res.Header().Get("Location"))
			Expect(err).NotTo(HaveOccurred())
			state := redirect.Query().Get("state")

			// simulate github redirecting back to our callback endpoint...
			req := httptest.NewRequest("GET", fmt.Sprintf("/?state=%s&code=123", state), nil)
			req.Header.Set("Cookie", res.Result().Cookies()[0].String())
			res = httptest.NewRecorder()

			// The callback handler will be reaching out to github to exchange the code for the token.. let's fake that
			// response...
			bakedResponse, _ := json.Marshal(oauth2.Token{
				AccessToken:  "token",
				TokenType:    "jwt",
				RefreshToken: "refresh",
				Expiry:       time.Now(),
			})
			serviceProviderReached := false
			ctx := context.WithValue(context.TODO(), oauth2.HTTPClient, &http.Client{
				Transport: fakeRoundTrip(func(r *http.Request) (*http.Response, error) {
					if strings.HasPrefix(r.URL.String(), "https://special.sp") {
						serviceProviderReached = true
						return &http.Response{
							StatusCode: 200,
							Header:     http.Header{},
							Body:       ioutil.NopCloser(bytes.NewBuffer(bakedResponse)),
							Request:    r,
						}, nil
					}

					return nil, fmt.Errorf("unexpected request to: %s", r.URL.String())
				}),
			})

			g.Callback(ctx, res, req)

			Expect(res.Code).To(Equal(http.StatusFound))
			Expect(serviceProviderReached).To(BeTrue())
		})

		It("redirects to specified url", func() {
			g, res := authenticateFlow()

			// grab the encoded state
			redirect, err := url.Parse(res.Header().Get("Location"))
			Expect(err).NotTo(HaveOccurred())
			state := redirect.Query().Get("state")

			// simulate github redirecting back to our callback endpoint...
			req := httptest.NewRequest("GET", fmt.Sprintf("/?state=%s&code=123&redirect_after_login=https://redirect.to?foo=bar", state), nil)
			req.Header.Set("Cookie", res.Result().Cookies()[0].String())
			res = httptest.NewRecorder()

			// The callback handler will be reaching out to github to exchange the code for the token.. let's fake that
			// response...
			bakedResponse, _ := json.Marshal(oauth2.Token{
				AccessToken:  "token",
				TokenType:    "jwt",
				RefreshToken: "refresh",
				Expiry:       time.Now(),
			})
			ctx := context.WithValue(context.TODO(), oauth2.HTTPClient, &http.Client{
				Transport: fakeRoundTrip(func(r *http.Request) (*http.Response, error) {
					if strings.HasPrefix(r.URL.String(), "https://special.sp") {
						return &http.Response{
							StatusCode: 200,
							Header:     http.Header{},
							Body:       ioutil.NopCloser(bytes.NewBuffer(bakedResponse)),
							Request:    r,
						}, nil
					}

					return nil, fmt.Errorf("unexpected request to: %s", r.URL.String())
				}),
			})

			g.Callback(ctx, res, req)

			Expect(res.Code).To(Equal(http.StatusFound))
			Expect(res.Result().Header.Get("Location")).To(Equal("https://redirect.to?foo=bar"))
		})
	})
})
