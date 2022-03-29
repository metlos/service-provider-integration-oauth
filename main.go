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

package main

import (
	"context"
	"fmt"
	"html/template"
	"net/http"
	"os"
	"strings"

	"github.com/alexflint/go-arg"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"

	"github.com/redhat-appstudio/service-provider-integration-oauth/controllers"
	"github.com/redhat-appstudio/service-provider-integration-operator/pkg/spi-shared/config"

	"github.com/gorilla/mux"
	"go.uber.org/zap"
)

type cliArgs struct {
	ConfigFile string `arg:"-c, --config-file, env" default:"/etc/spi/config.yaml" help:"The location of the configuration file"`
	Port       int    `arg:"-p, --port, env" default:"8000" help:"The port to listen on"`
	DevMode    bool   `arg:"-d, --dev-mode, env" default:"false" help:"use dev-mode logging"`
	KubeConfig string `arg:"-k, --kubeconfig, env" default:"" help:""`
}

type viewData struct {
	Title   string
	Message string
}

func OkHandler(w http.ResponseWriter, _ *http.Request) {
	w.WriteHeader(http.StatusOK)
}

func CallbackSuccessHandler(w http.ResponseWriter, r *http.Request) {
	http.ServeFile(w, r, "static/callback_success.html")
}

func CallbackErrorHandler(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	errorMsg := q.Get("error")
	errorDescription := q.Get("error_description")
	data := viewData{
		Title:   errorMsg,
		Message: errorDescription,
	}
	tmpl, _ := template.ParseFiles("static/callback_error.html")

	err := tmpl.Execute(w, data)
	if err == nil {
		w.WriteHeader(http.StatusOK)
	} else {
		zap.L().Error("failed to process template: %s", zap.Error(err))
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(fmt.Sprintf("Error response returned to OAuth callback: %s. Message: %s ", errorMsg, errorDescription)))
	}

}

func main() {
	args := cliArgs{}
	arg.MustParse(&args)

	var loggerConfig zap.Config
	if args.DevMode {
		loggerConfig = zap.NewDevelopmentConfig()
	} else {
		loggerConfig = zap.NewProductionConfig()
	}
	loggerConfig.OutputPaths = []string{"stdout"}
	loggerConfig.ErrorOutputPaths = []string{"stdout"}
	logger, err := loggerConfig.Build()
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to initialize logging: %s", err.Error())
		os.Exit(1)
	}
	defer logger.Sync()
	undo := zap.ReplaceGlobals(logger)
	defer undo()

	cfg, err := config.LoadFrom(args.ConfigFile)
	if err != nil {
		zap.L().Error("failed to initialize the configuration", zap.Error(err))
		os.Exit(1)
	}

	kubeConfig, err := kubernetesConfig(args.KubeConfig)
	if err != nil {
		zap.L().Error("failed to create kubernetes configuration", zap.Error(err))
		os.Exit(1)
	}

	start(cfg, args.Port, kubeConfig)
}

func start(cfg config.Configuration, port int, kubeConfig *rest.Config) {
	router := mux.NewRouter()

	//static routes first
	router.HandleFunc("/health", OkHandler).Methods("GET")
	router.HandleFunc("/ready", OkHandler).Methods("GET")
	router.HandleFunc("/callback_success", CallbackSuccessHandler).Methods("GET")
	router.NewRoute().Path("/{type}/callback").Queries("error", "", "error_description", "").HandlerFunc(CallbackErrorHandler)

	for _, sp := range cfg.ServiceProviders {
		controller, err := controllers.FromConfiguration(cfg, sp, kubeConfig)
		if err != nil {
			zap.L().Error("failed to initialize controller: %s", zap.Error(err))
		}

		prefix := strings.ToLower(string(sp.ServiceProviderType))

		router.Handle(fmt.Sprintf("/%s/authenticate", prefix), http.HandlerFunc(controller.Authenticate)).Methods("GET")
		router.Handle(fmt.Sprintf("/%s/callback", prefix), http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			controller.Callback(context.Background(), w, r)
		})).Methods("GET")
	}

	err := http.ListenAndServe(fmt.Sprintf(":%d", port), router)
	if err != nil {
		zap.L().Error("failed to start the HTTP server", zap.Error(err))
	}
}

func kubernetesConfig(kubeConfig string) (*rest.Config, error) {
	if kubeConfig == "" {
		return rest.InClusterConfig()
	} else {
		return clientcmd.BuildConfigFromFlags("", kubeConfig)
	}
}
