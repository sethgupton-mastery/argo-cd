package version

import (
	"context"

	"github.com/golang/protobuf/ptypes/empty"
	"github.com/google/go-jsonnet"

	log "github.com/sirupsen/logrus"

	"github.com/argoproj/argo-cd/v2/common"
	"github.com/argoproj/argo-cd/v2/pkg/apiclient/version"
	"github.com/argoproj/argo-cd/v2/server/settings"
	"github.com/argoproj/argo-cd/v2/util/helm"
	"github.com/argoproj/argo-cd/v2/util/kustomize"
	sessionmgr "github.com/argoproj/argo-cd/v2/util/session"
)

type Server struct {
	kustomizeVersion string
	helmVersion      string
	jsonnetVersion   string
	authenticator    settings.Authenticator
	disableAuth      func() (bool, error)
}

func NewServer(authenticator settings.Authenticator, disableAuth func() (bool, error)) *Server {
	return &Server{authenticator: authenticator, disableAuth: disableAuth}
}

// Version returns the version of the API server
func (s *Server) Version(ctx context.Context, _ *empty.Empty) (*version.VersionMessage, error) {
	log.Infof("!!! VERSION CALLED !!!")
	vers := common.GetVersion()
	disableAuth, err := s.disableAuth()
	if err != nil {
		return nil, err
	}

	if disableAuth {
		log.Infof("!!! Auth disabled !!!")
	}

	log.Infof("!!! Version - Pre Login check !!!")
	if !sessionmgr.LoggedIn(ctx) && !disableAuth {
		return &version.VersionMessage{Version: vers.Version}, nil
	}
	log.Infof("!!! Version - Post Login check !!!")

	if s.kustomizeVersion == "" {
		kustomizeVersion, err := kustomize.Version(true)
		if err == nil {
			s.kustomizeVersion = kustomizeVersion
		} else {
			s.kustomizeVersion = err.Error()
		}
	}
	log.Infof("!!! Version - Post kustomizeVersion check !!!")
	if s.helmVersion == "" {
		helmVersion, err := helm.Version(true)
		if err == nil {
			s.helmVersion = helmVersion
		} else {
			s.helmVersion = err.Error()
		}
	}
	log.Infof("!!! Version - Post helmVersion check !!!")
	s.jsonnetVersion = jsonnet.Version()
	log.Infof("!!! Version - Post jsonnetVersion check !!!")
	return &version.VersionMessage{
		Version:          vers.Version,
		BuildDate:        vers.BuildDate,
		GitCommit:        vers.GitCommit,
		GitTag:           vers.GitTag,
		GitTreeState:     vers.GitTreeState,
		GoVersion:        vers.GoVersion,
		Compiler:         vers.Compiler,
		Platform:         vers.Platform,
		KustomizeVersion: s.kustomizeVersion,
		HelmVersion:      s.helmVersion,
		JsonnetVersion:   s.jsonnetVersion,
		KubectlVersion:   vers.KubectlVersion,
		ExtraBuildInfo:   vers.ExtraBuildInfo,
	}, nil
}

// AuthFuncOverride allows the version to be returned without auth
func (s *Server) AuthFuncOverride(ctx context.Context, fullMethodName string) (context.Context, error) {
	log.Infof("!!! AuthFuncOverride CALLED !!!")
	if s.authenticator != nil {
		// this authenticates the user, but ignores any error, so that we have claims populated
		ctx, _ = s.authenticator.Authenticate(ctx)
	}
	return ctx, nil
}
