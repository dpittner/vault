package ibmcloud

import (
	"context"
	"errors"
	"fmt"
	"net/http"

	"github.com/IBM/go-sdk-core/v5/core"

	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/vault/api"
	"github.com/hashicorp/vault/command/agent/auth"
)

const (
	typeVPC       = "vpc"
	typeContainer = "container"
)

type ibmcloudMethod struct {
	logger        hclog.Logger
	credsFound    chan struct{}
	authenticator tokenProvider
	lastToken     string
	mountPath     string

	// common members
	iamProfileId string
	// container specific members
	crTokenFilename string
	iamProfileName  string
	iamEndpoint     string
	clientId        string
	clientSecret    string
	scope           string

	// vpc specific members
	vpcMetatadaEndpoint string
	iamProfileCRN       string
}

// As there is no interface for token based authenticators, thus we make one
type tokenProvider interface {
	GetToken() (string, error)
}

func NewIBMCloudAuthMethod(conf *auth.AuthConfig) (auth.AuthMethod, error) {

	if conf == nil {
		return nil, errors.New("empty config")
	}
	if conf.Config == nil {
		return nil, errors.New("empty config data")
	}

	a := &ibmcloudMethod{
		logger:     conf.Logger,
		mountPath:  conf.MountPath,
		credsFound: make(chan struct{}),
	}

	typeRaw, ok := conf.Config["type"]
	if !ok {
		return nil, errors.New("missing 'type' value")
	}
	authType, ok := typeRaw.(string)
	if !ok {
		return nil, errors.New("could not convert 'type' config value to string")
	}

	crTokenFilename, ok := conf.Config["crTokenFilename"]
	if ok {
		a.crTokenFilename, ok = crTokenFilename.(string)
		if !ok {
			return nil, errors.New("could not convert 'crTokenFilename' value into string")
		}
	}

	iamProfileName, ok := conf.Config["iamProfileName"]
	if ok {
		a.iamProfileName, ok = iamProfileName.(string)
		if !ok {
			return nil, errors.New("could not convert 'iamProfileName' value into string")
		}
	}

	iamProfileId, ok := conf.Config["iamProfileId"]
	if ok {
		a.iamProfileId, ok = iamProfileId.(string)
		if !ok {
			return nil, errors.New("could not convert 'iamProfileId' value into string")
		}
	}

	iamProfileCRN, ok := conf.Config["iamProfileCRN"]
	if ok {
		a.iamProfileCRN, ok = iamProfileCRN.(string)
		if !ok {
			return nil, errors.New("could not convert 'iamProfileCRN' value into string")
		}
	}

	iamEndpoint, ok := conf.Config["iamEndpoint"]
	if ok {
		a.iamEndpoint, ok = iamEndpoint.(string)
		if !ok {
			return nil, errors.New("could not convert 'iamEndpoint' value into string")
		}
	}
	vpcMetatadaEndpoint, ok := conf.Config["vpcMetatadaEndpoint"]
	if ok {
		a.vpcMetatadaEndpoint, ok = vpcMetatadaEndpoint.(string)
		if !ok {
			return nil, errors.New("could not convert 'vpcMetatadaEndpoint' value into string")
		}
	}

	clientId, ok := conf.Config["clientID"]
	if ok {
		a.clientId, ok = clientId.(string)
		if !ok {
			return nil, errors.New("could not convert 'clientID' value into string")
		}
	}

	clientSecret, ok := conf.Config["clientSecret"]
	if ok {
		a.clientSecret, ok = clientSecret.(string)
		if !ok {
			return nil, errors.New("could not convert 'clientSecret' value into string")
		}
	}

	scope, ok := conf.Config["scope"]
	if ok {
		a.scope, ok = scope.(string)
		if !ok {
			return nil, errors.New("could not convert 'scope' value into string")
		}
	}

	var authenticator tokenProvider
	var err error
	if authType == typeContainer {
		builder := core.NewContainerAuthenticatorBuilder().
			SetCRTokenFilename(a.crTokenFilename).
			SetIAMProfileName(a.iamProfileName).
			SetIAMProfileID(a.iamProfileId).
			SetURL(a.iamEndpoint).
			SetClientIDSecret(a.clientId, a.clientSecret).
			SetScope(a.scope)
		authenticator, err = builder.Build()
	}
	if authType == typeVPC {
		builder := core.NewVpcInstanceAuthenticatorBuilder().
			SetIAMProfileCRN(a.iamProfileCRN).
			SetIAMProfileID(a.iamProfileId).
			SetURL(a.vpcMetatadaEndpoint)
		authenticator, err = builder.Build()
	}

	if err != nil {
		return nil, err
	}
	a.authenticator = authenticator

	return a, nil
}

func (a *ibmcloudMethod) Authenticate(ctx context.Context, client *api.Client) (retToken string, header http.Header, retData map[string]interface{}, retErr error) {
	a.logger.Trace("beginning authentication")

	data := make(map[string]interface{})

	// will take care of obtaining/refreshing token
	token, err := a.authenticator.GetToken()
	if err != nil {
		retErr = fmt.Errorf("error obtaining iam token: %w", err)
		return
	}

	// Send change notifications to statisfy contract
	if token != a.lastToken {
		a.lastToken = token
		a.credsFound <- struct{}{}
	}

	data["token"] = token

	return fmt.Sprintf("%s/login", a.mountPath), nil, data, nil
}

func (a *ibmcloudMethod) NewCreds() chan struct{} {
	return a.credsFound
}

func (a *ibmcloudMethod) CredSuccess() {}

func (a *ibmcloudMethod) Shutdown() {}
