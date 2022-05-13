package gitlab

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"io/ioutil"
	"net/http"
	"time"
	"github.com/mitchellh/mapstructure"
	"golang.org/x/oauth2"
	"kubesphere.io/kubesphere/pkg/apiserver/authentication/identityprovider"
	"kubesphere.io/kubesphere/pkg/apiserver/authentication/oauth"
)


func init() {
	identityprovider.RegisterOAuthProvider(&gitlabProviderFactory{})
}

type gitlab struct {
	// ClientID is the application's ID.
	ClientID string `json:"clientID" yaml:"clientID"`

	// ClientSecret is the application's secret.
	ClientSecret string `json:"-" yaml:"clientSecret"`

	// Endpoint contains the resource server's token endpoint
	// URLs. These are constants specific to each server and are
	// often available via site-specific packages, such as
	// google.Endpoint or gitlab.endpoint.
	Endpoint endpoint `json:"endpoint" yaml:"endpoint"`

	// RedirectURL is the URL to redirect users going through
	// the OAuth flow, after the resource owner's URLs.
	RedirectURL string `json:"redirectURL" yaml:"redirectURL"`

	// Used to turn off TLS certificate checks
	InsecureSkipVerify bool `json:"insecureSkipVerify" yaml:"insecureSkipVerify"`

	// Scope specifies optional requested permissions.
	Scopes []string `json:"scopes" yaml:"scopes"`

	Config *oauth2.Config `json:"-" yaml:"-"`
}

// endpoint represents an OAuth 2.0 provider's authorization and token
// endpoint URLs.
type endpoint struct {
	AuthURL     string `json:"authURL" yaml:"authURL"`
	TokenURL    string `json:"tokenURL" yaml:"tokenURL"`
	UserInfoURL string `json:"userInfoURL" yaml:"userInfoURL"`
}

type Identity struct {
	Provider string `json:"provider"`
	ExternUid string `json:"extern_uid"`
}

// 根据gitab user 接口返回字段定义结构体
type gitlabIdentity struct {
	ID                int       `json:"id"`
	UserName	  string    `json:"username"`
	Email             string    `json:"email"`
	Name              string    `json:"name"`
	State               string     `json:"state"`
	AvatarURL         string    `json:"avatar_url"`
	WEBURL            string    `json:"web_url"`
	CreatedAt         time.Time `json:"created_at"`
	IsAdmin           bool      `json:"is_admin"`
	Bio               string    `json:"bio"`
	Location          string    `json:"location"`
	Skype             string    `json:"skype"`
	LINKEDIN          string    `json:"linkedin"`
	TWITTER           string    `json:"twitter"`
	WebsiteURL        string    `json:"website_url"`
	ORGANIZATION      string    `json:"organization"`
	LastSignInAt      time.Time `json:"last_sign_in_at"`
	ConfirmedAt       time.Time `json:"confirmed_at"`
	ThemeID           int       `json:"theme_id"`
	ColorSchemeID     int    `json:"color_scheme_id"`
	ProjectsLimits    int       `json:"projects_limit"`
	CurrentSignInAt   time.Time `json:"current_sign_in_at"`
	CanCreateGroup    bool      `json:"can_create_group"`
	CanCreateProject  bool      `json:"can_create_project"`
	TwoFactorEnabled  bool      `json:"two_factor_enabled"`
	External          bool      `json:"external"`
	Identities        []Identity `json:"identities"`
}

type gitlabProviderFactory struct {
}

func (g *gitlabProviderFactory) Type() string {
	return "GitLabIdentityProvider"
}

func (g *gitlabProviderFactory) Create(options oauth.DynamicOptions) (identityprovider.OAuthProvider, error) {
	var gitlab gitlab
	if err := mapstructure.Decode(options, &gitlab); err != nil {
		return nil, err
	}

	// fixed options
	options["endpoint"] = oauth.DynamicOptions{
		"authURL":     gitlab.Endpoint.AuthURL,
		"tokenURL":    gitlab.Endpoint.TokenURL,
		"userInfoURL": gitlab.Endpoint.UserInfoURL,
	}
	gitlab.Config = &oauth2.Config{
		ClientID:     gitlab.ClientID,
		ClientSecret: gitlab.ClientSecret,
		Endpoint: oauth2.Endpoint{
			AuthURL:  gitlab.Endpoint.AuthURL,
			TokenURL: gitlab.Endpoint.TokenURL,
		},
		RedirectURL: gitlab.RedirectURL,
		Scopes:      gitlab.Scopes,
	}
	return &gitlab, nil
}

func (g gitlabIdentity) GetUserID() string {
	return g.UserName
}

func (g gitlabIdentity) GetUsername() string {
	return g.UserName
}

func (g gitlabIdentity) GetEmail() string {
	return g.Email
}

// 请求oauth2服务端,反序列化用户信息
func (g *gitlab) IdentityExchangeCallback(req *http.Request) (identityprovider.Identity, error) {
	code := req.URL.Query().Get("code")
	ctx := req.Context()
	if g.InsecureSkipVerify {
		client := &http.Client{
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{
					InsecureSkipVerify: true,
				},
			},
		}
		ctx = context.WithValue(ctx, oauth2.HTTPClient, client)
	}
	token, err := g.Config.Exchange(ctx, code)
	if err != nil {
		return nil, err
	}
	resp, err := oauth2.NewClient(ctx, oauth2.StaticTokenSource(token)).Get(g.Endpoint.UserInfoURL)
	if err != nil {
		return nil, err
	}

	data, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var gitlabIdentity gitlabIdentity
	err = json.Unmarshal(data, &gitlabIdentity)
	if err != nil {
		return nil, err
	}

	return gitlabIdentity, nil
}
