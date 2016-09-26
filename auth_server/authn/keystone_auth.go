package authn

import (
	"bytes"
	"encoding/json"
	"github.com/golang/glog"
	"io/ioutil"
	"net/http"
)

type KeystoneClient struct {
	HttpClient *http.Client
	Config     *KeystoneConfig
}

type KeystoneConfig struct {
	Url        string `yaml:"url,omitempty"`
	AdminToken string `yaml:"admin_token,omitempty"`
	DomainId   string `yaml:"domain_id,omitempty"`
}

//ListUsersResp to keystone api GET /v3/users
type ListUsersResp struct {
	Links ListUsersRespLinks  `json:"links,omitempty"`
	Users []ListUsersRespUser `json:"users,omitempty"`
}

type ListUsersRespLinks struct {
	Next     string `json:"next,omitempty"`
	Previous string `json:"previous,omitempty"`
	Self     string `json:"self,omitempty"`
}

type ListUsersRespUser struct {
	DefaultProjectID  string                `json:"default_project_id,omitempty"`
	DomainId          string                `json:"domain_id,omitempty"`
	Enabled           bool                  `json:"enabled,omitempty"`
	ID                string                `json:"id,omitemty"`
	Links             ListUsersRespUserLink `json:"links,omitempty"`
	Name              string                `json:"name,omitempty"`
	PasswordExpiresAt string                `json:"password_expires_at,omitempty"`
}

type ListUsersRespUserLink struct {
	Self string `json:"self,omitempty"`
}

//ShowUserResp to GET /v3/users/{user_id}
type ShowUserResp struct {
	User ListUsersRespUser `json:"user,omitempty"`
}

//CheckUserReq to POST /v3/auth/tokens
type CheckUserReq struct {
	Auth CheckUserReqAuth `json:"auth,omitemty"`
}

type CheckUserReqAuth struct {
	Identity CheckUserReqAuthIdentity `json:"identity,omitempty"`
}

type CheckUserReqAuthIdentity struct {
	Methods  []string                         `json:"methods,omitempty"`
	Password CheckUserReqAuthIdentityPassword `json:"password,omitempty"`
}

type CheckUserReqAuthIdentityPassword struct {
	User CheckUserReqAuthIdentityPasswordUser `json:"user,omitempty"`
}

type CheckUserReqAuthIdentityPasswordUser struct {
	Name     string                                     `json:"name,omitempty"`
	Domain   CheckUserReqAuthIdentityPasswordUserDomain `json:"domain,omitempty"`
	Password string                                     `json:"password,omitempty"`
}

type CheckUserReqAuthIdentityPasswordUserDomain struct {
	ID string `json:"id,omitempty"`
}

//CheckUserResp
type CheckUserResp struct {
	Token CheckUserRespToken `json:"token,omitempty"`
}

type CheckUserRespToken struct {
	IssuedAt  string                 `json:"issued_at,omitempty"`
	AuditIds  []string               `json:"audit_ids,omitempty"`
	Methods   []string               `json:"methods,omitempty"`
	ExpiresAt string                 `json:"expires_at,omitempty"`
	User      CheckUserRespTokenUser `json:"user,omitempty"`
}

type CheckUserRespTokenUser struct {
	Domain CheckUserRespTokenUserDomain `json:"domain,omitempty"`
	ID     string                       `json:"id,omitempty"`
	Name   string                       `json:"name,omitempty"`
}

type CheckUserRespTokenUserDomain struct {
	ID   string `json:"id,omitempty"`
	Name string `json:"name,omitempty"`
}

//ShowProjectResp to GET /v3/projects
type ShowProjectResp struct {
	Project ShowProjectRespProject `json:"project,omitempty"`
}

type ShowProjectRespProject struct {
	IsDomain    bool                        `json:"is_domain,omitempty"`
	Description string                      `json:"description,omitempty"`
	DomainId    string                      `json:"domain_id,omitempty"`
	Enabled     bool                        `json:"enabled,omitempty"`
	ID          string                      `json:"id,omitempty"`
	Links       ShowProjectRespProjectLinks `json:"links,omitempty"`
	Name        string                      `json:"name,omitempty"`
	ParentID    string                      `json:"parent_id,omitempty"`
}

type ShowProjectRespProjectLinks struct {
	Self string `json:"self,omitempty"`
}

// NewKeystoneClient create http client with keystone config
func NewKeystoneClient(config *KeystoneConfig) (*KeystoneClient, error) {
	return &KeystoneClient{
		HttpClient: http.DefaultClient,
		Config:     config,
	}, nil
}

//to keystone api GET /v3/users
func (kc *KeystoneClient) ListUsers(username string) (r *ListUsersResp, err error) {
	var respArry *ListUsersResp
	reqURl := kc.Config.Url + "/users?name=" + username
	req, err := http.NewRequest("GET", reqURl, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("X-Auth-Token", kc.Config.AdminToken)
	req.Header.Set("Content-Type", "application/json")

	resp, err := kc.HttpClient.Do(req)

	if err != nil {
		return nil, err
	}

	respBody, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	err = json.Unmarshal(respBody, respArry)
	if err != nil {
		return nil, err
	}
	return respArry, nil
}

//to keystone api POST /v3/auth/tokens
func (kc *KeystoneClient) CheckUser(username, password string) (bool, error) {
	glog.Infoln("CheckUser password is :", password)
	var respArry CheckUserResp
	var methods []string
	methods = append(methods, "password")
	reqURl := kc.Config.Url + "/auth/tokens"

	cp := CheckUserReq{
		Auth: CheckUserReqAuth{
			Identity: CheckUserReqAuthIdentity{
				Methods: methods,
				Password: CheckUserReqAuthIdentityPassword{
					User: CheckUserReqAuthIdentityPasswordUser{
						Name: username,
						Domain: CheckUserReqAuthIdentityPasswordUserDomain{
							ID: kc.Config.DomainId,
						},
						Password: password,
					},
				},
			},
		},
	}

	cpio, err := json.Marshal(cp)
	if err != nil {
		return false, err
	}
	req, err := http.NewRequest("POST", reqURl, bytes.NewBuffer(cpio))
	if err != nil {
		return false, err
	}
	req.Header.Set("X-Auth-Token", kc.Config.AdminToken)
	req.Header.Set("Content-Type", "application/json")
	glog.Infoln("request is :", *req)

	resp, err := kc.HttpClient.Do(req)
	glog.Infoln("respone is :", *resp)

	if err != nil {
		return false, err
	}

	respBody, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return false, err
	}

	err = json.Unmarshal(respBody, &respArry)
	if err != nil {
		return false, err
	}
	s := resp.Header.Get("X-Subject-Token")
	glog.Errorln("X-Subject-Token is: ", s)
	if s != "" {
		return true, nil
	}
	return false, nil
}

//to keystone api GET /v3/projects
func (kc *KeystoneClient) ShowProject(projectID string) (*ShowProjectResp, error) {
	var respArry *ShowProjectResp
	reqURL := kc.Config.Url + "/projects/" + projectID
	req, err := http.NewRequest("GET", reqURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("X-Auth-Token", kc.Config.AdminToken)
	req.Header.Set("Content-Type", "application/json")

	resp, err := kc.HttpClient.Do(req)
	if err != nil {
		return nil, err
	}
	glog.Infoln("show project resp is :", *resp)

	respBody, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	err = json.Unmarshal(respBody, respArry)
	if err != nil {
		return nil, err
	}
	return respArry, nil

}

func (kc *KeystoneClient) Authenticate(user string, password PasswordString) (bool, error) {
	glog.Infoln("Start KeystoneAuth **********************")
	result, err := kc.CheckUser(user, password.String())
	if err != nil || !result {
		return false, err
	}
	return result, nil
}

func (kc *KeystoneClient) Stop() {

}

func (kc *KeystoneClient) Name() string {
	return "keystone_auth"
}
