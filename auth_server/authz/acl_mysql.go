package authz

import (
	"database/sql"
	"errors"
	"github.com/cesanta/docker_auth/auth_server/authn"
	_ "github.com/go-sql-driver/mysql"
	"github.com/golang/glog"
)

const (
	KEYSTONE_URL = "http://127.0.0.1:35357/v3"
	ADMIN_TOKEN  = "123456"
	DOMAIN_ID    = "61534a660b2a431786cd07233d922d9c"
	//DOMAIN_ID = "291d84999cd145cb9dc2eed438021337"
)

type ACLMysql struct {
	Config *ACLMysqlConfig
}

type ACLMysqlConfig struct {
	Url string `yaml:"url,omitempty"`
}

func NewACLMysql(config *ACLMysqlConfig) (*ACLMysql, error) {
	return &ACLMysql{
		Config: config,
	}, nil
}

func (am *ACLMysql) Authorize(ai *AuthRequestInfo) ([]string, error) {
	glog.Infoln("Start ACLMysql*****************************************", ai.Type)
	switch ai.Type {
	case "registry":
		reg, err := am.authorizeRegistry(ai)
		return reg, err
	case "repository":
		repo, err := am.authorizerRepository(ai)
		return repo, err
	default:
		return nil, errors.New("type is not exist")
	}
}

func (am *ACLMysql) authorizeRegistry(ai *AuthRequestInfo) ([]string, error) {
	glog.Infoln("authorizeRegistry Account is :", ai.Account)
	if ai.Account != "admin" {
		glog.Infoln("accont is :", ai.Account)
		return nil, errors.New("just admin can view catalog")
	}
	glog.Infoln("accont is :", ai.Account)
	return StringSetIntersection(ai.Actions, ai.Actions), nil

}

func (am *ACLMysql) authorizerRepository(ai *AuthRequestInfo) ([]string, error) {
	s, err := am.GetRepoProperty(ai.Name)
	if err != nil {
		glog.Errorln(err)
	}
	glog.Infoln("repo property is :", s)
	if len(s) == 0 {
		//return StringSetIntersection(ai.Actions, nil), errors.New("repo has no property,please check mysql realy exist?")
		glog.Errorln("repo has no property,please check repo realy exist? or you should insert repo and rel table info", ai.Name)
		return StringSetIntersection(ai.Actions, nil), nil
	}
	if ai.Account == "admin" {
		glog.Infoln("accont is :", ai.Account)
		return StringSetIntersection(ai.Actions, ai.Actions), nil
	}
	if s == "public" {
		for _, i := range ai.Actions {
			if i == "push" {
				//return StringSetIntersection(ai.Actions, nil), errors.New("non-admin is forbid to push public repo")
				glog.Errorln("non-admin is forbid to push public repo")
				return StringSetIntersection(ai.Actions, nil), nil
			}
		}
		glog.Infoln("user action is :", ai.Actions, "it not permit.")
		return StringSetIntersection(ai.Actions, ai.Actions), nil
	}
	kc, err := authn.NewKeystoneClient(&authn.KeystoneConfig{
		Url:        KEYSTONE_URL,
		AdminToken: ADMIN_TOKEN,
		DomainId:   DOMAIN_ID,
	})
	if err != nil {
		glog.Errorln("NewKeystoneclient err :", err)
	}
	resp, err := kc.ListUsers(ai.Account)
	if err != nil {
		glog.Errorln("kc.Getusers err :", err)
	}
	glog.Infoln("get user info is: ", resp)

	result, err := kc.ShowProject(resp.Users[0].DefaultProjectID)
	if err != nil {
		glog.Errorln("show project  err :", err)
	}

	resultm, err := am.GetRepos(result.Project.Name)
	if err != nil {
		glog.Errorln("get repos  err :", err, "repo not exist,please create first")
	}
	glog.Infoln("get project's repos from mysql: ", result.Project.Name, resultm)
	for _, repo := range resultm {
		if ai.Name == repo {
			glog.Infoln(ai.Name, "is not in mysql")
			return StringSetIntersection(ai.Actions, ai.Actions), nil
		}
	}

	//return StringSetIntersection(ai.Actions, nil), errors.New("authorizerRepository failed")
	glog.Infoln("default deal ,not permit!")
	return StringSetIntersection(ai.Actions, nil), nil

}

func (am *ACLMysql) Stop() {

}

func (am *ACLMysql) Name() string {
	return "ACLMysql"
}

func (am *ACLMysql) GetRepoProperty(repoName string) (property string, err error) {
	var p string
	db, err := sql.Open("mysql", am.Config.Url)
	if err != nil {
		glog.Errorln(err)
	}
	defer db.Close()

	rows, err := db.Query("select property from repo where repo_name=?", repoName)
	if err != nil {
		glog.Errorln(err)
	}
	for rows.Next() {
		if err := rows.Scan(&p); err != nil {
			glog.Errorln(err)
		}
	}
	return p, nil

}

func (am *ACLMysql) GetRepos(projectName string) (repos []string, err error) {
	var rs []string
	db, err := sql.Open("mysql", am.Config.Url)
	if err != nil {
		glog.Errorln(err)
	}
	defer db.Close()

	rows, err := db.Query("select repo_name from rel where project_name=? and status='exist'", projectName)
	if err != nil {
		glog.Errorln(err)
	}

	for rows.Next() {
		var repo string
		if err := rows.Scan(&repo); err != nil {
			glog.Errorln(err)
		}
		rs = append(rs, repo)
	}
	return rs, nil
}

func (am *ACLMysql) InsertRepo(reponame, property string) (bool, error) {
	db, err := sql.Open("mysql", am.Config.Url)
	if err != nil {
		glog.Errorln(err)
	}
	defer db.Close()

	_, err = db.Exec("insert repo set repo_name=?,property=?", reponame, property)
	if err != nil {
		glog.Errorln(err)
	}
	return true, nil
}

func (am *ACLMysql) InsertRel(projectName, repoName, status string) (bool, error) {
	db, err := sql.Open("mysql", am.Config.Url)
	if err != nil {
		glog.Errorln(err)
	}
	defer db.Close()

	_, err = db.Exec("insert rel set project_name=?,repo_name=?,status=?", projectName, repoName, status)
	if err != nil {
		glog.Errorln(err)
	}
	return true, nil
}

func (am *ACLMysql) UpdateRel(projectName, repoName, status string) (bool, error) {

	db, err := sql.Open("mysql", am.Config.Url)
	if err != nil {
		glog.Errorln(err)
	}
	defer db.Close()

	_, err = db.Exec("update rel set status=? where project_name=? and repo_name=?", status, projectName, repoName)
	if err != nil {
		glog.Errorln(err)
	}
	return true, nil
}

//func main() {
//	s, err := InsertRepo("nginx2", "private")
//	if err != nil || s != true {
//		fmt.Println("insert repo err !!!!!")
//	}
//	r, err := GetRepoProperty("nginx1")
//	if err != nil {
//		panic(err.Error())
//	}
//	fmt.Println("repo property is :", r)
//
//	k, err := InsertRel("admin", "nginx1", "enable")
//	if err != nil || k != true {
//		panic(err.Error())
//	}
//	j, err := GetRepos("admin")
//	if err != nil {
//		panic(err.Error())
//	}
//	fmt.Println("repos is :", j)
//}
