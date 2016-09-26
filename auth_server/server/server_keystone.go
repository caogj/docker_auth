// GOLANG
//***********************************************
//
//      Filename: add.go
//
//        Author: xwisen 1031649164@qq.com
//   Description: ---
//        Create: 2016-09-13 09:34:31
// Last Modified: 2016-09-13 09:40:43
//***********************************************

package server

import (
	"encoding/json"
	"net/http"

	"github.com/cesanta/docker_auth/auth_server/authz"
	"github.com/golang/glog"
)

func (as *AuthServer) doAuthRepo(rw http.ResponseWriter, req *http.Request) {
	switch req.Method {
	case "POST":
		//add a repo info
		as.doAuthRepoPost(rw, req)
	case "DELETE":
		//delete a repo info
		as.doAuthRepoDelete(rw, req)
	default:
		//default return method not support
		as.doAuthDefault(rw, req)
	}
}
func (as *AuthServer) doAuthRepoPost(rw http.ResponseWriter, req *http.Request) {
	reponame := req.FormValue("reponame")
	property := req.FormValue("property")
	if property == "" || reponame == "" {
		glog.Errorln("please provide property and reponame")
		resultTrue, _ := json.Marshal(&map[string]string{"info": "reponame or property is null"})
		glog.V(3).Infof("%s", resultTrue)
		rw.Header().Set("Content-Type", "application/json")
		rw.WriteHeader(http.StatusNotFound)
		rw.Write(resultTrue)
		return
	}

	mc, err := authz.NewACLMysql(as.config.ACLMysql)
	if err != nil {
		glog.Errorln(err)
	}
	result, err := mc.InsertRepo(reponame, property)
	if err != nil {
		glog.Errorln(err)
		resultTrue, _ := json.Marshal(&map[string]string{"info": "insert mysql error"})
		glog.V(3).Infof("%s", resultTrue)
		rw.Header().Set("Content-Type", "application/json")
		rw.WriteHeader(http.StatusNotFound)
		rw.Write(resultTrue)
		return
	}
	resultTrue, _ := json.Marshal(&map[string]bool{"status": result})
	glog.V(3).Infof("%s", resultTrue)
	rw.Header().Set("Content-Type", "application/json")
	rw.Write(resultTrue)
}

func (as *AuthServer) doAuthRepoDelete(rw http.ResponseWriter, req *http.Request) {

}

func (as *AuthServer) doAuthDefault(rw http.ResponseWriter, req *http.Request) {
	resultTrue, _ := json.Marshal(&map[string]string{"info": "Methods not support error"})
	glog.V(3).Infof("%s", resultTrue)
	rw.Header().Set("Content-Type", "application/json")
	rw.WriteHeader(http.StatusNotFound)
	rw.Write(resultTrue)

}

func (as *AuthServer) doAuthRel(rw http.ResponseWriter, req *http.Request) {
	switch req.Method {
	case "GET":
		//get rels of projects and it's repo
		as.doAuthRelGet(rw, req)
	case "POST":
		//add a rel info
		as.doAuthRelPost(rw, req)
	case "PUT":
		//update a rel
	case "DELETE":
		//delete a rel info
		as.doAuthRelDelete(rw, req)
	default:
		//default return method not support
		as.doAuthDefault(rw, req)
	}
}

func (as *AuthServer) doAuthRelGet(rw http.ResponseWriter, req *http.Request) {
	project := req.FormValue("project")
	if project == "" {
		glog.Errorln("please provide project")
		resultTrue, _ := json.Marshal(&map[string]string{"info": "project is null"})
		glog.V(3).Infof("%s", resultTrue)
		rw.Header().Set("Content-Type", "application/json")
		rw.WriteHeader(http.StatusNotFound)
		rw.Write(resultTrue)
		return
	}

	mc, err := authz.NewACLMysql(as.config.ACLMysql)
	if err != nil {
		glog.Errorln(err)
	}
	result, err := mc.GetRepos(project)

	if err != nil {
		glog.Errorln(err)
		resultTrue, _ := json.Marshal(&map[string]string{"info": "func get repos mysql error"})
		glog.V(3).Infof("%s", resultTrue)
		rw.Header().Set("Content-Type", "application/json")
		rw.WriteHeader(http.StatusNotFound)
		rw.Write(resultTrue)
		return
	}
	resultTrue, _ := json.Marshal(&map[string][]string{"repos": result})
	glog.V(3).Infof("%s", resultTrue)
	rw.Header().Set("Content-Type", "application/json")
	rw.Write(resultTrue)

}

func (as *AuthServer) doAuthRelPost(rw http.ResponseWriter, req *http.Request) {
	project := req.FormValue("project")
	reponame := req.FormValue("reponame")
	if project == "" || reponame == "" {
		glog.Errorln("please provide project and reponame")
		resultTrue, _ := json.Marshal(&map[string]string{"info": "project or reponame is null"})
		glog.V(3).Infof("%s", resultTrue)
		rw.Header().Set("Content-Type", "application/json")
		rw.WriteHeader(http.StatusNotFound)
		rw.Write(resultTrue)
		return
	}

	mc, err := authz.NewACLMysql(as.config.ACLMysql)
	if err != nil {
		glog.Errorln(err)
	}
	result, err := mc.InsertRel(project, reponame, "exist")

	if err != nil {
		glog.Errorln(err)
		resultTrue, _ := json.Marshal(&map[string]string{"info": "insert mysql error"})
		glog.V(3).Infof("%s", resultTrue)
		rw.Header().Set("Content-Type", "application/json")
		rw.WriteHeader(http.StatusNotFound)
		rw.Write(resultTrue)
		return
	}
	resultTrue, _ := json.Marshal(&map[string]bool{"status": result})
	glog.V(3).Infof("%s", resultTrue)
	rw.Header().Set("Content-Type", "application/json")
	rw.Write(resultTrue)
}

func (as *AuthServer) doAuthRelDelete(rw http.ResponseWriter, req *http.Request) {
	project := req.FormValue("project")
	reponame := req.FormValue("reponame")
	if project == "" || reponame == "" {
		glog.Errorln("please provide project and reponame")
		resultTrue, _ := json.Marshal(&map[string]string{"info": "project or reponame is null"})
		glog.V(3).Infof("%s", resultTrue)
		rw.Header().Set("Content-Type", "application/json")
		rw.WriteHeader(http.StatusNotFound)
		rw.Write(resultTrue)
		return
	}

	mc, err := authz.NewACLMysql(as.config.ACLMysql)
	if err != nil {
		glog.Errorln(err)
	}

	result, err := mc.UpdateRel(project, reponame, "non-exist")
	if err != nil {
		glog.Errorln(err)
		resultTrue, _ := json.Marshal(&map[string]string{"info": "update mysql error"})
		glog.V(3).Infof("%s", resultTrue)
		rw.Header().Set("Content-Type", "application/json")
		rw.WriteHeader(http.StatusNotFound)
		rw.Write(resultTrue)
		return
	}
	resultTrue, _ := json.Marshal(&map[string]bool{"status": result})
	glog.V(3).Infof("%s", resultTrue)
	rw.Header().Set("Content-Type", "application/json")
	rw.Write(resultTrue)

}
