package api

import (
	"github.com/gogf/gf/frame/g"
	"github.com/gogf/gf/net/ghttp"
	"github.com/kotlin2018/jwt"
)

var Work = new(workApi)

type workApi struct{}

// works is the default router handler for web server.
func (a *workApi) Works(r *ghttp.Request) {
	data := g.Map{
		"message": "It works!",
	}
	r.Response.WriteJson(data)
}

// info should be authenticated to view.
// info is the get user data handler
func (a *workApi) Info(r *ghttp.Request) {
	data := g.Map{
		// get identity by identity key 'id'
		"id":           r.Get("id"),
		"identity_key": r.Get(jwt.Auth.IdentityKey),
		// get payload by identity
		"payload": r.Get("JWT_Payload"),
	}
	r.Response.WriteJson(data)
}
