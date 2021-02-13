package main

import (
	"github.com/gogf/gf/frame/g"
	"github.com/gogf/gf/net/ghttp"
	"github.com/kotlin2018/jwt"
	"github.com/kotlin2018/jwt/example/api"
)

func main() {
	s := g.Server()
	s.BindHandler("/", api.Work.Works)
	s.BindHandler("POST:/login", api.Auth.LoginHandler)
	s.Group("/user", func(g *ghttp.RouterGroup) {
		g.Middleware(jwt.CORS, api.Auth.Use)
		g.ALL("/info", api.Work.Info)
		g.ALL("/refresh_token", api.Auth.RefreshHandler)
		g.ALL("/logout", api.Auth.LogoutHandler)
	})
	s.SetPort(8080)
	s.Run()
}
