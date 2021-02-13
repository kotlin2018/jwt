package service

import (
	"github.com/gogf/gf/frame/g"
	"github.com/kotlin2018/jwt/example/model"
)

var User = new(userService)

type userService struct{}

func (s *userService) GetUserByUsernamePassword(serviceReq *model.ServiceLoginReq) map[string]interface{} {
	if serviceReq.Username == "admin" && serviceReq.Password == "admin" {
		return g.Map{
			"id":       1,
			"username": "admin",
		}
	}
	return nil
}
