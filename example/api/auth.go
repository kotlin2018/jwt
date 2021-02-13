package api

import (
	"github.com/gogf/gf/net/ghttp"
	"github.com/gogf/gf/util/gconv"
	"github.com/kotlin2018/jwt"
	"github.com/kotlin2018/jwt/example/model"
	"github.com/kotlin2018/jwt/example/service"
	"time"
)

var (
	Auth *jwt.GfJWTMiddleware
)

func init(){
	jwt.Name = "test zone"
	jwt.Key = "secret key"
	jwt.Timeout = "1"
	jwt.MaxRefresh = "1"
	jwt.Auth.Authenticator = Authenticator
	jwt.Auth.RefreshResponse = RefreshResponse
	Auth = jwt.Auth
}

// 返回值interface{} 就是 JWT_Payload对应的值，即: interface{} = r.Get("JWT_Payload")
func Authenticator(r *ghttp.Request) (interface{}, error) {
	var (
		apiReq     *model.ApiLoginReq
		serviceReq *model.ServiceLoginReq
	)
	if err := r.Parse(&apiReq); err != nil {
		return "", err
	}
	if err := gconv.Struct(apiReq, &serviceReq); err != nil {
		return "", err
	}

	if user := service.User.GetUserByUsernamePassword(serviceReq); user != nil {
		return user, nil
	}

	return nil, jwt.ErrFailedAuthentication
}

func RefreshResponse(*ghttp.Request, int, string, time.Time){

}

func PayloadFunc(data interface{}) jwt.MapClaims {
	claims := jwt.MapClaims{}
	params := data.(map[string]interface{})
	if len(params) > 0 {
		for k, v := range params {
			claims[k] = v
		}
	}
	return claims
}
