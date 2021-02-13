package jwt

import (
	"errors"
	"github.com/gogf/gf/frame/g"
	"github.com/gogf/gf/net/ghttp"
	"github.com/gogf/gf/os/glog"
	"github.com/gogf/gf/util/gconv"
	"net/http"
	"time"
)

var (
	Auth 		*GfJWTMiddleware
	Name 		string  // 显示给用户的名称，这个参数必须要有。
	Key 		string  // 用于签名的密钥。 这个参数必须要有。
	Timeout 	string  // jwt令牌有效的持续时间。 可选，默认为一小时，时间单位为:小时。
	// 此字段允许客户端刷新令牌，直到MaxRefresh通过。可选，默认为0，表示不可刷新。
	//
	// 请注意: 客户端可以在MaxRefresh的最后时刻刷新其令牌，这意味着令牌的最大有效时间跨度为TokenTime + MaxRefresh。
	MaxRefresh 	string  // 此字段允许客户端刷新令牌，直到MaxRefresh通过。
)

func init() {
	authMiddleware, err := New(&GfJWTMiddleware{
		Name:            Name,
		Key:             []byte(Key),
		Timeout:         gconv.Duration(Timeout) * time.Hour * 1,
		MaxRefresh:      gconv.Duration(MaxRefresh) * time.Hour * 1,
		IdentityKey:     "id",
		TokenLookup:     "header: Authorization, query: token, cookie: jwt",
		TokenHeadName:   "Bearer",
		TimeFunc:        time.Now,
		Authenticator:   Authenticator,
		LoginResponse:   LoginResponse,
		RefreshResponse: RefreshResponse,
		LogoutResponse:  LogoutResponse,
		Unauthorized:    Unauthorized,
		PayloadFunc:     PayloadFunc,
		IdentityHandler: IdentityHandler,
		Use: 			 MiddlewareAuth,
	})
	if err != nil {
		glog.Fatal("JWT Error:" + err.Error())
	}
	Auth = authMiddleware
}

// PayloadFunc是一个回调函数，将在登录期间被调用。
//
// 使用此功能可以向网络令牌添加其他有效载荷数据。
// 然后在请求期间通过c.Get（“ JWT_PAYLOAD”）使数据可用。
// 请注意，有效负载未加密。 jwt.io上提到的属性不能用作map的键。
// 可选，默认情况下不会设置其他数据。
func PayloadFunc(data interface{}) MapClaims {
	claims := MapClaims{}
	params := data.(map[string]interface{})
	if len(params) > 0 {
		for k, v := range params {
			claims[k] = v
		}
	}
	return claims
}

// IdentityHandler从JWT获取身份并为每个请求设置身份使用此函数，通过r.GetParam（“ id”）获取身份。
func IdentityHandler(r *ghttp.Request) interface{} {
	claims := ExtractClaims(r)
	return claims[Auth.IdentityKey]
}


// Unauthorized 用于定义自定义的未经授权的回调函数。
func Unauthorized(r *ghttp.Request, code int, message string) {
	r.Response.WriteJson(g.Map{
		"code": code,
		"msg":  message,
	})
	r.ExitAll()
}

// ============ ============ ============ ============
// LoginResponse 用于定义自定义的登录成功回调函数。
func LoginResponse(r *ghttp.Request, code int, token string, expire time.Time) {
	r.Response.WriteJson(g.Map{
		"code":   http.StatusOK,
		"token":  token,
		"expire": expire.Format(time.RFC3339),
	})
	r.ExitAll()
}

// LogoutResponse is used to set token blacklist.
func LogoutResponse(r *ghttp.Request, code int) {
	r.Response.WriteJson(g.Map{
		"code":    code,
		"message": "success",
	})
	r.ExitAll()
}

func RefreshResponse(r *ghttp.Request, code int, token string, expire time.Time) {
	r.Response.WriteJson(g.Map{
		"code":   http.StatusOK,
		"token":  token,
		"expire": expire.Format(time.RFC3339),
	})
	r.ExitAll()
}

// 返回值interface{} 就是 JWT_Payload对应的值，即: interface{} = r.Get("JWT_Payload")
func Authenticator(r *ghttp.Request) (interface{}, error) {
	return nil,errors.New("请实现这个函数")
}

func MiddlewareAuth(r *ghttp.Request) {
	Auth.MiddlewareFunc()(r)
	r.Middleware.Next()
}

func CORS(r *ghttp.Request){
	r.Response.CORSDefault()
	r.Middleware.Next()
}

// JWTAuth JwtToken中间件。
//
// 可选参数<pattern> 不能为空，<pattern>用法如下:
//
// pattern[0] = "POST:/login"
//
// pattern[1] = "ALL:/refresh_token"
//
// pattern[2] = "ALL:/logout"
func JWTAuth (pattern ...string) {
	s := g.Server()
	switch len(pattern) {
	case 1:
		s.BindMiddleware(pattern[0],Auth.LoginHandler)
	case 2:
		s.BindMiddleware(pattern[1],Auth.RefreshHandler)
	case 3:
		s.BindMiddleware(pattern[2],Auth.LogoutHandler)
	default:
		glog.Error("请输入api，例如: POST:/login")
		s.Shutdown()
	}
}
