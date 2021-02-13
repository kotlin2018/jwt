package jwt

import (
	"crypto/rsa"
	"github.com/dgrijalva/jwt-go"
	"github.com/gogf/gf/crypto/gmd5"
	"github.com/gogf/gf/frame/g"
	"github.com/gogf/gf/net/ghttp"
	"github.com/gogf/gf/os/gcache"
	"io/ioutil"
	"net/http"
	"strings"
	"time"
)

var (
	// 默认身份密钥
	IdentityKey = "identity"
	// 黑名单存储尚未过期但已被停用的令牌。
	blacklist = gcache.New()
)

// MapClaims 如果您不提供，这是默认的声明类型。使用map [string] interface {}进行JSON解码
type MapClaims map[string]interface{}

// GfJWTMiddleware 提供了Json-Web-Token身份验证实现。
//
// 失败时，将返回401 HTTP响应；成功后，将调用包装的中间件，并以c.Get（“ userID”）。（string）的形式提供userID。
//
// 用户可以通过将json请求发布到LoginHandler来获得令牌，然后需要在Authentication标头中传递令牌。
//
// 示例：授权：承载者XXX_TOKEN_XXX
type GfJWTMiddleware struct {
	// 显示给用户的名称，这个参数必须要有。默认值: "gf jwt"
	Name string

	// 签名算法-可能的值是HS256，HS384，HS512可选，默认值为: HS256。
	SigningAlgorithm string

	// 用于签名的密钥。 这个参数必须要有。
	Key []byte

	// jwt令牌有效的持续时间。 可选，默认为一小时。
	Timeout time.Duration

	// 此字段允许客户端刷新令牌，直到MaxRefresh通过。
	// 请注意，客户端可以在MaxRefresh的最后时刻刷新其令牌。
	// 这意味着令牌的最大有效时间跨度为TokenTime + MaxRefresh。 可选，默认为0，表示不可刷新。
	MaxRefresh time.Duration

	// 应基于登录信息执行用户身份验证的回调函数。
	// 必须返回用户数据作为用户标识符，它将存储在Claim Array中。
	// 必需的。 检查错误（e），以确定适当的错误消息。
	Authenticator func(r *ghttp.Request) (interface{}, error)

	// 仅在身份验证成功后调用。 成功必须返回true，失败必须返回false。 可选，默认为成功。
	Authorizer func(data interface{}, r *ghttp.Request) bool

	// 登录期间将调用的回调函数。
	// 使用此功能可以向网络令牌添加其他有效载荷数据。
	// 然后在请求期间通过c.Get（“ JWT_PAYLOAD”）使数据可用。
	// 请注意，有效负载未加密。 jwt.io上提到的属性不能用作地图的键。
	// 可选，默认情况下不会设置其他数据。
	PayloadFunc func(data interface{}) MapClaims

	// 用户可以定义自己的未经授权的功能。
	Unauthorized func(*ghttp.Request, int, string)

	// 登陆成功之后的回调函数
	LoginResponse func(*ghttp.Request, int, string, time.Time)

	// 刷新Token令牌
	RefreshResponse func(*ghttp.Request, int, string, time.Time)

	// 注销token后的回调函数
	LogoutResponse func(*ghttp.Request, int)

	// 设置身份处理程序功能
	IdentityHandler func(*ghttp.Request) interface{}

	// 将 GfJWTMiddleware实例注册成中间件
	Use func(*ghttp.Request)

	// 设置身份密钥
	IdentityKey string

	// TokenLookup 是“ <source>：<name>”形式的字符串，用于从请求中提取令牌。
	//
	// 默认值: "header:Authorization"。
	//
	// 可选值:
	//
	// - "header:<name>"
	//
	// - "query:<name>"
	//
	// - "cookie:<name>"
	TokenLookup string

	// TokenHeadName 是标题中的字符串，默认值为: "Bearer"
	TokenHeadName string

	// TimeFunc 提供当前时间。 您可以覆盖它以使用其他时间值。 这对于测试或服务器使用不同于令牌的时区很有用。
	TimeFunc func() time.Time

	// 当JWT中间件发生故障时的HTTP状态消息。 检查错误（e），以确定适当的错误消息。
	HTTPStatusMsgFunc func(e error, r *ghttp.Request) string

	// 非对称算法的私钥文件
	PrivateKeyFile string

	// 非对称算法的公钥文件
	PublicKeyFile string

	// 私钥
	privKey *rsa.PrivateKey

	// 公钥
	pubKey *rsa.PublicKey

	// (可选) 将令牌作为Cookie返回
	SendCookie bool

	// 允许不安全的Cookie通过HTTP进行开发
	SecureCookie bool

	// 允许访问客户端的Cookie以进行开发
	CookieHTTPOnly bool

	// 允许更改Cookie域以进行开发
	CookieDomain string

	// SendAuthorization 允许每个请求的返回授权标头
	SendAuthorization bool

	// 禁用上下文的abort()。
	DisabledAbort bool

	// CookieName允许更改Cookie名称以进行开发，默认值: "jwt"
	CookieName string

	// 缓存适配器
	CacheAdapter gcache.Adapter
}

func New (m *GfJWTMiddleware)(*GfJWTMiddleware,error) {
	if err := m.MiddlewareInit(); err != nil {
		return nil, err
	}
	return m, nil
}

func (m *GfJWTMiddleware) MiddlewareInit() error {

	if m.TokenLookup == "" {
		m.TokenLookup = "header:Authorization"
	}

	if m.SigningAlgorithm == "" {
		m.SigningAlgorithm = "HS256"
	}

	if m.Timeout == 0 {
		m.Timeout = time.Hour
	}

	if m.TimeFunc == nil {
		m.TimeFunc = time.Now
	}

	m.TokenHeadName = strings.TrimSpace(m.TokenHeadName)
	if len(m.TokenHeadName) == 0 {
		m.TokenHeadName = "Bearer"
	}

	if m.Authorizer == nil {
		m.Authorizer = func(data interface{}, r *ghttp.Request) bool {
			return true
		}
	}

	if m.Unauthorized == nil {
		m.Unauthorized = func(r *ghttp.Request, code int, message string) {
			r.Response.WriteJson(g.Map{
				"code":    code,
				"message": message,
			})
		}
	}

	if m.LoginResponse == nil {
		m.LoginResponse = func(r *ghttp.Request, code int, token string, expire time.Time) {
			r.Response.WriteJson(g.Map{
				"code":   http.StatusOK,
				"token":  token,
				"expire": expire.Format(time.RFC3339),
			})
		}
	}

	if m.RefreshResponse == nil {
		m.RefreshResponse = func(r *ghttp.Request, code int, token string, expire time.Time) {
			r.Response.WriteJson(g.Map{
				"code":   http.StatusOK,
				"token":  token,
				"expire": expire.Format(time.RFC3339),
			})
		}
	}

	if m.LogoutResponse == nil {
		m.LogoutResponse = func(r *ghttp.Request, code int) {
			r.Response.WriteJson(g.Map{
				"code":    http.StatusOK,
				"message": "success",
			})
		}
	}

	if m.IdentityKey == "" {
		m.IdentityKey = IdentityKey
	}

	if m.IdentityHandler == nil {
		m.IdentityHandler = func(r *ghttp.Request) interface{} {
			claims := ExtractClaims(r)
			return claims[m.IdentityKey]
		}
	}

	if m.HTTPStatusMsgFunc == nil {
		m.HTTPStatusMsgFunc = func(e error, r *ghttp.Request) string {
			return e.Error()
		}
	}

	if m.Use == nil {
		m.Use = func(r *ghttp.Request) {
			m.middlewareImpl(r)
		}
	}

	if m.Name == "" {
		m.Name = "gf jwt"
	}

	if m.CookieName == "" {
		m.CookieName = "jwt"
	}

	if m.usingPublicKeyAlgo() {
		return m.readKeys()
	}

	if m.Key == nil {
		return ErrMissingSecretKey
	}

	if m.CacheAdapter != nil {
		blacklist.SetAdapter(m.CacheAdapter)
	}
	return nil
}

// MiddlewareFunc 使GfJWTMiddleware实现Middleware接口。内部只调用了middlewareImpl()
func (m *GfJWTMiddleware) MiddlewareFunc() ghttp.HandlerFunc {
	return func(r *ghttp.Request) {
		m.middlewareImpl(r)
	}
}

func (m *GfJWTMiddleware) middlewareImpl(r *ghttp.Request) {
	claims, token, err := m.GetClaimsFromJWT(r)
	if err != nil {
		m.unauthorized(r, http.StatusUnauthorized, m.HTTPStatusMsgFunc(err, r))
		return
	}

	if claims["expire"] == nil {
		m.unauthorized(r, http.StatusBadRequest, m.HTTPStatusMsgFunc(ErrMissingExpField, r))
		return
	}

	if _, ok := claims["expire"].(float64); !ok {
		m.unauthorized(r, http.StatusBadRequest, m.HTTPStatusMsgFunc(ErrWrongFormatOfExp, r))
		return
	}

	if int64(claims["expire"].(float64)) < m.TimeFunc().Unix() {
		m.unauthorized(r, http.StatusUnauthorized, m.HTTPStatusMsgFunc(ErrExpiredToken, r))
		return
	}

	in, err := m.inBlacklist(token)
	if err != nil {
		m.unauthorized(r, http.StatusUnauthorized, m.HTTPStatusMsgFunc(err, r))
		return
	}

	if in {
		m.unauthorized(r, http.StatusUnauthorized, m.HTTPStatusMsgFunc(ErrInvalidToken, r))
		return
	}

	r.SetParam("JWT_Payload", claims)
	identity := m.IdentityHandler(r)

	if identity != nil {
		r.SetParam(m.IdentityKey, identity)
	}

	if !m.Authorizer(identity, r) {
		m.unauthorized(r, http.StatusForbidden, m.HTTPStatusMsgFunc(ErrForbidden, r))
		return
	}
}


// ExtractClaims 帮助提取JWT claims
func ExtractClaims(r *ghttp.Request) MapClaims {
	claims := r.GetParam("JWT_Payload")
	return claims.(MapClaims)
}

//
func (m *GfJWTMiddleware)usingPublicKeyAlgo()bool {
	switch m.SigningAlgorithm {
	case "RS256", "RS512", "RS384":
		return true
	}
	return false
}


func (m *GfJWTMiddleware) publicKey() error {
	keyData, err := ioutil.ReadFile(m.PublicKeyFile)
	if err != nil {
		return ErrNoPubKeyFile
	}
	key, err := jwt.ParseRSAPublicKeyFromPEM(keyData)
	if err != nil {
		return ErrInvalidPubKey
	}
	m.pubKey = key
	return nil
}

func (m *GfJWTMiddleware) privateKey() error {
	keyData, err := ioutil.ReadFile(m.PrivateKeyFile)
	if err != nil {
		return ErrNoPrivKeyFile
	}
	key, err := jwt.ParseRSAPrivateKeyFromPEM(keyData)
	if err != nil {
		return ErrInvalidPrivKey
	}
	m.privKey = key
	return nil
}

func (m *GfJWTMiddleware) readKeys() error {
	err := m.privateKey()
	if err != nil {
		return err
	}
	err = m.publicKey()
	if err != nil {
		return err
	}
	return nil
}

func (m *GfJWTMiddleware) jwtFromHeader(r *ghttp.Request, key string) (string, error) {
	authHeader := r.Header.Get(key)

	if authHeader == "" {
		return "", ErrEmptyAuthHeader
	}

	parts := strings.SplitN(authHeader, " ", 2)
	if !(len(parts) == 2 && parts[0] == m.TokenHeadName) {
		return "", ErrInvalidAuthHeader
	}

	return parts[1], nil
}

func (m *GfJWTMiddleware) jwtFromQuery(r *ghttp.Request, key string) (string, error) {
	token := r.GetString(key)

	if token == "" {
		return "", ErrEmptyQueryToken
	}

	return token, nil
}

func (m *GfJWTMiddleware) jwtFromCookie(r *ghttp.Request, key string) (string, error) {
	cookie := r.Cookie.Get(key)

	if cookie == "" {
		return "", ErrEmptyCookieToken
	}

	return cookie, nil
}

func (m *GfJWTMiddleware) jwtFromParam(r *ghttp.Request, key string) (string, error) {
	token := r.GetString(key)
	if token == "" {
		return "", ErrEmptyParamToken
	}

	return token, nil
}

// ParseToken parse jwt token 该函数内部有 r.SetParam("Jwt_Token", token)
func (m *GfJWTMiddleware) ParseToken(r *ghttp.Request) (*jwt.Token, error) {
	var token string
	var err error

	methods := strings.Split(m.TokenLookup, ",")
	for _, method := range methods {
		if len(token) > 0 {
			break
		}
		parts := strings.Split(strings.TrimSpace(method), ":")
		k := strings.TrimSpace(parts[0])
		v := strings.TrimSpace(parts[1])
		switch k {
		case "header":
			token, err = m.jwtFromHeader(r, v)
		case "query":
			token, err = m.jwtFromQuery(r, v)
		case "cookie":
			token, err = m.jwtFromCookie(r, v)
		case "param":
			token, err = m.jwtFromParam(r, v)
		}
	}

	if err != nil {
		return nil, err
	}

	return jwt.Parse(token, func(t *jwt.Token) (interface{}, error) {
		if jwt.GetSigningMethod(m.SigningAlgorithm) != t.Method {
			return nil, ErrInvalidSigningAlgorithm
		}
		if m.usingPublicKeyAlgo() {
			return m.pubKey, nil
		}

		// save token string if vaild
		r.SetParam("Jwt_Token", token)
		return m.Key, nil
	})
}

func (m *GfJWTMiddleware) signedString(token *jwt.Token) (string, error) {
	var tokenString string
	var err error
	if m.usingPublicKeyAlgo() {
		tokenString, err = token.SignedString(m.privKey)
	} else {
		tokenString, err = token.SignedString(m.Key)
	}
	return tokenString, err
}

// 客户端可以用来获取jwt令牌的TokenGenerator方法。
func (m *GfJWTMiddleware) GenerateToken(data interface{}) (string, time.Time, error) {
	token := jwt.New(jwt.GetSigningMethod(m.SigningAlgorithm))
	claims := token.Claims.(jwt.MapClaims)

	if m.PayloadFunc != nil {
		for key, value := range m.PayloadFunc(data) {
			claims[key] = value
		}
	}

	expire := m.TimeFunc().UTC().Add(m.Timeout)
	claims["expire"] = expire.Unix()
	claims["current_time"] = m.TimeFunc().Unix()
	tokenString, err := m.signedString(token)
	if err != nil {
		return "", time.Time{}, err
	}
	return tokenString, expire, nil
}

func (m *GfJWTMiddleware) inBlacklist(token string) (bool, error) {
	// MD5的目标是减少密钥长度。
	tokenRaw, err := gmd5.EncryptString(token)

	if err != nil {
		return false, nil
	}

	// Global gcache
	if ok, err := blacklist.Contains(tokenRaw); err != nil {
		return false, nil
	} else {
		return ok, nil
	}
}

// CheckTokenExpire 检查令牌是否过期
func (m *GfJWTMiddleware) CheckTokenExpire(r *ghttp.Request) (jwt.MapClaims, string, error) {
	token, err := m.ParseToken(r)

	if err != nil {
		// 如果我们收到一个错误，并且该错误不是一个ValidationErrorExpired以外的任何其他错误，则我们想返回该错误。
		// 如果错误只是ValidationErrorExpired，我们想继续，因为如果令牌在MaxRefresh时间内，我们仍然可以刷新令牌。
		//（参见https：github.comappleboygin-jwtissues176）
		validationErr, ok := err.(*jwt.ValidationError)
		if !ok || validationErr.Errors != jwt.ValidationErrorExpired {
			return nil, "", err
		}
	}

	ok, err := m.inBlacklist(token.Raw)
	if err != nil {
		return nil, "", err
	}

	if ok {
		return nil, "", ErrInvalidToken
	}

	claims := token.Claims.(jwt.MapClaims)

	origIat := int64(claims["current_time"].(float64))

	if origIat < m.TimeFunc().Add(-m.MaxRefresh).Unix() {
		return nil, "", ErrExpiredToken
	}
	return claims, token.Raw, nil
}

func (m *GfJWTMiddleware) setBlacklist(token string, claims jwt.MapClaims) error {
	// MD5的目标是减少密钥长度。
	token, err := gmd5.EncryptString(token)
	if err != nil {
		return err
	}

	expire := int64(claims["expire"].(float64))

	// Global gcache
	err = blacklist.Set(token, true, time.Unix(expire, 0).Sub(m.TimeFunc()).Truncate(time.Second))
	if err != nil {
		return err
	}
	return nil
}

// RefreshToken 刷新令牌并检查令牌是否已过期
func (m *GfJWTMiddleware) RefreshToken(r *ghttp.Request) (string, time.Time, error) {
	claims, token, err := m.CheckTokenExpire(r)
	if err != nil {
		return "", time.Now(), err
	}

	// 创建令牌
	newToken := jwt.New(jwt.GetSigningMethod(m.SigningAlgorithm))
	newClaims := newToken.Claims.(jwt.MapClaims)

	for key := range claims {
		newClaims[key] = claims[key]
	}

	expire := m.TimeFunc().Add(m.Timeout)
	newClaims["expire"] = expire.Unix()
	newClaims["current_time"] = m.TimeFunc().Unix()
	tokenString, err := m.signedString(newToken)

	if err != nil {
		return "", time.Now(), err
	}

	// set cookie
	if m.SendCookie {
		maxAge := int64(expire.Unix() - time.Now().Unix())
		r.Cookie.SetCookie(m.CookieName, tokenString, m.CookieDomain, "/", time.Duration(maxAge)*time.Second)
	}

	// 将旧的token加入blacklist(黑名单)
	err = m.setBlacklist(token, claims)
	if err != nil {
		return "", time.Now(), err
	}
	return tokenString, expire, nil
}

func (m *GfJWTMiddleware) unauthorized(r *ghttp.Request, code int, message string) {
	r.Header.Set("WWW-Authenticate", "JWT realm="+m.Name)
	m.Unauthorized(r, code, message)
	if !m.DisabledAbort {
		r.ExitAll()
	}
}

// RefreshHandler 可用于刷新令牌。令牌在刷新时仍然需要有效。应放置在使用GfJWTMiddleware的端点下。回复的格式为{“ token”：“ TOKEN”}
func (m *GfJWTMiddleware) RefreshHandler(r *ghttp.Request) {
	tokenString, expire, err := m.RefreshToken(r)
	if err != nil {
		m.unauthorized(r, http.StatusUnauthorized, m.HTTPStatusMsgFunc(err, r))
		return
	}
	m.RefreshResponse(r, http.StatusOK, tokenString, expire)
}

// LogoutHandler 可用于注销令牌。 令牌仍然需要在注销时有效。 注销令牌会将未过期的令牌列入黑名单
func (m *GfJWTMiddleware) LogoutHandler (r *ghttp.Request) {
	claims, token, err := m.CheckTokenExpire(r)
	if err != nil {
		m.unauthorized(r, http.StatusUnauthorized, m.HTTPStatusMsgFunc(err, r))
		return
	}

	err = m.setBlacklist(token, claims)
	if err != nil {
		m.unauthorized(r, http.StatusUnauthorized, m.HTTPStatusMsgFunc(err, r))
		return
	}
	m.LogoutResponse(r, http.StatusOK)
}

// LoginHandler 客户端可以使用LoginHandler获得jwt令牌。
//
// 该函数内部逻辑依赖于 Authenticator()，LoginResponse() 这两个函数的具体实现。
//
// 有效负载必须为{“ username”：“ USERNAME”，“ password”：“ PASSWORD”}形式的json。
//
// 回复的格式为{“ token”：“ TOKEN”}。: Authenticator()，LoginResponse()
func (m *GfJWTMiddleware) LoginHandler(r *ghttp.Request) {
	if m.Authenticator == nil {
		m.unauthorized(r, http.StatusInternalServerError, m.HTTPStatusMsgFunc(ErrMissingAuthenticatorFunc, r))
		return
	}

	data, err := m.Authenticator(r)

	if err != nil {
		m.unauthorized(r, http.StatusUnauthorized, m.HTTPStatusMsgFunc(err, r))
		return
	}

	// Create the token
	token := jwt.New(jwt.GetSigningMethod(m.SigningAlgorithm))
	claims := token.Claims.(jwt.MapClaims)

	if m.PayloadFunc != nil {
		for key, value := range m.PayloadFunc(data) {
			claims[key] = value
		}
	}

	if _, ok := claims[m.IdentityKey]; !ok {
		m.unauthorized(r, http.StatusInternalServerError, m.HTTPStatusMsgFunc(ErrMissingIdentity, r))
		return
	}

	expire := m.TimeFunc().Add(m.Timeout)
	claims["expire"] = expire.Unix()
	claims["current_time"] = m.TimeFunc().Unix()
	tokenString, err := m.signedString(token)

	if err != nil {
		m.unauthorized(r, http.StatusUnauthorized, m.HTTPStatusMsgFunc(ErrFailedTokenCreation, r))
		return
	}

	// set cookie
	if m.SendCookie {
		maxAge := int64(expire.Unix() - time.Now().Unix())
		r.Cookie.SetCookie(m.CookieName, tokenString, m.CookieDomain, "/", time.Duration(maxAge)*time.Second)
	}
	m.LoginResponse(r, http.StatusOK, tokenString, expire)
}

// GetClaimsFromJWT 从JWT令牌获取claims
func (m *GfJWTMiddleware) GetClaimsFromJWT(r *ghttp.Request) (MapClaims, string, error) {
	token, err := m.ParseToken(r)
	if err != nil {
		return nil, "", err
	}

	if m.SendAuthorization {
		token := r.GetString("Jwt_Token")
		if len(token) > 0 {
			r.Header.Set("Authorization", m.TokenHeadName+" "+token)
		}
	}

	claims := MapClaims{}
	for key, value := range token.Claims.(jwt.MapClaims) {
		claims[key] = value
	}

	return claims, token.Raw, nil
}









