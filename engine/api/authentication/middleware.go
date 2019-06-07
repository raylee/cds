package authentication

import (
	"context"
	"crypto/rsa"
	"net/http"
	"strings"

	jwt "github.com/dgrijalva/jwt-go"
	"github.com/go-gorp/gorp"

	"github.com/ovh/cds/engine/api/observability"
	"github.com/ovh/cds/engine/service"
	"github.com/ovh/cds/sdk"
	"github.com/ovh/cds/sdk/log"
)

var (
	LocalIssuer string
	signingKey  *rsa.PrivateKey
	verifyKey   *rsa.PublicKey
)

// Init the package by passing the signing key
func Init(issuer string, k []byte) error {
	LocalIssuer = issuer
	var err error
	signingKey, err = jwt.ParseRSAPrivateKeyFromPEM(k)
	if err != nil {
		return sdk.WithStack(err)
	}
	verifyKey = &signingKey.PublicKey
	return nil
}

const (
	jwtCookieName  = "jwt_token"
	xsrfHeaderName = "X-XSRF-TOKEN"
)

// Middleware for authentication.
func Middleware(ctx context.Context, db gorp.SqlExecutor, w http.ResponseWriter, req *http.Request, rc *service.HandlerConfig) (context.Context, error) {
	// If the route don't need auth return directly
	if !rc.NeedAuth {
		return ctx, nil
	}

	// Check for a JWT in current request and add it to the context
	var err error
	ctx, err = jwtMiddleware(ctx, req, rc)
	if err != nil {
		return ctx, err
	}

	jwt, ok := ctx.Value(contextJWT).(*jwt.Token)
	if !ok {
		return nil, sdk.WithStack(sdk.ErrUnauthorized)
	}
	claims := jwt.Claims.(*sdk.AccessTokenJWTClaims)
	sessionID := claims.StandardClaims.Id

	// Check for session based on jwt from context
	session, err = VerifySession(db, sessionID)
	if err != nil {
		return ctx, err
	}

	ctx = context.WithValue(ctx, contextSession, session)

	return ctx, nil
}

func jwtMiddleware(ctx context.Context, req *http.Request, rc *service.HandlerConfig) (context.Context, error) {
	ctx, end := observability.Span(ctx, "router.authJWTMiddleware")
	defer end()

	var jwtRaw string
	var xsrfTokenNeeded bool

	log.Debug("authJWTMiddleware> searching for a jwt token")

	// Try to get the jwt from the cookie firstly then from the authorization bearer header, a XSRF token with cookie
	jwtCookie, _ := req.Cookie(jwtCookieName)
	if jwtCookie != nil {
		jwtRaw = jwtCookie.Value
		xsrfTokenNeeded = true
	} else if strings.HasPrefix(req.Header.Get("Authorization"), "Bearer ") {
		jwtRaw = strings.TrimPrefix(req.Header.Get("Authorization"), "Bearer ")
	}
	if jwtRaw == "" {
		return ctx, sdk.WithStack(sdk.ErrUnauthorized)
	}

	log.Debug("authJWTMiddleware> found a jwt token %s...", jwtRaw[:12])

	// Checking X-XSRF-TOKEN header
	if xsrfTokenNeeded {
		log.Debug("authJWTMiddleware> searching for a xsrf token")

		xsrfToken := req.Header.Get(xsrfHeaderName)

		log.Debug("authJWTMiddleware> checking xsrf token %s...", xsrfToken[:12])

		// TODO check xsrf token validity
	}

	log.Debug("authJWTMiddleware> checking jwt token %s...", jwtRaw[:12])

	jwt, err := VerifyJWT(jwtRaw)
	if err != nil {
		return ctx, err
	}

	ctx = context.WithValue(ctx, contextJWTRaw, jwt)
	ctx = context.WithValue(ctx, contextJWT, jwt)

	return ctx, nil
}

// VerifyJWT .
func VerifyJWT(jwtToken string) (*jwt.Token, error) {
	token, err := jwt.ParseWithClaims(jwtToken, &sdk.AccessTokenJWTClaims{},
		func(token *jwt.Token) (interface{}, error) {
			if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
				return nil, sdk.NewErrorFrom(sdk.ErrUnauthorized, "unexpected signing method: %v", token.Header["alg"])
			}
			return verifyKey, nil
		})
	if err != nil {
		return nil, sdk.WithStack(err)
	}

	if claims, ok := token.Claims.(*sdk.AccessTokenJWTClaims); ok && token.Valid {
		log.Debug("authentication.jwtVerify> jwt token is valid: %v %v", claims.Issuer, claims.StandardClaims.ExpiresAt)
		return token, nil
	}

	return nil, sdk.WithStack(sdk.ErrUnauthorized)
}

// VerifySession .
func VerifySession(ctx context.Context, db gorp.SqlExecutor, sessionID string) (*Session, error) {
	// Load the session from the id read in the claim
	session, err := LoadSessionByID(ctx, db, sessionID)
	if err != nil {
		return nil, sdk.NewErrorWithStack(err, sdk.NewErrorFrom(sdk.ErrUnauthorized, "cannot load session for id: %s", id))
	}
	if session == nil {
		log.Debug("authentication.sessionMiddleware> no session found for id: %s", id)
		return nil, sdk.WithStack(sdk.ErrUnauthorized)
	}

	// TODO chekc session validity

	return session, nil
}
