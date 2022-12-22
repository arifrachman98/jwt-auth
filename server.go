package main

import (
	"net/http"
	"time"

	"github.com/golang-jwt/jwt"
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
)

// jwtCustomClaims merupakan salah satu bentuk custom claim
type jwtCustomClaims struct {
	Name  string `json:"name"`
	Admin bool   `json:"admin"`
	jwt.StandardClaims
}

func login(ctx echo.Context) error {
	username := ctx.FormValue("username")
	password := ctx.FormValue("password")

	//cek error dari unauthorized user
	if username != "jon" || password != "ssh!" {
		return echo.ErrUnauthorized
	}

	//set custom claims token
	claims := &jwtCustomClaims{
		"Jon Skeleton",
		true,
		jwt.StandardClaims{
			ExpiresAt: time.Now().Add(time.Hour * 72).Unix(),
		},
	}

	//membuat token dengan claims
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	//meng-generate encode token dan mengirimnya sebagai response
	t, err := token.SignedString([]byte("secret"))

	if err != nil {
		return err
	}

	return ctx.JSON(http.StatusOK, echo.Map{
		"token": t,
	})
}

func accessible(ctx echo.Context) error {
	return ctx.String(http.StatusOK, "Accessible")
}

func restricted(ctx echo.Context) error {
	user := ctx.Get("user").(*jwt.Token)
	claims := user.Claims.(*jwtCustomClaims)
	name := claims.Name

	return ctx.String(http.StatusOK, "Welcome "+name+"!")
}

func main() {
	e := echo.New()

	//middleware
	e.Use(middleware.Logger())
	e.Use(middleware.Recover())

	//login route
	e.POST("/login", login)

	//unauthenticated route
	e.GET("/", accessible)

	//restricted group
	r := e.Group("/restricted")

	//membuat middleware dengan tipe custom claims
	config := middleware.JWTConfig{
		Claims:     &jwtCustomClaims{},
		SigningKey: []byte("secret"),
	}
	r.Use(middleware.JWTWithConfig(config))
	r.GET("", restricted)

	e.Logger.Fatal(e.Start(":9940"))
}
