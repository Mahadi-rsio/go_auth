package main

import (
	"api/src/controllers"
	"api/src/dto"
	"api/src/middleware"

	"github.com/gin-gonic/gin"
)

func Router(address string) {
	r := gin.Default()

	r.POST(
		"/api/auth/sign-in/email",
		middleware.ValidateJSON[dto.LogInBody](),
		controllers.LoginWithEmail,
	)

	r.POST(
		"/api/auth/sign-up/email",
		middleware.ValidateJSON[dto.SignUpBody](),
		controllers.SignUpWithEmail,
	)

	r.Run(address)
}
