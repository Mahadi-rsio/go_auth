package middleware

import (
	"api/src/controllers"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/go-playground/validator/v10"
)

var validate = validator.New()

func ValidateJSON[T any]() gin.HandlerFunc {
	return func(ctx *gin.Context) {
		var body T

		if err := ctx.ShouldBindJSON(&body); err != nil {
			ctx.JSON(http.StatusBadRequest, gin.H{
				"message": "all fields are required",
				"data":    body,
			})

			ctx.Abort()
			return
		}

		if err := validate.Struct(body); err != nil {
			ctx.JSON(http.StatusBadRequest, gin.H{
				"validate_err": err.Error(),
			})

			ctx.Abort()
			return
		}

		ctx.Set(controllers.ValidateContext, body)
		ctx.Next()

	}
}
