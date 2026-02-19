package middleware

import (
	"api/src/auth"
	"api/src/controllers"
	"fmt"
	"net/http"

	"github.com/gin-gonic/gin"
)

func AuthMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		tokenString := c.GetHeader("Authorization")

		if tokenString == "" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "No token provided"})
			c.Abort()
			return
		}

		claims, err := auth.GetClaims(tokenString)

		if err != nil {
			fmt.Print("UNAITHORIZED")
			c.JSON(http.StatusUnauthorized, gin.H{"error": "UNAITHORIZED"})
			c.Abort()
			return
		}

		c.Set(controllers.Jwt_Auth_User_Claims, claims) // store claims in context
		c.Next()
	}
}
