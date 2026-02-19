package controllers

import (
	"api/src/auth"
	"api/src/dto"
	"api/src/repositories"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"
)

func Err(c *gin.Context, body any) {
	c.JSON(http.StatusBadRequest, gin.H{
		"err":  "json body shoudnt empty",
		"data": body,
	})

}

func LoginWithEmail(c *gin.Context) {

	body := c.MustGet(ValidateContext).(dto.LogInBody)

	var user repositories.User

	res := repositories.Database.Where("email = ?", body.Email).First(&user)

	if res.Error != nil {
		c.JSON(http.StatusUnauthorized, gin.H{
			"message": "Unauthorized",
		})
		return
	}

	valid := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(body.Password))

	if valid != nil {
		c.JSON(http.StatusUnauthorized, gin.H{
			"message": "Unauthorized",
		})
		return

	}

	token, err := auth.GenerateSignedStringWithClaims(repositories.JwtUserClaims{
		ID:    user.ID,
		Name:  user.Name,
		Image: user.Image,
		Email: user.Email,
		Role:  user.Role,
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    "http://localhost:3000",
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Minute * 2)),
		},
	})

	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"message": "token generation faild",
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"succes": "ok",
		"token":  token,
	})

}

func SignUpWithEmail(c *gin.Context) {

	body := c.MustGet(ValidateContext).(dto.SignUpBody)

	var existingUser repositories.User

	res := repositories.Database.Where("email = ?", body.Email).First(&existingUser)

	if res.Error == nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"message": "user already exist",
		})
		return
	}

	errCreate := repositories.Database.Create(&repositories.User{
		Name:     body.Name,
		Email:    body.Email,
		Password: body.Password,
		Provider: "email_password",
	}).Error

	if errCreate != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"message": "account createtion faild",
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"succes": true,
	})

}
