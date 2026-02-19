package auth

import (
	"api/src/repositories"
	"crypto/rand"
	"crypto/rsa"
	"encoding/pem"
	"fmt"

	"crypto/x509"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func CreateKeys() (*rsa.PrivateKey, *rsa.PublicKey, *rsa.PrivateKey, *rsa.PublicKey) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)

	if err != nil {
		panic(err.Error())
	}

	publicKey := privateKey.PublicKey

	refreshPrivateKey, err := rsa.GenerateKey(rand.Reader, 2048)

	if err != nil {
		panic(err.Error())
	}

	refreshPublicKey := refreshPrivateKey.PublicKey

	return privateKey, &publicKey, refreshPrivateKey, &refreshPublicKey
}

func SaveKeys() {

	privateKey, publicKey, refreshPrivateKey, refreshPublicKey := CreateKeys()

	privateKeyBuffer := x509.MarshalPKCS1PrivateKey(privateKey)
	privateKeyString := pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE RSA KEY",
		Bytes: privateKeyBuffer,
	})

	publicKeyBuffer, err := x509.MarshalPKIXPublicKey(publicKey)

	if err != nil {
		panic("PUBLIC KEY GENERATION FAILD")
	}

	publicKeyString := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC RSA KEY",
		Bytes: publicKeyBuffer,
	})

	refreshPrivateKeyBuffer := x509.MarshalPKCS1PrivateKey(refreshPrivateKey)
	refreshPrivateKeyString := pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE RSA KEY",
		Bytes: refreshPrivateKeyBuffer,
	})

	refreshPublicKeyBuffer, err := x509.MarshalPKIXPublicKey(refreshPublicKey)

	if err != nil {
		panic("PUBLIC KEY GENERATION FAILD")
	}

	refreshPublicKeyString := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC RSA KEY",
		Bytes: refreshPublicKeyBuffer,
	})

	repositories.Database.Create(&repositories.KeyEntity{
		PrivateKey:        string(privateKeyString),
		PublicKey:         string(publicKeyString),
		RefreshPrivateKey: string(refreshPrivateKeyString),
		RefreshPublicKey:  string(refreshPublicKeyString),
		CreatedAt:         time.Now(),
		ExpireAt:          time.Now().Add(time.Hour * 24 * 15),
	})
}

func ParsePrivateKeyFromPEM(pemStr string) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode([]byte(pemStr))
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM")
	}

	privateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	return privateKey, nil
}

func ParsePublicKeyFromPEM(pemStr string) (*rsa.PublicKey, error) {
	block, _ := pem.Decode([]byte(pemStr))
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM")
	}

	pubInterface, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	publicKey, ok := pubInterface.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("not RSA public key")
	}

	return publicKey, nil
}

func ValidateKeys() (string, string, string, string) {

	var keys repositories.KeyEntity

	err := repositories.Database.Order("created_at desc").First(&keys).Error

	if err != nil {
		fmt.Print("NO KEYS FOUND | GENERATING NEW KEY\n")
		SaveKeys()

		repositories.Database.Where("expire_at < ?", time.Now()).Delete(&repositories.KeyEntity{})
		fmt.Print("OLD KEY DELETED\n")
		repositories.Database.Order("created_at desc").First(&keys)

	}

	if time.Now().After(keys.ExpireAt) {
		fmt.Print("KEY EXPIRED | GENERATING NEW KEY\n")
		SaveKeys()

		repositories.Database.Where("expire_at < ?", time.Now()).Delete(&repositories.KeyEntity{})
		fmt.Print("OLD KEY DELETED\n")
		repositories.Database.Order("created_at desc").First(&keys)

	}

	return keys.PublicKey, keys.PrivateKey, keys.RefreshPrivateKey, keys.RefreshPublicKey
}

func GenerateSignedStringWithClaims(claims repositories.JwtUserClaims) (string, error) {
	_, privateKeyPEM, _, _ := ValidateKeys()

	privateKeyRSA, err := ParsePrivateKeyFromPEM(privateKeyPEM)
	if err != nil {
		panic("FAILED TO PARSE PRIVATE KEY: " + err.Error())
	}

	token := jwt.NewWithClaims(jwt.SigningMethodPS512, &claims)

	signedString, err := token.SignedString(privateKeyRSA)
	if err != nil {
		panic("FAILED TO SIGN TOKEN: " + err.Error())
	}

	fmt.Println("Signed Token:", signedString)

	return signedString, err
}

func GetClaims(tokenString string) (*repositories.JwtUserClaims, error) {
	publicKeyPEM, _, _, _ := ValidateKeys()
	publicKey, err := ParsePublicKeyFromPEM(publicKeyPEM)
	if err != nil {
		return nil, fmt.Errorf("failed to parse public key: %v", err)
	}

	token, err := jwt.ParseWithClaims(tokenString, &repositories.JwtUserClaims{}, func(t *jwt.Token) (any, error) {
		if t.Method.Alg() != jwt.SigningMethodPS512.Alg() {
			return nil, fmt.Errorf("unexpected signing method: %v", t.Method.Alg())
		}
		return publicKey, nil
	})

	if err != nil {
		return nil, err
	}

	claims, ok := token.Claims.(*repositories.JwtUserClaims)
	if !ok || !token.Valid {
		return nil, fmt.Errorf("invalid token claims")
	}

	return claims, nil
}

func GenerateRefreshTokenWithClaims(claims repositories.JwtUserClaims) (string, error) {
	_, _, refreshPrivateKeyPEM, _ := ValidateKeys()

	refreshPrivateKeyRSA, err := ParsePrivateKeyFromPEM(refreshPrivateKeyPEM)
	if err != nil {
		return "", fmt.Errorf("failed to parse refresh private key: %v", err)
	}

	// Set longer expiration
	claims.RegisteredClaims = jwt.RegisteredClaims{
		ExpiresAt: jwt.NewNumericDate(time.Now().Add(15 * 24 * time.Hour)),
		IssuedAt:  jwt.NewNumericDate(time.Now()),
		NotBefore: jwt.NewNumericDate(time.Now()),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodPS512, &claims)

	signedString, err := token.SignedString(refreshPrivateKeyRSA)
	if err != nil {
		return "", fmt.Errorf("failed to sign refresh token: %v", err)
	}

	dbErr := repositories.Database.Create(&repositories.User{
		RefreshToken: signedString,
	}).Error

	if dbErr != nil {
		fmt.Print(dbErr.Error())
		return "", nil
	}

	return signedString, nil
}

func ParseRefreshToken(tokenString string) (*repositories.JwtUserClaims, error) {
	_, _, _, refreshPublicKeyPEM := ValidateKeys()

	refreshPublicKey, err := ParsePublicKeyFromPEM(refreshPublicKeyPEM)
	if err != nil {
		return nil, fmt.Errorf("failed to parse refresh public key: %v", err)
	}

	token, err := jwt.ParseWithClaims(tokenString, &repositories.JwtUserClaims{}, func(t *jwt.Token) (any, error) {
		if t.Method.Alg() != jwt.SigningMethodPS512.Alg() {
			return nil, fmt.Errorf("unexpected signing method: %v", t.Method.Alg())
		}
		return refreshPublicKey, nil
	})

	if err != nil {
		return nil, err
	}

	claims, ok := token.Claims.(*repositories.JwtUserClaims)
	if !ok || !token.Valid {
		return nil, fmt.Errorf("invalid refresh token")
	}

	return claims, nil
}

func GetNewAccessToken(refreshToken string) (string, error) {
	// Step 1: Validate refresh token
	claims, err := ParseRefreshToken(refreshToken)
	if err != nil {
		return "", fmt.Errorf("invalid refresh token: %v", err)
	}

	// Step 2: Create new access claims
	newAccessClaims := repositories.JwtUserClaims{
		ID:    claims.ID,
		Name:  claims.Name,
		Image: claims.Image,
		Email: claims.Email,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(15 * time.Minute)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			NotBefore: jwt.NewNumericDate(time.Now()),
		},
	}

	// Step 3: Generate new access token
	newAccessToken, err := GenerateSignedStringWithClaims(newAccessClaims)
	if err != nil {
		return "", err
	}

	return newAccessToken, nil
}
