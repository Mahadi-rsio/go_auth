package repositories

import (
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

type KeyEntity struct {
	ID                uuid.UUID `gorm:"primaryKey"`
	PrivateKey        string    `gorm:"not null"`
	PublicKey         string    `gorm:"not null"`
	RefreshPrivateKey string    `gorm:"not null"`
	RefreshPublicKey  string    `gorm:"not null"`
	CreatedAt         time.Time
	ExpireAt          time.Time
}

type User struct {
	ID           uuid.UUID `gorm:"primaryKey"`
	Name         string    `gorm:"not null"`
	Email        string    `gorm:"not null;uniqueIndex"`
	Image        string
	Provider     string
	Password     string
	Role         string `gorm:"default:user"`
	IsActive     bool   `gorm:"default:true"`
	RefreshToken string
	CreatedAt    time.Time
	UpdatedAt    time.Time
}

type JwtUserClaims struct {
	ID       uuid.UUID `gorm:"primaryKey"`
	Name     string    `gorm:"not null"`
	Email    string    `gorm:"not null;uniqueIndex"`
	Image    string
	IsActive bool   `gorm:"default:true"`
	Role     string `gorm:"default:user"`

	jwt.RegisteredClaims
}
