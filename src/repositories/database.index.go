package repositories

import (
	"fmt"

	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

var Database *gorm.DB
var DatabaseError error

func CreateDB(url string) {
	Database, DatabaseError = gorm.Open(sqlite.Open(url), &gorm.Config{})
	Database.AutoMigrate(
		&User{},
		&KeyEntity{},
	)
}

func (key *KeyEntity) BeforeCreate(tx *gorm.DB) (err error) {
	key.ID = uuid.New()
	return
}

func (user *User) BeforeCreate(tx *gorm.DB) (err error) {

	hash, err := bcrypt.GenerateFromPassword([]byte(user.Password), bcrypt.DefaultCost)

	if err != nil {
		fmt.Printf("Password Generate faild %s", err.Error())
		return
	}

	user.ID = uuid.New()
	user.Password = string(hash)
	return
}
