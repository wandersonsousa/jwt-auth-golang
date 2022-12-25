package initializers

import "jwtauthgo/models"

func SyncDatabase() {
	DB.AutoMigrate(&models.User{})
}
