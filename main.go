package main

import (
	"jwtauthgo/controllers"
	"jwtauthgo/initializers"
	"jwtauthgo/middlewares"

	"github.com/gin-gonic/gin"
)

func init() {
	initializers.LoadEnvVariables()
	initializers.ConnectToDB()
	initializers.SyncDatabase()
}

func main() {
	r := gin.Default()
	r.POST("/signup", controllers.Signup)
	r.POST("/login", controllers.Login)
	r.GET("/validate", middlewares.RequireAuth, controllers.Validate)
	r.Run() // listen and serve on 0.0.0.0:8080
}
