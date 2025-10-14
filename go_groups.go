package main

import (
	"net/http"
	"github.com/gin-gonic/gin"
)

func main() {
	r := gin.Default()
	
	// API v1 group
	v1 := r.Group("/api/v1")
	{
		v1.GET("/users", getUsers)
		v1.POST("/users", createUser)
		v1.GET("/users/:id", getUser)
	}
	
	// API v2 group
	v2 := r.Group("/api/v2")
	{
		v2.GET("/users", getUsersV2)
		v2.POST("/users", createUserV2)
	}
	
	// Admin group
	admin := r.Group("/admin")
	{
		admin.GET("/stats", getStats)
		admin.GET("/health", healthCheck)
	}
	
	r.Run()
}

func getUsers(c *gin.Context) {
	// External API call
	resp, err := http.Get("https://jsonplaceholder.typicode.com/users")
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	c.JSON(200, gin.H{"message": "success"})
}

func createUser(c *gin.Context) {
	// External API call
	resp, err := http.Post("https://api.validation-service.com/validate", "application/json", nil)
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	c.JSON(201, gin.H{"message": "created"})
}